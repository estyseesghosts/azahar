// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>

#include "common/logging/log.h"
#include "video_core/renderer_vulkan/vk_gpu_error.h"

#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#include <pdhmsg.h>
#endif

namespace Vulkan {

namespace {

std::mutex fault_mutex;
std::optional<GpuError> fault;
std::atomic_bool faulted = false;
std::atomic_bool acknowledged = false;
std::atomic<u64> failures = 0;
std::atomic_bool memory_invalidated = false;

using Clock = std::chrono::steady_clock;

u64 ElapsedNs(Clock::time_point since) {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - since).count();
}
std::atomic<u64> allocations = 0;
std::atomic<GpuFailureHandler> failure_handler = nullptr;

void Handle(const GpuError& error) {
    InvalidateGpuMemory();
    if (const GpuFailureHandler handler = failure_handler.load(std::memory_order_acquire)) {
        handler(*DescribeGpuFailure(error));
    }
}

/// CTR_WORKER_VK_FAIL_ALLOC, read once: empty or 0 disables injection.
const std::string& InjectionMode() {
    static const std::string mode = [] {
        const char* value = std::getenv("CTR_WORKER_VK_FAIL_ALLOC");
        return std::string{value ? value : ""};
    }();
    return mode;
}

/// "file" and "device_lost_file" modes: `<LOTUS_STORAGE_ROOT>/vk-fail-alloc` holding N arms a failure of the Nth
/// following allocation; the file is consumed when read. Checked on every allocation, which
/// only happens when the mode is set.
bool InjectFromFile() {
    static std::mutex mutex;
    static u64 remaining = 0;
    std::scoped_lock lock{mutex};
    if (remaining == 0) {
        const char* root = std::getenv("LOTUS_STORAGE_ROOT");
        if (!root) {
            return false;
        }
        const auto path = std::filesystem::path{root} / "vk-fail-alloc";
        std::ifstream file{path};
        if (!file || !(file >> remaining)) {
            return false;
        }
        file.close();
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        LOG_WARNING(Render_Vulkan, "allocation failure injection armed: allocation {}", remaining);
    }
    return remaining != 0 && --remaining == 0;
}

VkResult InjectAllocationError() {
    const std::string& mode = InjectionMode();
    if (mode == "file" || mode == "device_lost_file") {
        if (!InjectFromFile()) {
            return VK_SUCCESS;
        }
        return mode == "file" ? VK_ERROR_OUT_OF_DEVICE_MEMORY : VK_ERROR_DEVICE_LOST;
    }
    const u64 index = mode.empty() ? 0 : std::strtoull(mode.c_str(), nullptr, 10);
    const bool inject = index != 0 && allocations.fetch_add(1, std::memory_order_relaxed) + 1 == index;
    return inject ? VK_ERROR_OUT_OF_DEVICE_MEMORY : VK_SUCCESS;
}

#ifdef _WIN32
// WDDM reports all dedicated allocations on the Vulkan adapter, even when that
// adapter's per-process Vulkan budget has not changed.
class DedicatedUsage {
public:
    ~DedicatedUsage() {
        Close();
    }

    void Open(VkPhysicalDevice device) {
        VkPhysicalDeviceIDProperties id{.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES};
        VkPhysicalDeviceProperties2 properties{
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &id};
        VULKAN_HPP_DEFAULT_DISPATCHER.vkGetPhysicalDeviceProperties2(device, &properties);
        if (!id.deviceLUIDValid || id.deviceNodeMask != 1 ||
            properties.properties.deviceType != VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) {
            return;
        }
        static_assert(sizeof(LUID) == VK_LUID_SIZE);
        LUID luid{};
        std::memcpy(&luid, id.deviceLUID, sizeof(luid));
        const auto path = fmt::format(
            R"(\GPU Adapter Memory(luid_0x{:08x}_0x{:08x}_phys_0)\Dedicated Usage)",
            static_cast<u32>(luid.HighPart), static_cast<u32>(luid.LowPart));
        if (PdhOpenQueryA(nullptr, 0, &query) != ERROR_SUCCESS ||
            PdhAddEnglishCounterA(query, path.c_str(), 0, &counter) != ERROR_SUCCESS) {
            Close();
        }
    }

    void Close() {
        if (query) {
            PdhCloseQuery(query);
            query = nullptr;
        }
        usage.reset();
        sampled_at = {};
    }

    std::optional<u64> Read(bool throttle) {
        const auto now = Clock::now();
        if (query && (!throttle || now - sampled_at >= GPU_MEMORY_SAMPLE_INTERVAL)) {
            sampled_at = now;
            PDH_FMT_COUNTERVALUE value{};
            if (PdhCollectQueryData(query) == ERROR_SUCCESS &&
                PdhGetFormattedCounterValue(counter, PDH_FMT_LARGE, nullptr, &value) ==
                    ERROR_SUCCESS &&
                (value.CStatus == PDH_CSTATUS_VALID_DATA || value.CStatus == PDH_CSTATUS_NEW_DATA) &&
                value.largeValue >= 0) {
                usage = static_cast<u64>(value.largeValue);
            } else {
                usage.reset();
            }
        }
        return usage;
    }

    Clock::time_point SampledAt() const {
        return sampled_at;
    }

private:
    PDH_HQUERY query{};
    PDH_HCOUNTER counter{};
    std::optional<u64> usage;
    Clock::time_point sampled_at{};
};
#endif

struct Accounting {
    // The allocator lock pins VMA and its physical device during slow sampling.
    std::mutex mutex;
    // The published sample has a separate lock, never held across driver calls.
    std::mutex sample_mutex;
    GpuMemoryStats sample;
    Clock::time_point sampled_at{};
    u64 sample_sequence = 0;
    VmaAllocator allocator = VK_NULL_HANDLE;
    bool budget_extension = false;
    std::array<std::atomic<u64>, VK_MAX_MEMORY_HEAPS> live{};
    std::array<std::atomic<u64>, VK_MAX_MEMORY_HEAPS> high_water{};
    /// Memory type -> heap, filled at registration before any allocation.
    std::array<std::atomic<u32>, VK_MAX_MEMORY_TYPES> heap_of{};
#ifdef _WIN32
    DedicatedUsage dedicated_usage;
#endif
};

Accounting& Accounts() {
    static Accounting accounting;
    return accounting;
}

void VKAPI_PTR OnAllocate(VmaAllocator, uint32_t memory_type, VkDeviceMemory, VkDeviceSize size,
                          void*) {
    auto& accounts = Accounts();
    const u32 heap = accounts.heap_of[memory_type].load(std::memory_order_relaxed);
    const u64 now = accounts.live[heap].fetch_add(size, std::memory_order_relaxed) + size;
    u64 peak = accounts.high_water[heap].load(std::memory_order_relaxed);
    while (now > peak &&
           !accounts.high_water[heap].compare_exchange_weak(peak, now, std::memory_order_relaxed)) {
    }
}

void VKAPI_PTR OnFree(VmaAllocator, uint32_t memory_type, VkDeviceMemory, VkDeviceSize size,
                      void*) {
    auto& accounts = Accounts();
    const u32 heap = accounts.heap_of[memory_type].load(std::memory_order_relaxed);
    accounts.live[heap].fetch_sub(size, std::memory_order_relaxed);
}

const VmaDeviceMemoryCallbacks callbacks{
    .pfnAllocate = OnAllocate,
    .pfnFree = OnFree,
    .pUserData = nullptr,
};

} // namespace

GpuError::GpuError(GpuErrorKind kind_, VkResult result_, std::string object_)
    : std::runtime_error{std::string{KindName(kind_)} + ": " + ResultName(result_) +
                         (object_.empty() ? "" : " (" + object_ + ")")},
      kind{kind_}, result{result_}, object{std::move(object_)} {}

GpuErrorKind KindOf(VkResult result) {
    switch (result) {
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:
    case VK_ERROR_OUT_OF_HOST_MEMORY:
    case VK_ERROR_OUT_OF_POOL_MEMORY:
    case VK_ERROR_FRAGMENTED_POOL:
    case VK_ERROR_FRAGMENTATION:
        return GpuErrorKind::OutOfMemory;
    case VK_ERROR_DEVICE_LOST:
        return GpuErrorKind::DeviceLost;
    default:
        return GpuErrorKind::Other;
    }
}

const char* KindName(GpuErrorKind kind) {
    switch (kind) {
    case GpuErrorKind::OutOfMemory:
        return "gpu_out_of_memory";
    case GpuErrorKind::DeviceLost:
        return "gpu_device_lost";
    default:
        return "gpu_error";
    }
}

std::string ResultName(VkResult result) {
    // vk::to_string drops the VK_ERROR_ prefix the host log classifier and Vulkan docs use.
    switch (result) {
    case VK_ERROR_OUT_OF_HOST_MEMORY:
        return "VK_ERROR_OUT_OF_HOST_MEMORY";
    case VK_ERROR_OUT_OF_DEVICE_MEMORY:
        return "VK_ERROR_OUT_OF_DEVICE_MEMORY";
    case VK_ERROR_DEVICE_LOST:
        return "VK_ERROR_DEVICE_LOST";
    case VK_ERROR_OUT_OF_POOL_MEMORY:
        return "VK_ERROR_OUT_OF_POOL_MEMORY";
    case VK_ERROR_FRAGMENTED_POOL:
        return "VK_ERROR_FRAGMENTED_POOL";
    case VK_ERROR_FRAGMENTATION:
        return "VK_ERROR_FRAGMENTATION";
    default:
        return "VkResult " + std::to_string(static_cast<int>(result));
    }
}

void ThrowGpuError(VkResult result, std::string object) {
    const GpuErrorKind kind = KindOf(result);
    if (kind == GpuErrorKind::OutOfMemory) {
        failures.fetch_add(1, std::memory_order_relaxed);
    }
    GpuError error{kind, result, std::move(object)};
    LOG_CRITICAL(Render_Vulkan, "{} ({})", error.what(), static_cast<int>(result));
    Handle(error);
    throw error;
}

std::optional<GpuError> AsGpuError(const std::exception& error) {
    if (const auto* gpu = dynamic_cast<const GpuError*>(&error)) {
        return *gpu;
    }
    if (const auto* system = dynamic_cast<const vk::SystemError*>(&error)) {
        const auto result = static_cast<VkResult>(system->code().value());
        if (KindOf(result) != GpuErrorKind::Other) {
            return GpuError{KindOf(result), result, system->what()};
        }
    }
    return std::nullopt;
}

std::optional<GpuFailure> DescribeGpuFailure(const std::exception& error) {
    const auto gpu = AsGpuError(error);
    if (!gpu) {
        return std::nullopt;
    }
    return GpuFailure{
        .cause = KindName(gpu->Kind()),
        .vk_result = static_cast<int>(gpu->Result()),
        .vk_result_name = ResultName(gpu->Result()),
        .object = gpu->Object(),
        .device_lost = gpu->Kind() == GpuErrorKind::DeviceLost,
    };
}

void RaiseFault(const GpuError& error) {
    Handle(error);
    std::scoped_lock lock{fault_mutex};
    if (!fault) {
        LOG_CRITICAL(Render_Vulkan, "renderer thread fault: {}", error.what());
        fault = error;
        faulted.store(true, std::memory_order_release);
    }
}

bool Faulted() {
    return faulted.load(std::memory_order_acquire);
}

void ThrowIfFaulted() {
    if (!Faulted() || acknowledged.load(std::memory_order_acquire)) {
        return;
    }
    std::scoped_lock lock{fault_mutex};
    throw *fault;
}

void SetGpuFailureHandler(GpuFailureHandler handler) {
    failure_handler.store(handler, std::memory_order_release);
}

void AcknowledgeFault() {
    acknowledged.store(true, std::memory_order_release);
}

bool FaultAcknowledged() {
    return acknowledged.load(std::memory_order_acquire);
}

void CreateImage(VmaAllocator allocator, const VkImageCreateInfo& image_info,
                 const VmaAllocationCreateInfo& alloc_info, VkImage* image,
                 VmaAllocation* allocation, VmaAllocationInfo* allocation_info,
                 const std::string& object) {
    VkResult result = InjectAllocationError();
    if (result == VK_SUCCESS) {
        result = vmaCreateImage(allocator, &image_info, &alloc_info, image, allocation,
                                allocation_info);
    }
    if (result != VK_SUCCESS) [[unlikely]] {
        ThrowGpuError(result, object + " " + std::to_string(image_info.extent.width) + "x" +
                                  std::to_string(image_info.extent.height));
    }
}

void CreateBuffer(VmaAllocator allocator, const VkBufferCreateInfo& buffer_info,
                  const VmaAllocationCreateInfo& alloc_info, VkBuffer* buffer,
                  VmaAllocation* allocation, VmaAllocationInfo* allocation_info,
                  const std::string& object) {
    VkResult result = InjectAllocationError();
    if (result == VK_SUCCESS) {
        result = vmaCreateBuffer(allocator, &buffer_info, &alloc_info, buffer, allocation,
                                 allocation_info);
    }
    if (result != VK_SUCCESS) [[unlikely]] {
        ThrowGpuError(result, object + " " + std::to_string(buffer_info.size) + " bytes");
    }
}

const VmaDeviceMemoryCallbacks* MemoryCallbacks() {
    return &callbacks;
}

void RegisterAllocator(VmaAllocator allocator, bool budget_extension) {
    auto& accounts = Accounts();
    std::scoped_lock lock{accounts.mutex};
    // Called right after vmaCreateAllocator, before the first device-memory callback.
    const VkPhysicalDeviceMemoryProperties* properties{};
    vmaGetMemoryProperties(allocator, &properties);
    for (u32 type = 0; type < properties->memoryTypeCount; ++type) {
        accounts.heap_of[type].store(properties->memoryTypes[type].heapIndex,
                                     std::memory_order_relaxed);
    }
    {
        std::scoped_lock sample_lock{accounts.sample_mutex};
        accounts.sample = GpuMemoryStats{.available = true, .budget_extension = budget_extension};
        accounts.sampled_at = {};
    }
    memory_invalidated.store(false, std::memory_order_release);
    accounts.allocator = allocator;
    accounts.budget_extension = budget_extension;
#ifdef _WIN32
    VmaAllocatorInfo info{};
    vmaGetAllocatorInfo(allocator, &info);
    accounts.dedicated_usage.Open(info.physicalDevice);
#endif
}

void UnregisterAllocator() {
    auto& accounts = Accounts();
    std::scoped_lock lock{accounts.mutex};
    accounts.allocator = VK_NULL_HANDLE;
    {
        std::scoped_lock sample_lock{accounts.sample_mutex};
        accounts.sample = {};
        accounts.sampled_at = {};
    }
#ifdef _WIN32
    accounts.dedicated_usage.Close();
#endif
}

void InvalidateGpuMemory() {
    memory_invalidated.store(true, std::memory_order_release);
}

void SampleGpuMemory(bool sync_status) {
    auto& accounts = Accounts();
    const auto start = Clock::now();
    std::scoped_lock lock{accounts.mutex};
    if (accounts.allocator == VK_NULL_HANDLE ||
        memory_invalidated.load(std::memory_order_acquire)) {
        return;
    }
    const auto sampled_at = Clock::now();
    GpuMemoryStats stats{.available = true, .budget_extension = accounts.budget_extension};
    stats.accounting_wait_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(sampled_at - start).count();
#ifdef _WIN32
    const auto adapter_start = Clock::now();
    stats.adapter_dedicated_usage_bytes = accounts.dedicated_usage.Read(sync_status);
    stats.adapter_ns = ElapsedNs(adapter_start);
#endif
    const VkPhysicalDeviceMemoryProperties* properties{};
    vmaGetMemoryProperties(accounts.allocator, &properties);
    std::array<VmaBudget, VK_MAX_MEMORY_HEAPS> budgets{};
    const auto vma_start = Clock::now();
    vmaGetHeapBudgets(accounts.allocator, budgets.data());
    stats.vma_ns = ElapsedNs(vma_start);
    VkPhysicalDeviceMemoryBudgetPropertiesEXT live_budget{
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_BUDGET_PROPERTIES_EXT,
    };
    if (stats.budget_extension) {
        // VMA caches the extension values until an allocator refresh. An idle or
        // allocation-free worker still needs to see changes made by other processes.
        VmaAllocatorInfo info{};
        vmaGetAllocatorInfo(accounts.allocator, &info);
        VkPhysicalDeviceMemoryProperties2 memory{
            .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_MEMORY_PROPERTIES_2,
            .pNext = &live_budget,
        };
        const auto vulkan_start = Clock::now();
        VULKAN_HPP_DEFAULT_DISPATCHER.vkGetPhysicalDeviceMemoryProperties2(info.physicalDevice,
                                                                          &memory);
        stats.vulkan_ns = ElapsedNs(vulkan_start);
    }
    for (u32 heap = 0; heap < properties->memoryHeapCount; ++heap) {
        stats.heaps.push_back({
            .device_local =
                (properties->memoryHeaps[heap].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) != 0,
            .size = properties->memoryHeaps[heap].size,
            .budget = stats.budget_extension ? live_budget.heapBudget[heap] : budgets[heap].budget,
            .usage = stats.budget_extension ? live_budget.heapUsage[heap] : budgets[heap].usage,
            .allocation_bytes = budgets[heap].statistics.allocationBytes,
        });
    }
    stats.sample_ns = ElapsedNs(sampled_at);
    std::scoped_lock sample_lock{accounts.sample_mutex};
    stats.sample_sequence = ++accounts.sample_sequence;
    accounts.sample = std::move(stats);
    accounts.sampled_at = sampled_at;
#ifdef _WIN32
    // In synchronous rollback mode, the WDDM counter may have been sampled earlier
    // than Vulkan. Bound admission freshness by the oldest contributing source.
    if (accounts.sample.adapter_dedicated_usage_bytes) {
        accounts.sampled_at = std::min(sampled_at, accounts.dedicated_usage.SampledAt());
    }
#endif
}

GpuMemoryStats QueryGpuMemory(bool failure_report) {
    auto& accounts = Accounts();
    GpuMemoryStats stats;
    {
        std::unique_lock lock{accounts.sample_mutex, std::defer_lock};
        // A fatal error can arrive on a renderer thread. Never wait for the sampler here.
        if (failure_report) {
            lock.try_lock();
        } else {
            lock.lock();
        }
        if (lock.owns_lock()) {
            stats = accounts.sample;
            if (stats.sample_sequence) {
                const auto age = Clock::now() - accounts.sampled_at;
                stats.sample_age_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(age).count();
            }
            for (u32 heap = 0; heap < stats.heaps.size(); ++heap) {
                stats.heaps[heap].block_bytes = accounts.live[heap].load(std::memory_order_relaxed);
                stats.heaps[heap].block_bytes_high_water =
                    accounts.high_water[heap].load(std::memory_order_relaxed);
            }
        }
    }
    stats.allocation_failures = failures.load(std::memory_order_relaxed);
    stats.invalidated = memory_invalidated.load(std::memory_order_acquire);
    return stats;
}

} // namespace Vulkan
