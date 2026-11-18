// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <array>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>

#include "common/logging/log.h"
#include "video_core/renderer_vulkan/vk_gpu_error.h"

namespace Vulkan {

namespace {

std::mutex fault_mutex;
std::optional<GpuError> fault;
std::atomic_bool faulted = false;
std::atomic_bool acknowledged = false;
std::atomic<u64> failures = 0;
std::atomic<u64> allocations = 0;
std::atomic<GpuFailureHandler> failure_handler = nullptr;

void Handle(const GpuError& error) {
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

/// "file" mode: `<LOTUS_STORAGE_ROOT>/vk-fail-alloc` holding N arms a failure of the Nth
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

bool Inject() {
    const std::string& mode = InjectionMode();
    if (mode.empty()) {
        return false;
    }
    if (mode == "file") {
        return InjectFromFile();
    }
    const u64 index = std::strtoull(mode.c_str(), nullptr, 10);
    return index != 0 && allocations.fetch_add(1, std::memory_order_relaxed) + 1 == index;
}

struct Accounting {
    std::mutex mutex;
    VmaAllocator allocator = VK_NULL_HANDLE;
    bool budget_extension = false;
    std::array<std::atomic<u64>, VK_MAX_MEMORY_HEAPS> live{};
    std::array<std::atomic<u64>, VK_MAX_MEMORY_HEAPS> high_water{};
    /// Memory type -> heap, filled at registration before any allocation.
    std::array<std::atomic<u32>, VK_MAX_MEMORY_TYPES> heap_of{};
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
    const VkResult result =
        Inject() ? VK_ERROR_OUT_OF_DEVICE_MEMORY
                 : vmaCreateImage(allocator, &image_info, &alloc_info, image, allocation,
                                  allocation_info);
    if (result != VK_SUCCESS) [[unlikely]] {
        ThrowGpuError(result, object + " " + std::to_string(image_info.extent.width) + "x" +
                                  std::to_string(image_info.extent.height));
    }
}

void CreateBuffer(VmaAllocator allocator, const VkBufferCreateInfo& buffer_info,
                  const VmaAllocationCreateInfo& alloc_info, VkBuffer* buffer,
                  VmaAllocation* allocation, VmaAllocationInfo* allocation_info,
                  const std::string& object) {
    const VkResult result =
        Inject() ? VK_ERROR_OUT_OF_DEVICE_MEMORY
                 : vmaCreateBuffer(allocator, &buffer_info, &alloc_info, buffer, allocation,
                                   allocation_info);
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
    accounts.allocator = allocator;
    accounts.budget_extension = budget_extension;
}

void UnregisterAllocator() {
    auto& accounts = Accounts();
    std::scoped_lock lock{accounts.mutex};
    accounts.allocator = VK_NULL_HANDLE;
}

GpuMemoryStats QueryGpuMemory() {
    auto& accounts = Accounts();
    std::scoped_lock lock{accounts.mutex};
    GpuMemoryStats stats;
    stats.allocation_failures = failures.load(std::memory_order_relaxed);
    if (accounts.allocator == VK_NULL_HANDLE) {
        return stats;
    }
    stats.available = true;
    stats.budget_extension = accounts.budget_extension;
    const VkPhysicalDeviceMemoryProperties* properties{};
    vmaGetMemoryProperties(accounts.allocator, &properties);
    std::array<VmaBudget, VK_MAX_MEMORY_HEAPS> budgets{};
    vmaGetHeapBudgets(accounts.allocator, budgets.data());
    for (u32 heap = 0; heap < properties->memoryHeapCount; ++heap) {
        stats.heaps.push_back({
            .device_local =
                (properties->memoryHeaps[heap].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) != 0,
            .size = properties->memoryHeaps[heap].size,
            .budget = budgets[heap].budget,
            .usage = budgets[heap].usage,
            .block_bytes = accounts.live[heap].load(std::memory_order_relaxed),
            .block_bytes_high_water = accounts.high_water[heap].load(std::memory_order_relaxed),
            .allocation_bytes = budgets[heap].statistics.allocationBytes,
        });
    }
    return stats;
}

} // namespace Vulkan
