// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <chrono>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include "common/common_types.h"

// The part of vk_gpu_error.h a frontend needs, without Vulkan headers (lotus#46).

namespace Vulkan {

struct GpuFailure {
    /// "gpu_out_of_memory", "gpu_device_lost" or "gpu_error".
    std::string cause;
    int vk_result;
    std::string vk_result_name;
    std::string object;
    bool device_lost;
};

/// The typed failure behind `error`, if it is a GpuError or a vulkan-hpp exception for an
/// out-of-memory or device-lost result.
std::optional<GpuFailure> DescribeGpuFailure(const std::exception& error);

/// The frontend has caught the failure and shuts the renderer down: waits on GPU work that was
/// dropped after the fault return instead of rethrowing.
void AcknowledgeFault();

/// Called at the failure, on the failing thread, before any exception is thrown. A frontend
/// whose failures may surface inside JIT-compiled guest code installs one: C++ exceptions cannot
/// unwind through dynarmic's generated frames, which carry no SEH unwind data on Windows, so a
/// renderer allocation made from a guest-triggered draw cannot throw back to the frontend. The
/// handler is expected not to return (the native worker reports and exits). Without one, or if
/// it returns, the failure is thrown as GpuError or latched (renderer threads).
using GpuFailureHandler = void (*)(const GpuFailure& failure);
void SetGpuFailureHandler(GpuFailureHandler handler);

struct GpuMemoryHeap {
    bool device_local;
    u64 size;
    /// What this process may use and its current usage, from Vulkan or the VMA estimate.
    u64 budget;
    u64 usage;
    /// Live VkDeviceMemory blocks of this process and their high-water mark.
    u64 block_bytes;
    u64 block_bytes_high_water;
    /// Bytes in live VMA allocations within those blocks.
    u64 allocation_bytes;
};

struct GpuMemoryStats {
    bool available = false;
    /// True when budgets come from VK_EXT_memory_budget (they then include other processes);
    /// otherwise VMA estimates the budget as 80 % of the heap and usage from this process.
    bool budget_extension = false;
    bool invalidated = false;
    u64 sample_sequence = 0;
    std::optional<u64> sample_age_ms;
    u64 accounting_wait_ns = 0;
    u64 sample_ns = 0;
    u64 vma_ns = 0;
    u64 vulkan_ns = 0;
    u64 adapter_ns = 0;
    u64 allocation_failures = 0;
    /// WDDM dedicated usage across processes on a supported Windows adapter.
    std::optional<u64> adapter_dedicated_usage_bytes;
    std::vector<GpuMemoryHeap> heaps;
};

inline constexpr auto GPU_MEMORY_SAMPLE_INTERVAL = std::chrono::milliseconds{500};
inline constexpr auto GPU_MEMORY_SAMPLE_TTL = std::chrono::milliseconds{1000};

/// Sample on the worker's telemetry thread or at a load/diagnostic boundary.
void SampleGpuMemory();
/// Invalidate admission data before reporting a terminal Vulkan failure.
void InvalidateGpuMemory();
/// Copy the published sample and live counters without calling a driver.
GpuMemoryStats QueryGpuMemory(bool failure_report = false);

} // namespace Vulkan
