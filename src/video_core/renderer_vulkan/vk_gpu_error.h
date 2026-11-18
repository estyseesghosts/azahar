// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "common/common_types.h"
#include "video_core/renderer_vulkan/vk_common.h"
#include "video_core/renderer_vulkan/vk_gpu_status.h"

#include <vk_mem_alloc.h>

// Typed Vulkan failures for the native worker (lotus#46).
//
// Allocation and device-loss failures used to call UNREACHABLE(), aborting the process with no
// cause the host could act on. They now throw GpuError on the emulation thread. Renderer threads
// (the scheduler worker, the fence waiter) cannot throw across threads, so they latch the first
// fault, stop executing GPU work, and the emulation thread rethrows it at its next scheduler
// wait or flush. The worker's control loop catches GpuError, reports it and stops the session.
//
// Allocation accounting: VMA device-memory callbacks track this process's live block bytes and
// their high-water mark per heap; budgets come from vmaGetHeapBudgets, which reflects other
// processes only when VK_EXT_memory_budget is enabled (`budget_extension`). Without it VMA
// estimates the budget as 80 % of the heap size and usage from this process alone.
//
// Fault injection, for tests: CTR_WORKER_VK_FAIL_ALLOC=N makes the Nth image or buffer
// allocation made through CreateImage/CreateBuffer (1-based, counted from process start) fail
// with VK_ERROR_OUT_OF_DEVICE_MEMORY without calling VMA. CTR_WORKER_VK_FAIL_ALLOC=file arms one
// session at run time instead: `<LOTUS_STORAGE_ROOT>/vk-fail-alloc` containing N fails the Nth
// allocation after the file is read (it is consumed).

namespace Vulkan {

enum class GpuErrorKind { OutOfMemory, DeviceLost, Other };

class GpuError : public std::runtime_error {
public:
    GpuError(GpuErrorKind kind, VkResult result, std::string object);

    GpuErrorKind Kind() const {
        return kind;
    }
    VkResult Result() const {
        return result;
    }
    const std::string& Object() const {
        return object;
    }

private:
    GpuErrorKind kind;
    VkResult result;
    std::string object;
};

GpuErrorKind KindOf(VkResult result);
/// "gpu_out_of_memory", "gpu_device_lost" or "gpu_error".
const char* KindName(GpuErrorKind kind);
/// "VK_ERROR_OUT_OF_DEVICE_MEMORY" etc., or the number.
std::string ResultName(VkResult result);

/// Logs the failure (Render_Vulkan critical, with the VkResult name), counts it and throws.
[[noreturn]] void ThrowGpuError(VkResult result, std::string object);

/// A GpuError or a vulkan-hpp exception for an out-of-memory or device-lost result.
std::optional<GpuError> AsGpuError(const std::exception& error);

/// Latch the first fault seen on a renderer thread. Later GPU work is skipped.
void RaiseFault(const GpuError& error);
bool Faulted();
/// Rethrows a latched fault on the calling thread, unless the worker has acknowledged it and is
/// shutting the renderer down (waits then return instead of blocking on work that never ran).
void ThrowIfFaulted();
bool FaultAcknowledged();

/// vmaCreateImage/vmaCreateBuffer with fault injection; throws GpuError on failure.
void CreateImage(VmaAllocator allocator, const VkImageCreateInfo& image_info,
                 const VmaAllocationCreateInfo& alloc_info, VkImage* image,
                 VmaAllocation* allocation, VmaAllocationInfo* allocation_info,
                 const std::string& object);
void CreateBuffer(VmaAllocator allocator, const VkBufferCreateInfo& buffer_info,
                  const VmaAllocationCreateInfo& alloc_info, VkBuffer* buffer,
                  VmaAllocation* allocation, VmaAllocationInfo* allocation_info,
                  const std::string& object);

/// Device-memory callbacks for VmaAllocatorCreateInfo::pDeviceMemoryCallbacks.
const VmaDeviceMemoryCallbacks* MemoryCallbacks();
void RegisterAllocator(VmaAllocator allocator, bool budget_extension);
void UnregisterAllocator();


} // namespace Vulkan
