// Optional callbacks owned by an external native debugger, invoked on the emulation thread.
#pragma once
#include <functional>
#include <set>
#include <string>
#include "common/common_types.h"
namespace Core { class ARM_Interface; }
namespace Kernel { class Thread; }
namespace DebugChannel {
inline std::function<bool(Core::ARM_Interface&, Kernel::Thread*)> before_instruction;
inline std::function<void(u32, u32, bool)> memory_access;
inline std::function<void(u32, const std::string&)> guest_log;
inline std::function<void(u32)> hio;
inline std::function<void(u32, bool)> svc;
inline std::function<void(u32, u32)> exception;
inline std::function<void(u32,u32,bool)> memory_fault;
inline std::function<void(u32)> svc_break;
inline std::function<void(u32,const void*)> gpu_event;
inline std::function<void(u32,u32)> gpu_action; // frame, command list, fill, transfer
inline std::function<void(const void*)> gpu_vertex_output;
inline bool single_step = false;
// Armed execute-breakpoint addresses. The Dynarmic translator ends a block in front of each
// and halts there (arm_dynarmic.cpp, PreCodeReadHook), so JIT slices keep running while
// breakpoints are armed. Change only between RunLoop calls, then clear the JIT caches.
inline std::set<u32> code_breakpoints;
}
