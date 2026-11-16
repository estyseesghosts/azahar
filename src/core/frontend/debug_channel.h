// Optional callbacks owned by an external native debugger, invoked on the emulation thread.
#pragma once
#include <functional>
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
inline bool single_step = false;
}
