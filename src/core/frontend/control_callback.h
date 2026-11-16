#pragma once
#include <functional>

namespace Frontend {
// Registered/cleared only on the emulation thread. Empty for stock frontends.
// The callback may inspect state, but may not load/reset/shutdown a nested RunLoop.
inline std::function<void()> control_callback;
} // namespace Frontend
