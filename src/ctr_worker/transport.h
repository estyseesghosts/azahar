#pragma once
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <json.hpp>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <poll.h>
#include <unistd.h>
#endif

namespace CtrWorker {
// Poll inherited stdin so stopping can join the reader without orphan threads.
inline bool ReadExact(char* data, size_t size, const std::atomic_bool& stop) {
    while (size && !stop) {
#ifdef _WIN32
        DWORD available = 0;
        const auto handle = GetStdHandle(STD_INPUT_HANDLE);
        if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr))
            return false;
        if (!available) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        DWORD received = 0;
        if (!ReadFile(handle, data, static_cast<DWORD>(std::min<size_t>(size, available)),
                      &received, nullptr) ||
            !received)
            return false;
#else
        pollfd descriptor{STDIN_FILENO, POLLIN, 0};
        if (poll(&descriptor, 1, 10) <= 0)
            continue;
        const auto received = read(STDIN_FILENO, data, size);
        if (received <= 0)
            return false;
#endif
        data += received;
        size -= received;
    }
    return size == 0;
}
inline bool Receive(nlohmann::json& request, const std::atomic_bool& stop) {
    unsigned char prefix[4];
    if (!ReadExact(reinterpret_cast<char*>(prefix), 4, stop))
        return false;
    const u32 size =
        u32{prefix[0]} | (u32{prefix[1]} << 8) | (u32{prefix[2]} << 16) | (u32{prefix[3]} << 24);
    if (!size || size > 65536)
        return false;
    std::string payload(size, '\0');
    if (!ReadExact(payload.data(), size, stop))
        return false;
    request = nlohmann::json::parse(payload, nullptr, false);
    return !request.is_discarded();
}
inline void Send(const nlohmann::json& reply) {
    const auto payload = reply.dump();
    if (payload.size() > 65536)
        throw std::runtime_error("reply exceeds control bound");
    for (unsigned i = 0; i < 4; ++i)
        std::cout.put(static_cast<char>(payload.size() >> (i * 8)));
    std::cout.write(payload.data(), payload.size());
    std::cout.flush();
    if (!std::cout)
        throw std::runtime_error("control pipe disconnected");
}
} // namespace CtrWorker
