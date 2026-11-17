#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <iostream>
#include <mutex>
#include <stdexcept>
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
// Ends a reader thread blocked in a stdin read so stopping can join it without orphan
// threads. Windows reads block in ReadFile and are cancelled with CancelSynchronousIo. The
// earlier PeekNamedPipe loop slept sleep_for(1 ms) on an empty pipe, which lasts until the
// next timer tick (about 15.6 ms at the default resolution) and so delayed every request by
// up to a tick: Lotus measured 14.8 ms p50 for `registers` on a running worker (lotus#22,
// tools/bench_parallel.py, runs/bp-real-02).
class StdinReader {
public:
    // On the reader thread, before its first read.
    void Enter() {
#ifdef _WIN32
        HANDLE self = nullptr;
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &self, 0,
                            FALSE, DUPLICATE_SAME_ACCESS))
            thread = self;
#endif
    }
    // On the reader thread, after its last read.
    void Exit() { done = true; }
    // From another thread once `stop` is set: unblock the read and wait for Exit. Repeated
    // because a cancel issued before the reader enters ReadFile has nothing to cancel.
    void Interrupt() {
#ifdef _WIN32
        while (!done) {
            if (const HANDLE handle = thread)
                CancelSynchronousIo(handle);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (const HANDLE handle = thread.exchange(nullptr))
            CloseHandle(handle);
#endif
    }

private:
    std::atomic_bool done = false;
#ifdef _WIN32
    std::atomic<HANDLE> thread = nullptr;
#endif
};
inline bool ReadExact(char* data, size_t size, const std::atomic_bool& stop) {
    while (size && !stop) {
#ifdef _WIN32
        // Blocks until bytes arrive, the host closes the pipe, or StdinReader::Interrupt.
        DWORD received = 0;
        if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), data,
                      static_cast<DWORD>(std::min<size_t>(size, 65536)), &received, nullptr) ||
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
// The control channel owns the original stdout. Everything else that writes to
// stdout (Teakra, third-party printf) is redirected to stderr so it can never
// corrupt reply framing.
inline int& ControlOutput() {
    static int descriptor = -1;
    return descriptor;
}
inline void ReserveControlOutput() {
    std::fflush(stdout);
#ifdef _WIN32
    const int reserved = _dup(_fileno(stdout));
    if (reserved < 0 || _dup2(_fileno(stderr), _fileno(stdout)) != 0)
        throw std::runtime_error("cannot reserve control output");
    _setmode(reserved, _O_BINARY);
    SetStdHandle(STD_OUTPUT_HANDLE, GetStdHandle(STD_ERROR_HANDLE));
#else
    const int reserved = dup(STDOUT_FILENO);
    if (reserved < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0)
        throw std::runtime_error("cannot reserve control output");
#endif
    ControlOutput() = reserved;
}
inline void WriteControl(const char* data, size_t size) {
    while (size) {
#ifdef _WIN32
        const int written = _write(ControlOutput(), data, static_cast<unsigned>(size));
#else
        const auto written = write(ControlOutput(), data, size);
#endif
        if (written <= 0)
            throw std::runtime_error("control pipe disconnected");
        data += written;
        size -= static_cast<size_t>(written);
    }
}
// A length-prefixed frame, or empty when the payload exceeds the 64 KiB control bound.
inline std::string Frame(const nlohmann::json& message) {
    const auto payload = message.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (payload.size() > 65536)
        return {};
    std::string frame(4, '\0');
    for (unsigned i = 0; i < 4; ++i)
        frame[i] = static_cast<char>(payload.size() >> (i * 8));
    return frame + payload;
}
// Serializes and writes control frames on its own thread, so the emulation thread never
// formats a frame or blocks on the pipe (lotus#26). Before, every reply and notification was
// dumped and written synchronously by the thread that produced it; a host that read slowly
// stalled emulation, and every PICA, SVC or log event cost a pipe write. Replies and reliable
// notifications (debug stops) keep their order and are never dropped; they are bounded by
// the request queue (16) and by one stop per resume. Best-effort notifications are bounded
// at BEST_EFFORT_LIMIT: a new one past the bound drops the oldest queued one, counted in
// `dropped` and reported in every later notification as `notifications_dropped`.
class ControlWriter {
public:
    static constexpr size_t BEST_EFFORT_LIMIT = 1024;
    void Start() {
        if (ControlOutput() < 0)
            throw std::runtime_error("control output not reserved");
        thread = std::thread([this] { Loop(); });
    }
    void Post(nlohmann::json message, bool reliable) {
        {
            std::scoped_lock lock{mutex};
            if (failed || closing)
                return;
            if (!reliable) {
                if (best_effort == BEST_EFFORT_LIMIT) {
                    for (auto entry = queue.begin(); entry != queue.end(); ++entry) {
                        if (!entry->reliable) {
                            queue.erase(entry);
                            break;
                        }
                    }
                    ++dropped;
                } else {
                    ++best_effort;
                }
            }
            queue.push_back({std::move(message), reliable});
            peak = std::max(peak, queue.size());
        }
        ready.notify_one();
    }
    // Writes everything already queued, then ends the thread. Blocks while the host does not
    // read, as the synchronous writes did.
    void Close() {
        {
            std::scoped_lock lock{mutex};
            closing = true;
        }
        ready.notify_one();
        if (thread.joinable())
            thread.join();
    }
    bool Failed() const {
        return failed;
    }
    nlohmann::json Stats() {
        std::scoped_lock lock{mutex};
        return {{"queued", queue.size()},     {"best_effort_queued", best_effort},
                {"best_effort_limit", BEST_EFFORT_LIMIT}, {"peak", peak},
                {"written", written},         {"dropped", dropped},
                {"oversize_dropped", oversize}};
    }

private:
    struct Entry {
        nlohmann::json message;
        bool reliable;
    };
    void Loop() {
        for (;;) {
            Entry entry;
            {
                std::unique_lock lock{mutex};
                ready.wait(lock, [this] { return !queue.empty() || closing; });
                if (queue.empty())
                    return;
                entry = std::move(queue.front());
                queue.pop_front();
                if (!entry.reliable)
                    --best_effort;
                if (entry.message.contains("notification"))
                    entry.message["notifications_dropped"] = dropped;
            }
            const auto frame = Frame(entry.message);
            try {
                if (frame.empty()) {
                    // A reply must never be lost; an oversized event is dropped and counted.
                    if (entry.reliable)
                        throw std::runtime_error("reply exceeds control bound");
                    std::scoped_lock lock{mutex};
                    ++oversize;
                    continue;
                }
                WriteControl(frame.data(), frame.size());
            } catch (const std::exception& error) {
                std::cerr << "worker_control_error: " << error.what() << '\n';
                std::scoped_lock lock{mutex};
                failed = true;
                queue.clear();
                best_effort = 0;
                return;
            }
            std::scoped_lock lock{mutex};
            ++written;
        }
    }
    std::mutex mutex;
    std::condition_variable ready;
    std::deque<Entry> queue;
    std::thread thread;
    size_t best_effort = 0, peak = 0;
    unsigned long long written = 0, dropped = 0, oversize = 0;
    bool closing = false;
    std::atomic_bool failed = false;
};
} // namespace CtrWorker
