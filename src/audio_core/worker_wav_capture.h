// Bounded WAV capture for the worker's raw DSP output.
#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

namespace AudioCore {

class WorkerWavCapture {
  public:
    using BeforeWrite = void (*)();
    static constexpr std::size_t queue_capacity = 256 << 10;
    static constexpr std::size_t pcm_limit = (64 << 20) - 44;
    static constexpr auto control_timeout = std::chrono::seconds{2};

    enum class Phase { Idle, Starting, Recording, Finalizing, Complete, Failed };

    struct Status {
        Phase phase = Phase::Idle;
        std::size_t pcm_bytes = 0;
        std::size_t queued_bytes = 0;
        std::size_t queue_peak_bytes = 0;
        std::uint64_t dropped_blocks = 0;
        std::uint64_t dropped_frames = 0;
        bool limit_reached = false;
        bool queue_overflow = false;
        const char* error = nullptr;

        bool Published() const { return phase == Phase::Complete; }

        const char* Name() const {
            switch (phase) {
            case Phase::Starting:
                return "starting";
            case Phase::Recording:
                return "recording";
            case Phase::Finalizing:
                return "finalizing";
            case Phase::Complete:
                return dropped_frames == 0 ? "complete" : "truncated";
            case Phase::Failed:
                return "failed";
            case Phase::Idle:
                return "idle";
            }
            return "idle";
        }
    };

    WorkerWavCapture() = default;
    explicit WorkerWavCapture(BeforeWrite before_write) : before_write{before_write} {}

    ~WorkerWavCapture() {
        if (writer.joinable()) {
            Stop();
            // A stalled filesystem can outlive the caller's deadline. The writer owns its
            // state until it exits, and the worker process owns the ultimate shutdown deadline.
            if (writer.joinable())
                writer.detach();
        }
    }

    // Start and Stop belong to the worker control thread. Push belongs to the DSP producer.
    Status Start(std::filesystem::path path, unsigned sample_rate) {
        {
            std::scoped_lock lock{state->mutex};
            if (!Terminal(state->status.phase))
                throw std::invalid_argument("audio capture already active");
        }
        JoinFinished();
        {
            std::scoped_lock lock{state->mutex};
            state->head = 0;
            state->admitted = 0;
            state->status = {Phase::Starting};
        }
        try {
            writer = std::thread{Write, state, std::move(path), sample_rate, before_write};
        } catch (const std::system_error&) {
            std::scoped_lock lock{state->mutex};
            state->status.phase = Phase::Failed;
            state->status.error = "could not start WAV writer";
        }
        std::unique_lock lock{state->mutex};
        state->ready.wait_for(lock, control_timeout,
                              [&] { return state->status.phase != Phase::Starting; });
        return state->status;
    }

    Status Stop() {
        Status result;
        {
            std::unique_lock lock{state->mutex};
            if (!Terminal(state->status.phase)) {
                state->accepting.store(false, std::memory_order_relaxed);
                state->status.phase = Phase::Finalizing;
                state->ready.notify_all();
                state->ready.wait_for(lock, control_timeout,
                                      [&] { return Terminal(state->status.phase); });
            }
            result = state->status;
        }
        if (Terminal(result.phase))
            JoinFinished();
        return result;
    }

    void Push(const void* data, std::size_t frames) {
        if (!state->accepting.load(std::memory_order_relaxed) || frames == 0)
            return;
        const auto* samples = static_cast<const char*>(data);
        const auto bytes = frames * bytes_per_frame;
        {
            std::scoped_lock lock{state->mutex};
            if (state->status.phase != Phase::Recording)
                return;
            auto& status = state->status;
            std::size_t kept = 0;
            if (!status.limit_reached && !status.queue_overflow) {
                const auto within_limit = std::min(bytes, pcm_limit - state->admitted);
                kept = std::min(within_limit, queue_capacity - status.queued_bytes);
                // Keep a contiguous prefix. After the first loss, all later frames are counted
                // as dropped instead of filling the WAV with disjoint spans.
                status.queue_overflow = kept != within_limit;
                status.limit_reached = !status.queue_overflow && within_limit != bytes;
                if (kept != 0) {
                    const auto tail = (state->head + status.queued_bytes) % queue_capacity;
                    const auto first = std::min(kept, queue_capacity - tail);
                    std::copy_n(samples, first, state->queue->data() + tail);
                    std::copy_n(samples + first, kept - first, state->queue->data());
                    state->admitted += kept;
                    status.queued_bytes += kept;
                    status.queue_peak_bytes =
                        std::max(status.queue_peak_bytes, status.queued_bytes);
                }
            }
            if (kept != bytes) {
                ++status.dropped_blocks;
                status.dropped_frames += (bytes - kept) / bytes_per_frame;
            }
            if (kept == 0)
                return;
        }
        state->ready.notify_one();
    }

  private:
    static constexpr std::size_t bytes_per_frame = 4;
    static constexpr std::size_t write_bytes = 16 << 10;
    using Queue = std::array<char, queue_capacity>;

    struct Shared {
        std::mutex mutex;
        std::condition_variable ready;
        std::atomic<bool> accepting{false};
        std::unique_ptr<Queue> queue;
        Status status;
        std::size_t head = 0;
        std::size_t admitted = 0;
    };

    std::shared_ptr<Shared> state = std::make_shared<Shared>();
    BeforeWrite before_write = nullptr;
    std::thread writer;

    static bool Terminal(Phase phase) {
        return phase == Phase::Idle || phase == Phase::Complete || phase == Phase::Failed;
    }

    void JoinFinished() {
        if (writer.joinable())
            writer.join();
    }

    static void Header(std::ofstream& file, std::uint32_t bytes, unsigned sample_rate) {
        const auto le = [&](std::uint32_t value, unsigned count) {
            for (unsigned i = 0; i < count; ++i)
                file.put(static_cast<char>(value >> (8 * i)));
        };
        file.seekp(0);
        file.write("RIFF", 4);
        le(bytes + 36, 4);
        file.write("WAVEfmt ", 8);
        le(16, 4);
        le(1, 2);
        le(2, 2);
        le(sample_rate, 4);
        le(sample_rate * bytes_per_frame, 4);
        le(bytes_per_frame, 2);
        le(16, 2);
        file.write("data", 4);
        le(bytes, 4);
    }

    static const char* WriteFile(Shared& state, const std::filesystem::path& pending,
                                 unsigned sample_rate, bool& opened, BeforeWrite before_write) {
        std::ofstream file{pending, std::ios::binary | std::ios::trunc};
        if (!file)
            return "could not open WAV output";
        opened = true;
        Header(file, 0, sample_rate);
        if (!file)
            return "could not write provisional WAV header";
        auto queue = std::make_unique_for_overwrite<Queue>();
        {
            std::scoped_lock lock{state.mutex};
            state.queue = std::move(queue);
            if (state.status.phase == Phase::Starting) {
                state.status.phase = Phase::Recording;
                state.accepting.store(true, std::memory_order_relaxed);
            }
            state.ready.notify_all();
        }
        std::array<char, write_bytes> block;
        std::size_t written = 0;
        while (true) {
            std::size_t count;
            {
                std::unique_lock lock{state.mutex};
                state.ready.wait(lock, [&] {
                    return state.status.queued_bytes != 0 ||
                           state.status.phase == Phase::Finalizing;
                });
                count = std::min(block.size(), state.status.queued_bytes);
                if (count == 0)
                    break;
                const auto first = std::min(count, queue_capacity - state.head);
                std::copy_n(state.queue->data() + state.head, first, block.data());
                std::copy_n(state.queue->data(), count - first, block.data() + first);
                state.head = (state.head + count) % queue_capacity;
                state.status.queued_bytes -= count;
            }
            if (before_write)
                before_write();
            file.write(block.data(), count);
            if (!file)
                return "could not write WAV samples";
            written += count;
            std::scoped_lock lock{state.mutex};
            state.status.pcm_bytes = written;
        }
        Header(file, static_cast<std::uint32_t>(written), sample_rate);
        file.close();
        return file ? nullptr : "could not finalize WAV header";
    }

    static void Write(std::shared_ptr<Shared> state, std::filesystem::path path,
                      unsigned sample_rate, BeforeWrite before_write) {
        std::filesystem::path pending;
        const char* error = nullptr;
        bool opened = false;
        try {
            pending = path;
            pending += ".part";
            std::error_code directory_error;
            if (path.has_parent_path())
                std::filesystem::create_directories(path.parent_path(), directory_error);
            error = directory_error ? "could not create WAV output directory"
                                    : WriteFile(*state, pending, sample_rate, opened, before_write);
            if (!error) {
                std::error_code result;
                std::filesystem::rename(pending, path, result);
                if (result)
                    error = "could not publish WAV output";
            }
        } catch (const std::exception&) {
            error = "WAV writer failed";
        }
        if (error && opened) {
            std::error_code ignored;
            std::filesystem::remove(pending, ignored);
        }
        std::unique_ptr<Queue> queue;
        std::scoped_lock lock{state->mutex};
        queue = std::move(state->queue);
        state->accepting.store(false, std::memory_order_relaxed);
        state->status.phase = error ? Phase::Failed : Phase::Complete;
        state->status.error = error;
        state->status.queued_bytes = 0;
        if (error)
            state->status.pcm_bytes = 0;
        state->ready.notify_all();
    }
};

} // namespace AudioCore
