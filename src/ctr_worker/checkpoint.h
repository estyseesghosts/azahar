#pragma once
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>
#include "core/core.h"

// Rewind checkpoints compressed off the emulation thread (lotus#32).
//
// The emulation thread serializes the state at a safe point (Core::System::SerializeState) and
// hands the bytes to one compression thread. From then on the serialized bytes are immutable:
// the compressor only reads them, and a restore before compression finishes loads them
// directly. The compressed result replaces them under the checkpoint's mutex.
//
// `depth` bounds the checkpoints waiting for or in compression, which bounds the extra
// serialized buffers a worker holds (142 MiB Old 3DS, 274 MiB New 3DS, docs/34). A checkpoint
// that finds the queue full waits for a slot before serializing, so a backlog costs time on the
// emulation thread but never drops or skips a checkpoint. Depth 0 compresses on the calling
// thread, as before lotus#32.
struct Checkpoint {
    std::array<u8, 256> header{};
    int level = 3;
    std::mutex mutex;
    std::vector<u8> serialized; // emptied once `compressed` holds the state
    std::vector<u8> compressed; // CST header + zstd frame, as Core::System::SaveStateBuffer
    std::atomic<bool> done{false};
    bool failed = false; // compression failed; `serialized` is kept and is the state
    u64 compress_ns = 0;
    u64 serialized_bytes = 0;

    void Compress() {
        const auto start = std::chrono::steady_clock::now();
        auto result = Core::System::CompressState(header, serialized, level);
        const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                 std::chrono::steady_clock::now() - start)
                                 .count();
        std::scoped_lock lock{mutex};
        compress_ns = elapsed;
        if (result.empty()) {
            failed = true;
        } else {
            compressed = std::move(result);
            std::vector<u8>{}.swap(serialized);
        }
        done.store(true, std::memory_order_release);
    }
    // Bytes this checkpoint keeps once settled.
    u64 StoredBytes() const {
        return failed ? serialized.size() : compressed.size();
    }
    // `from_serialized` reports whether compression had not finished (or failed).
    bool Restore(Core::System& system, bool& from_serialized) {
        std::scoped_lock lock{mutex};
        from_serialized = !serialized.empty();
        if (from_serialized) return system.LoadStateSerialized(serialized);
        return system.LoadStateBuffer(std::span<const u8>{compressed});
    }
};

class CheckpointCompressor {
public:
    ~CheckpointCompressor() {
        {
            std::scoped_lock lock{mutex};
            stopping = true;
            queue.clear();
        }
        changed.notify_all();
        if (thread.joinable()) thread.join();
    }
    // Blocks until fewer than `depth` checkpoints are pending. Returns nanoseconds waited.
    u64 WaitForSlot(size_t depth) {
        std::unique_lock lock{mutex};
        if (pending < depth) return 0;
        const auto start = std::chrono::steady_clock::now();
        changed.wait(lock, [&] { return pending < depth; });
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
                   std::chrono::steady_clock::now() - start)
            .count();
    }
    void Submit(std::shared_ptr<Checkpoint> checkpoint) {
        {
            std::scoped_lock lock{mutex};
            if (!thread.joinable()) thread = std::thread([this] { Run(); });
            pending_bytes += checkpoint->serialized_bytes;
            ++pending;
            peak_pending_bytes = std::max(peak_pending_bytes, pending_bytes);
            queue.push_back(std::move(checkpoint));
        }
        changed.notify_all();
    }
    struct Load {
        u64 pending, pending_bytes, peak_pending_bytes;
    };
    Load Current() const {
        std::scoped_lock lock{mutex};
        return {pending, pending_bytes, peak_pending_bytes};
    }
    // The caller has dropped history. Wait for the active job to release its buffer before
    // a new configuration can allocate checkpoints, including when switching to depth zero.
    void Reset() {
        std::unique_lock lock{mutex};
        changed.wait(lock, [&] { return pending == 0; });
        peak_pending_bytes = 0;
    }

private:
    void Run() {
        std::unique_lock lock{mutex};
        while (true) {
            changed.wait(lock, [&] { return stopping || !queue.empty(); });
            if (stopping) return;
            auto checkpoint = std::move(queue.front());
            queue.pop_front();
            lock.unlock();
            // The history holds the other reference. Once it has dropped the checkpoint
            // (eviction, reverse, reconfigure), no new reference can appear, so skip the work.
            if (checkpoint.use_count() > 1) checkpoint->Compress();
            const u64 bytes = checkpoint->serialized_bytes;
            checkpoint.reset();
            lock.lock();
            pending_bytes -= bytes;
            --pending;
            changed.notify_all();
        }
    }

    mutable std::mutex mutex;
    std::condition_variable changed;
    std::deque<std::shared_ptr<Checkpoint>> queue;
    u64 pending = 0, pending_bytes = 0, peak_pending_bytes = 0;
    bool stopping = false;
    std::thread thread;
};
