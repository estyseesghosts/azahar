// Bounded muted sink. DSP execution continues; no host audio device is opened.
#pragma once
#include <array>
#include <mutex>
#include "audio_core/sink.h"

namespace AudioCore {
struct WorkerAudioStats {
    u64 samples = 0;
    u64 dropped = 0;
    u64 hash = 14695981039346656037ull;
    size_t buffered = 0;
};
class WorkerSink final : public Sink {
public:
    inline static std::mutex mutex;
    inline static std::array<s16, 32768> ring{};
    inline static WorkerAudioStats stats;
    unsigned GetNativeSampleRate() const override {
        return native_sample_rate;
    }
    void SetCallback(std::function<void(s16*, std::size_t)>) override {}
    bool ImmediateSubmission() override {
        return true;
    }
    void PushSamples(const void* data, std::size_t count) override {
        const auto* samples = static_cast<const s16*>(data);
        std::scoped_lock lock{mutex};
        for (size_t i = 0; i < count * 2; ++i) {
            ring[(stats.samples * 2 + i) % ring.size()] = samples[i];
            const auto value = static_cast<u16>(samples[i]);
            stats.hash = (stats.hash ^ (value & 255)) * 1099511628211ull;
            stats.hash = (stats.hash ^ (value >> 8)) * 1099511628211ull;
        }
        stats.samples += count;
        const auto total = stats.buffered + count;
        stats.dropped += total > ring.size() / 2 ? total - ring.size() / 2 : 0;
        stats.buffered = std::min(total, ring.size() / 2);
    }
    static WorkerAudioStats Drain() {
        std::scoped_lock lock{mutex};
        const auto snapshot = stats;
        stats.buffered = 0;
        return snapshot;
    }
    static void Reset() {
        std::scoped_lock lock{mutex};
        stats = {};
    }
};
} // namespace AudioCore
