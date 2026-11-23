// Worker audio adapter: raw DSP capture plus optional normal host playback.
#pragma once
#include <algorithm>
#include <array>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include "audio_core/sink.h"
#include "audio_core/sink_details.h"
#include "audio_core/worker_wav_capture.h"
#include "common/settings.h"
namespace AudioCore {
struct WorkerAudioStats {
    u64 samples = 0, dropped = 0, hash = 14695981039346656037ull;
    size_t buffered = 0;
};
class WorkerSink final : public Sink {
public:
    inline static std::mutex mutex;
    inline static std::array<s16, 32768> ring{};
    inline static WorkerAudioStats stats;
    inline static WorkerSink* active = nullptr;
    inline static bool focused = false;
    WorkerSink() { active = this; if (focused) SetFocus(true); }
    ~WorkerSink() override { output.reset(); active = nullptr; }
    unsigned GetNativeSampleRate() const override { return native_sample_rate; }
    void SetCallback(std::function<void(s16*, std::size_t)> cb) override {
        callback = std::move(cb);
        if (output) output->SetCallback(callback);
    }
    bool ImmediateSubmission() override { return !output; }
    // Raw samples are captured once in DspInterface, before volume or time stretching.
    void PushSamples(const void*, std::size_t) override {}
    static void SetFocus(bool enabled) {
        if (!active) { focused = enabled; return; }
        active->output.reset();
        focused = false;
        if (enabled) {
            const auto& details = GetSinkDetails(SinkType::Cubeb);
            if (details.type != SinkType::Cubeb) throw std::runtime_error("Cubeb host output unavailable");
            active->output = details.create_sink(Settings::values.output_device.GetValue());
            active->output->SetCallback(active->callback);
            focused = true;
        }
    }
    static void Record(const void* data, std::size_t count) {
        const auto* samples = static_cast<const s16*>(data);
        std::scoped_lock lock{mutex};
        for (size_t i = 0; i < count * 2; ++i) {
            ring[(stats.samples * 2 + i) % ring.size()] = samples[i];
            const auto value = static_cast<u16>(samples[i]);
            stats.hash = (stats.hash ^ (value & 255)) * 1099511628211ull;
            stats.hash = (stats.hash ^ (value >> 8)) * 1099511628211ull;
        }
        capture.Push(data, count);
        stats.samples += count;
        const auto total = stats.buffered + count;
        stats.dropped += total > ring.size() / 2 ? total - ring.size() / 2 : 0;
        stats.buffered = std::min(total, ring.size() / 2);
    }
    static WorkerWavCapture::Status CaptureStart(const std::filesystem::path& path) {
        return capture.Start(path, native_sample_rate);
    }
    static WorkerWavCapture::Status CaptureStop() {
        return capture.Stop();
    }
    static WorkerAudioStats Drain() {
        std::scoped_lock lock{mutex}; const auto snapshot=stats;stats.buffered=0;return snapshot;
    }
    static void Reset() { CaptureStop(); std::scoped_lock lock{mutex};stats={}; }
private:
    inline static WorkerWavCapture capture;
    std::function<void(s16*, std::size_t)> callback;
    std::unique_ptr<Sink> output;
};
} // namespace AudioCore
