// Worker audio adapter: raw DSP capture plus optional normal host playback.
#pragma once
#include <algorithm>
#include <array>
#include <fstream>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include "audio_core/sink.h"
#include "audio_core/sink_details.h"
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
    inline static std::ofstream capture;
    inline static u32 capture_bytes = 0;
    inline static bool capture_full = false;
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
        if (capture.is_open()) {
            constexpr size_t limit = 64u << 20;
            const auto bytes = std::min(count * 4, limit - capture_bytes);
            capture.write(static_cast<const char*>(data), bytes);
            capture_bytes += static_cast<u32>(bytes);
            if (bytes < count * 4) capture_full = true;
        }
        stats.samples += count;
        const auto total = stats.buffered + count;
        stats.dropped += total > ring.size() / 2 ? total - ring.size() / 2 : 0;
        stats.buffered = std::min(total, ring.size() / 2);
    }
    static void Header(u32 bytes) {
        const auto le = [](u32 v, unsigned count) {
            for (unsigned i=0;i<count;++i) capture.put(static_cast<char>(v >> (8*i)));
        };
        capture.seekp(0); capture.write("RIFF",4);le(bytes+36,4);capture.write("WAVEfmt ",8);
        le(16,4);le(1,2);le(2,2);le(native_sample_rate,4);le(native_sample_rate*4,4);
        le(4,2);le(16,2);capture.write("data",4);le(bytes,4);
    }
    static void CaptureStart(const std::filesystem::path& path) {
        std::scoped_lock lock{mutex};
        if (capture.is_open()) throw std::invalid_argument("audio capture already active");
        capture.open(path, std::ios::binary | std::ios::trunc);
        if (!capture) throw std::runtime_error("cannot create WAV capture");
        capture.exceptions(std::ios::badbit | std::ios::failbit);
        capture_bytes = 0;capture_full = false;Header(0);
    }
    static u32 CaptureStop() {
        std::scoped_lock lock{mutex};
        if (!capture.is_open()) return capture_bytes;
        Header(capture_bytes);capture.flush();capture.close();return capture_bytes;
    }
    static WorkerAudioStats Drain() {
        std::scoped_lock lock{mutex}; const auto snapshot=stats;stats.buffered=0;return snapshot;
    }
    static void Reset() { CaptureStop(); std::scoped_lock lock{mutex};stats={}; }
private:
    std::function<void(s16*, std::size_t)> callback;
    std::unique_ptr<Sink> output;
};
} // namespace AudioCore
