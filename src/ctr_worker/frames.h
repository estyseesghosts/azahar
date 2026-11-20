#pragma once
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <json.hpp>
#include "core/core.h"
#include "video_core/gpu.h"
#include "video_core/renderer_software/renderer_software.h"
#ifdef _WIN32
#include <windows.h>
#endif

namespace CtrWorker {
struct ScreenSpec {
    const char* name;
    VideoCore::ScreenId id;
    u32 native_width;
};
inline constexpr ScreenSpec SCREENS[] = {{"top", VideoCore::ScreenId::TopLeft, 400u},
                                         {"bottom", VideoCore::ScreenId::Bottom, 320u}};
// "LTRF", version, epoch, sequence, width, height; little endian (supported hosts are).
inline constexpr std::size_t FRAME_HEADER = 32;

inline void FrameHeader(u8* out, u64 epoch, u64 sequence, u32 width, u32 height) {
    std::memcpy(out, "LTRF", 4);
    const auto put = [&out](std::size_t at, u64 value, unsigned bytes) {
        for (unsigned i = 0; i < bytes; ++i) out[at + i] = static_cast<u8>(value >> (i * 8));
    };
    put(4, 1, 4);
    put(8, epoch, 8);
    put(16, sequence, 8);
    put(24, width, 4);
    put(28, height, 4);
}

inline Layout::FramebufferLayout ScreenLayout(const ScreenSpec& screen, u32 scale) {
    auto layout = Layout::SingleFrameLayout(screen.native_width * scale, 240 * scale,
                                            screen.id == VideoCore::ScreenId::Bottom, false);
    layout.render_3d_mode = Settings::StereoRenderOption::Off;
    return layout;
}

inline bool SoftwareRenderer() {
    return Settings::values.graphics_api.GetValue() == Settings::GraphicsAPI::Software;
}

// Row-major BGRA of the current frame of one screen at `scale`, into `pixels`
// (width*height*4 bytes). Software: copied from the renderer's own buffer. Vulkan: a
// synchronous readback.
inline void ScreenPixels(Core::System& system, const ScreenSpec& screen, u32 scale, u8* pixels) {
    auto& renderer = system.GPU().Renderer();
    const auto width = screen.native_width * scale, height = 240 * scale;
    if (SoftwareRenderer()) {
        const auto& source = static_cast<SwRenderer::RendererSoftware&>(renderer).Screen(screen.id);
        if (source.width != 240 || source.height != screen.native_width ||
            source.pixels.size() != screen.native_width * 240 * 4)
            throw std::runtime_error("unsupported framebuffer layout");
        for (u32 y = 0; y < height; ++y)
            for (u32 x = 0; x < width; ++x) {
                const auto input = ((y / scale) * screen.native_width + x / scale) * 4,
                           output = (y * width + x) * 4;
                pixels[output] = source.pixels[input + 2];
                pixels[output + 1] = source.pixels[input + 1];
                pixels[output + 2] = source.pixels[input];
                pixels[output + 3] = source.pixels[input + 3];
            }
        return;
    }
#ifdef ENABLE_VULKAN
    renderer.CaptureOffscreen(pixels, ScreenLayout(screen, scale));
#else
    throw std::runtime_error("offscreen capture unsupported by renderer");
#endif
}

// Explicit capture: three reusable files per screen. A consumer copies before asking for
// another capture. Always the current frame (synchronous readback).
inline nlohmann::json Capture(Core::System& system, const std::filesystem::path& root, u64 epoch,
                              u64 sequence, u32 scale=1) {
    if(!scale||scale>4)throw std::invalid_argument("capture scale 1..4");
    nlohmann::json frames = nlohmann::json::array();
    std::filesystem::create_directories(root / "frames");
    for (const auto& screen : SCREENS) {
        const auto width=screen.native_width*scale,height=240*scale;
        std::vector<u8> data(FRAME_HEADER + width * height * 4);
        ScreenPixels(system, screen, scale, data.data() + FRAME_HEADER);
        FrameHeader(data.data(), epoch, sequence, width, height);
        const auto relative =
            "frames/" + std::string{screen.name} + "-" + std::to_string(sequence % 3) + ".bgra";
        std::ofstream file{root / relative, std::ios::binary | std::ios::trunc};
        file.exceptions(std::ios::failbit | std::ios::badbit);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        frames.push_back({{"screen", screen.name},
                          {"path", relative},
                          {"epoch", epoch},
                          {"sequence", sequence},
                          {"slot", sequence % 3},
                          {"width", width},
                          {"height", height},
                          {"stride", width * 4},
                          {"format", "bgra8"},
                          {"orientation", "top_left_row_major"},
                          {"bytes", width * height * 4}});
    }
    return frames;
}

// Live preview ring (Windows): a pagefile-backed section, so steady-state previews never
// touch disk. Three slots; each holds both native screens as LTRF header + pixels, the same
// bytes as the capture files. The worker writes a slot only while answering `preview`, and the
// host copies it before its next request to this worker (requests are serialized), so a slot
// is never read while written; the header's epoch and sequence reject stale slots.
// While running, Vulkan previews never wait for the GPU (RendererBase::PreviewScreens): a
// request publishes the newest completed pair of this epoch, or, when none is newer than the
// last one published, answers with that slot again (`new_frame: false`), or with no frames when
// this epoch has none yet. A paused request may wait and always shows the current frame.
class PreviewRing {
public:
    static constexpr u32 SLOTS = 3;
    static constexpr std::size_t TOP = FRAME_HEADER + 400 * 240 * 4;
    static constexpr std::size_t SLOT = TOP + FRAME_HEADER + 320 * 240 * 4;
    static constexpr std::size_t BYTES = SLOT * SLOTS;
    // Frame ids carry the epoch, so a frame from before a load/reset/restore is never
    // labelled with the new epoch.
    static constexpr unsigned FRAME_BITS = 40;

    static constexpr bool Supported() {
#ifdef _WIN32
        return true;
#else
        return false;
#endif
    }

    PreviewRing() = default;
    PreviewRing(const PreviewRing&) = delete;
    PreviewRing& operator=(const PreviewRing&) = delete;
    ~PreviewRing() {
#ifdef _WIN32
        if (view) UnmapViewOfFile(view);
        if (mapping) CloseHandle(mapping);
#endif
    }

    nlohmann::json Write(Core::System& system, u64 epoch, u64 frames, bool nonblocking) {
        Open();
        ++requests;
        const u64 sequence = this->sequence + 1;
        const u64 slot = sequence % SLOTS;
        u8* base = view + slot * SLOT;
        const u64 id = (epoch << FRAME_BITS) | (frames & ((u64{1} << FRAME_BITS) - 1));
        u64 shown = id;
        if (SoftwareRenderer()) {
            std::size_t offset = 0;
            for (const auto& screen : SCREENS) {
                ScreenPixels(system, screen, 1, base + offset + FRAME_HEADER);
                offset += FRAME_HEADER + screen.native_width * 240 * 4;
            }
        } else {
            shown = system.GPU().Renderer().PreviewScreens(
                {base + FRAME_HEADER, base + TOP + FRAME_HEADER},
                {ScreenLayout(SCREENS[0], 1), ScreenLayout(SCREENS[1], 1)}, id, epoch << FRAME_BITS,
                !nonblocking);
        }
        if (!shown) {
            ++reused;
            nlohmann::json reply = last.is_object() && last.value("epoch", u64{0}) == epoch
                                       ? last
                                       : nlohmann::json{{"name", name}, {"bytes", BYTES},
                                                        {"frames", nlohmann::json::array()}, {"frame", 0}};
            reply.erase("epoch");
            reply["new_frame"] = false;
            reply["current_frame"] = frames;
            reply["current_epoch"] = epoch;
            reply["stats"] = Stats(system);
            return reply;
        }
        this->sequence = sequence;
        nlohmann::json leases = nlohmann::json::array();
        std::size_t offset = 0;
        for (const auto& screen : SCREENS) {
            const u32 width = screen.native_width, height = 240;
            const u64 shown_epoch = shown >> FRAME_BITS;
            FrameHeader(base + offset, shown_epoch, sequence, width, height);
            leases.push_back({{"screen", screen.name},
                              {"offset", slot * SLOT + offset},
                              {"epoch", shown_epoch},
                              {"sequence", sequence},
                              {"slot", slot},
                              {"width", width},
                              {"height", height},
                              {"stride", width * 4},
                              {"format", "bgra8"},
                              {"orientation", "top_left_row_major"},
                              {"bytes", width * height * 4}});
            offset += FRAME_HEADER + width * height * 4;
        }
        // Both screens come from one completed pair, so they share one frame id.
        nlohmann::json reply = {{"name", name},
                                {"bytes", BYTES},
                                {"frames", leases},
                                {"frame", shown & ((u64{1} << FRAME_BITS) - 1)}};
        last = reply;
        last["epoch"] = shown >> FRAME_BITS;
        reply["new_frame"] = true;
        reply["current_frame"] = frames;
        reply["current_epoch"] = epoch;
        reply["stats"] = Stats(system);
        return reply;
    }

private:
    nlohmann::json Stats(Core::System& system) const {
        const auto gpu = system.GPU().Renderer().PreviewStatistics();
        return {{"requests", requests},         {"reused", reused},
                {"readbacks", gpu.readbacks},   {"skipped_busy", gpu.skipped_busy},
                {"gpu_waits", gpu.gpu_waits},   {"gpu_wait_ns", gpu.gpu_wait_ns},
                {"copied_bytes", gpu.copied_bytes}};
    }
    u64 requests = 0, reused = 0;
    nlohmann::json last; // reply of the last published slot, with its epoch
    void Open() {
        if (view) return;
#ifdef _WIN32
        std::random_device random;
        const u64 nonce = (u64{random()} << 32) | random();
        char text[96];
        std::snprintf(text, sizeof text, "Local\\lotus-ctr-%lu-%016llx", GetCurrentProcessId(),
                      static_cast<unsigned long long>(nonce));
        mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                     static_cast<DWORD>(BYTES), text);
        if (!mapping || GetLastError() == ERROR_ALREADY_EXISTS)
            throw std::runtime_error("preview mapping unavailable");
        view = static_cast<u8*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, BYTES));
        if (!view) throw std::runtime_error("preview mapping unavailable");
        name = text;
#else
        throw std::runtime_error("shared-memory preview is Windows only");
#endif
    }

#ifdef _WIN32
    HANDLE mapping = nullptr;
#endif
    u8* view = nullptr;
    std::string name;
    u64 sequence = 0;
};
} // namespace CtrWorker
