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

// Row-major BGRA of one screen at `scale`, into `pixels` (width*height*4 bytes).
// Software: copied from the renderer's own buffer. Vulkan: `preview` selects the
// double-buffered readback (may return an earlier request's frame, see
// RendererBase::PreviewOffscreen); otherwise a synchronous readback. Returns frame_id
// of the pixels.
inline u64 ScreenPixels(Core::System& system, const ScreenSpec& screen, u32 scale, u8* pixels,
                        bool preview, u64 frame_id) {
    auto& renderer = system.GPU().Renderer();
    const auto width = screen.native_width * scale, height = 240 * scale;
    if (Settings::values.graphics_api.GetValue() == Settings::GraphicsAPI::Software) {
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
        return frame_id;
    }
#ifdef ENABLE_VULKAN
    auto layout = Layout::SingleFrameLayout(width, height, screen.id == VideoCore::ScreenId::Bottom, false);
    layout.render_3d_mode = Settings::StereoRenderOption::Off;
    if (preview)
        return renderer.PreviewOffscreen(pixels, layout, screen.id == VideoCore::ScreenId::Bottom,
                                         frame_id);
    renderer.CaptureOffscreen(pixels, layout);
    return frame_id;
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
        ScreenPixels(system, screen, scale, data.data() + FRAME_HEADER, false, 0);
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

    nlohmann::json Write(Core::System& system, u64 epoch, u64 frames) {
        Open();
        const u64 sequence = ++this->sequence;
        const u64 slot = sequence % SLOTS;
        u8* base = view + slot * SLOT;
        const u64 id = (epoch << FRAME_BITS) | (frames & ((u64{1} << FRAME_BITS) - 1));
        u64 shown = id;
        nlohmann::json leases = nlohmann::json::array();
        std::size_t offset = 0;
        for (const auto& screen : SCREENS) {
            const u32 width = screen.native_width, height = 240;
            shown = ScreenPixels(system, screen, 1, base + offset + FRAME_HEADER, true, id);
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
        // Both screens come from the same request, so they share one frame id.
        return {{"name", name},
                {"bytes", BYTES},
                {"frames", leases},
                {"frame", shown & ((u64{1} << FRAME_BITS) - 1)},
                {"current_frame", frames},
                {"current_epoch", epoch}};
    }

private:
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
