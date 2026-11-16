#pragma once
#include <filesystem>
#include <fstream>
#include <json.hpp>
#include "core/core.h"
#include "video_core/gpu.h"
#include "video_core/renderer_software/renderer_software.h"

namespace CtrWorker {
// Three reusable slots. A consumer copies before asking for another capture.
// No UI acknowledgement or retained guest pointers can stall the core.
inline nlohmann::json Capture(Core::System& system, const std::filesystem::path& root,
                              u64 epoch, u64 sequence) {
    const auto& renderer = static_cast<const SwRenderer::RendererSoftware&>(system.GPU().Renderer());
    nlohmann::json frames = nlohmann::json::array();
    std::filesystem::create_directories(root / "frames");
    for (const auto& [name, id, width] : {
             std::tuple{"top", VideoCore::ScreenId::TopLeft, 400u},
             std::tuple{"bottom", VideoCore::ScreenId::Bottom, 320u}}) {
        const auto& source = renderer.Screen(id);
        if (source.width != 240 || source.height != width || source.pixels.size() != width * 240 * 4)
            throw std::runtime_error("unsupported framebuffer layout");
        auto pixels = source.pixels;
        for (size_t i = 0; i < pixels.size(); i += 4) std::swap(pixels[i], pixels[i + 2]);
        const auto relative = "frames/" + std::string{name} + "-" + std::to_string(sequence % 3) + ".bgra";
        std::ofstream file{root / relative, std::ios::binary | std::ios::trunc};
        file.exceptions(std::ios::failbit | std::ios::badbit);
        // Windows/Linux supported hosts are little endian; wire header uses explicit shifts.
        file.write("LTRF", 4);
        const auto write_le = [&file](u64 value, unsigned bytes) {
            for (unsigned i = 0; i < bytes; ++i) file.put(static_cast<char>(value >> (i * 8)));
        };
        write_le(1, 4); write_le(epoch, 8); write_le(sequence, 8);
        write_le(width, 4); write_le(240, 4);
        file.write(reinterpret_cast<const char*>(pixels.data()), pixels.size());
        file.close();
        frames.push_back({{"screen", name}, {"path", relative}, {"epoch", epoch},
                          {"sequence", sequence}, {"slot", sequence % 3}, {"width", width},
                          {"height", 240}, {"stride", width * 4}, {"format", "bgra8"},
                          {"orientation", "top_left_row_major"}, {"bytes", pixels.size()}});
    }
    return frames;
}
} // namespace CtrWorker
