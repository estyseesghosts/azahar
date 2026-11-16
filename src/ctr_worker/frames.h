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
inline nlohmann::json Capture(Core::System& system, const std::filesystem::path& root, u64 epoch,
                              u64 sequence, u32 scale=1) {
    if(!scale||scale>4)throw std::invalid_argument("capture scale 1..4");
    auto& renderer = system.GPU().Renderer();
    nlohmann::json frames = nlohmann::json::array();
    std::filesystem::create_directories(root / "frames");
    for (const auto& [name, id, native_width] :
         {std::tuple{"top", VideoCore::ScreenId::TopLeft, 400u},
          std::tuple{"bottom", VideoCore::ScreenId::Bottom, 320u}}) {
        const auto width=native_width*scale,height=240*scale;
        std::vector<u8> pixels(width * height * 4);
        if (Settings::values.graphics_api.GetValue() == Settings::GraphicsAPI::Software) {
            const auto& source = static_cast<SwRenderer::RendererSoftware&>(renderer).Screen(id);
            if (source.width != 240 || source.height != native_width ||
                source.pixels.size() != native_width * 240 * 4)
                throw std::runtime_error("unsupported framebuffer layout");
            for(u32 y=0;y<height;++y)for(u32 x=0;x<width;++x) {
                const auto input=((y/scale)*native_width+x/scale)*4,output=(y*width+x)*4;
                pixels[output]=source.pixels[input+2];pixels[output+1]=source.pixels[input+1];
                pixels[output+2]=source.pixels[input];pixels[output+3]=source.pixels[input+3];
            }
        }
#ifdef ENABLE_VULKAN
        else {
            auto layout = Layout::SingleFrameLayout(width, height, id == VideoCore::ScreenId::Bottom, false);
            layout.render_3d_mode = Settings::StereoRenderOption::Off;
            renderer.CaptureOffscreen(pixels.data(), layout);
        }
#endif
        const auto relative =
            "frames/" + std::string{name} + "-" + std::to_string(sequence % 3) + ".bgra";
        std::ofstream file{root / relative, std::ios::binary | std::ios::trunc};
        file.exceptions(std::ios::failbit | std::ios::badbit);
        // Windows/Linux supported hosts are little endian; wire header uses explicit shifts.
        file.write("LTRF", 4);
        const auto write_le = [&file](u64 value, unsigned bytes) {
            for (unsigned i = 0; i < bytes; ++i)
                file.put(static_cast<char>(value >> (i * 8)));
        };
        write_le(1, 4);
        write_le(epoch, 8);
        write_le(sequence, 8);
        write_le(width, 4);
        write_le(height, 4);
        file.write(reinterpret_cast<const char*>(pixels.data()), pixels.size());
        file.close();
        frames.push_back({{"screen", name},
                          {"path", relative},
                          {"epoch", epoch},
                          {"sequence", sequence},
                          {"slot", sequence % 3},
                          {"width", width},
                          {"height", height},
                          {"stride", width * 4},
                          {"format", "bgra8"},
                          {"orientation", "top_left_row_major"},
                          {"bytes", pixels.size()}});
    }
    return frames;
}
} // namespace CtrWorker
