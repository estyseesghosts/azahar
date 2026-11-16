#pragma once
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>
#include <json.hpp>
#include "common/settings.h"
#include "core/core.h"
#include "core/frontend/camera/factory.h"
#include "core/frontend/camera/interface.h"
#include "core/hle/service/cam/cam.h"

namespace CtrWorker {
// Private still image served to every guest camera. Source: an uncompressed
// 24/32-bit BMP placed in the session root (media/camera.bmp). Pixels are
// scaled with nearest-neighbour sampling. YUV422 uses integer BT.601 studio
// swing; it is not byte-identical to Qt's table-driven converter.
struct CameraImage {
    u32 width = 0, height = 0;
    std::vector<u8> rgb; // row-major, top row first, 3 bytes per pixel
};
inline std::mutex& CameraMutex() {
    static std::mutex mutex;
    return mutex;
}
inline std::shared_ptr<const CameraImage>& CameraSource() {
    static std::shared_ptr<const CameraImage> source;
    return source;
}
inline CameraImage LoadBmp(const std::filesystem::path& path) {
    const auto size = std::filesystem::file_size(path);
    if (size < 54 || size > (16u << 20))
        throw std::invalid_argument("camera BMP size budget");
    std::vector<u8> bytes(size);
    std::ifstream file(path, std::ios::binary);
    file.exceptions(std::ios::failbit | std::ios::badbit);
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
    auto le32 = [&](size_t at) {
        return u32{bytes[at]} | (u32{bytes[at + 1]} << 8) | (u32{bytes[at + 2]} << 16) |
               (u32{bytes[at + 3]} << 24);
    };
    auto le16 = [&](size_t at) { return static_cast<u16>(bytes[at] | (bytes[at + 1] << 8)); };
    if (bytes[0] != 'B' || bytes[1] != 'M')
        throw std::invalid_argument("camera asset is not a BMP");
    const u32 offset = le32(10);
    const auto width = static_cast<s32>(le32(18));
    const auto height = static_cast<s32>(le32(22));
    const u16 bits = le16(28);
    const u32 compression = le32(30);
    if (le16(26) != 1 || (bits != 24 && bits != 32) || (compression != 0 && compression != 3) ||
        width <= 0 || width > 4096 || height == 0 || height > 4096 || height < -4096)
        throw std::invalid_argument("camera BMP must be uncompressed 24/32-bit, at most 4096x4096");
    CameraImage image;
    image.width = static_cast<u32>(width);
    image.height = static_cast<u32>(height < 0 ? -height : height);
    const size_t stride = ((size_t{image.width} * bits / 8) + 3) & ~size_t{3};
    if (offset > size || stride * image.height > size - offset)
        throw std::invalid_argument("truncated camera BMP");
    image.rgb.resize(size_t{image.width} * image.height * 3);
    for (u32 y = 0; y < image.height; ++y) {
        const u32 source_row = height < 0 ? y : image.height - 1 - y;
        const u8* row = bytes.data() + offset + stride * source_row;
        for (u32 x = 0; x < image.width; ++x) {
            const u8* pixel = row + size_t{x} * (bits / 8);
            u8* out = image.rgb.data() + (size_t{y} * image.width + x) * 3;
            out[0] = pixel[2];
            out[1] = pixel[1];
            out[2] = pixel[0];
        }
    }
    return image;
}
class StillCamera final : public Camera::CameraInterface {
public:
    explicit StillCamera(Service::CAM::Flip flip) : base_flip(flip) {}
    void StartCapture() override {}
    void StopCapture() override {}
    void SetResolution(const Service::CAM::Resolution& resolution) override {
        width = resolution.width;
        height = resolution.height;
    }
    void SetFlip(Service::CAM::Flip value) override { flip = value; }
    void SetEffect(Service::CAM::Effect) override {}
    void SetFormat(Service::CAM::OutputFormat format) override {
        rgb565 = format == Service::CAM::OutputFormat::RGB565;
    }
    void SetFrameRate(Service::CAM::FrameRate) override {}
    bool IsPreviewAvailable() override { return true; }
    std::vector<u16> ReceiveFrame() override {
        std::shared_ptr<const CameraImage> image;
        {
            std::scoped_lock lock{CameraMutex()};
            image = CameraSource();
        }
        std::vector<u16> frame(size_t{width} * height, rgb565 ? 0 : 0x8000);
        if (!image || !width || !height)
            return frame;
        const bool horizontal = Mirrored(Service::CAM::Flip::Horizontal);
        const bool vertical = Mirrored(Service::CAM::Flip::Vertical);
        auto sample = [&](u32 x, u32 y) {
            const u32 sx = (horizontal ? width - 1 - x : x) * image->width / width;
            const u32 sy = (vertical ? height - 1 - y : y) * image->height / height;
            return image->rgb.data() + (size_t{sy} * image->width + sx) * 3;
        };
        for (u32 y = 0; y < height; ++y) {
            for (u32 x = 0; x < width; ++x) {
                const u8* p = sample(x, y);
                if (rgb565) {
                    frame[size_t{y} * width + x] =
                        static_cast<u16>(((p[0] >> 3) << 11) | ((p[1] >> 2) << 5) | (p[2] >> 3));
                    continue;
                }
                // YUYV: even pixels carry Y0/U, odd pixels Y1/V of the pair average.
                const u8* pair = sample(x & ~1u, y);
                const u8* other = sample(std::min(x | 1u, width - 1), y);
                const int r = (pair[0] + other[0]) / 2, g = (pair[1] + other[1]) / 2,
                          b = (pair[2] + other[2]) / 2;
                const int luma = ((66 * p[0] + 129 * p[1] + 25 * p[2] + 128) >> 8) + 16;
                const int chroma = (x & 1) ? ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128
                                           : ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                frame[size_t{y} * width + x] =
                    static_cast<u16>(std::clamp(luma, 0, 255) | (std::clamp(chroma, 0, 255) << 8));
            }
        }
        return frame;
    }

private:
    bool Mirrored(Service::CAM::Flip axis) const {
        const auto has = [&](Service::CAM::Flip value) {
            return value == axis || value == Service::CAM::Flip::Reverse;
        };
        return has(flip) != has(base_flip);
    }
    Service::CAM::Flip base_flip;
    Service::CAM::Flip flip = Service::CAM::Flip::NoFlip;
    u32 width = 0, height = 0;
    bool rgb565 = false;
};
class StillCameraFactory final : public Camera::CameraFactory {
public:
    std::unique_ptr<Camera::CameraInterface> Create(const std::string&,
                                                    const Service::CAM::Flip& flip) override {
        return std::make_unique<StillCamera>(flip);
    }
};
inline void RegisterCamera() {
    Camera::RegisterFactory("ctr_image", std::make_unique<StillCameraFactory>());
}
// Mounts media/camera.bmp for all cameras; reloads live camera devices.
inline nlohmann::json MountCamera(Core::System& system, const std::filesystem::path& root) {
    auto image = std::make_shared<const CameraImage>(LoadBmp(root / "media/camera.bmp"));
    const auto width = image->width, height = image->height;
    {
        std::scoped_lock lock{CameraMutex()};
        CameraSource() = std::move(image);
    }
    for (auto& name : Settings::values.camera_name)
        name = "ctr_image";
    if (system.IsPoweredOn())
        if (const auto cam = Service::CAM::GetModule(system))
            cam->ReloadCameraDevices();
    return {{"width", width}, {"height", height},
            {"yuv", "integer BT.601 studio swing, not Qt-identical"}};
}
} // namespace CtrWorker
