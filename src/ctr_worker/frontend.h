// Minimal native software frontend. All methods run on the emulation thread.
#pragma once
#include <filesystem>
#include "audio_core/sink_details.h"
#include "common/file_util.h"
#include "common/logging/backend.h"
#include "common/settings.h"
#include "core/core.h"
#include "core/frontend/applets/mii_selector.h"
#include "core/frontend/applets/swkbd.h"
#include "core/frontend/emu_window.h"
#include "core/frontend/image_interface.h"
#include "core/hle/service/service.h"

namespace CtrWorker {
class Window final : public Frontend::EmuWindow {
public:
    Window() { UpdateCurrentFramebufferLayout(400, 480); }
    void PollEvents() override { ++frames; }
    u64 frames = 0;
};

class Keyboard final : public Frontend::SoftwareKeyboard {
public:
    explicit Keyboard(bool& unsupported) : unsupported(unsupported) {}
    void Execute(const Frontend::KeyboardConfig& config) override {
        SoftwareKeyboard::Execute(config);
        unsupported = true;
        Finalize("", 0);
    }
    void ShowError(const std::string&) override { unsupported = true; }
private:
    bool& unsupported;
};

class MiiSelector final : public Frontend::MiiSelector {
public:
    explicit MiiSelector(bool& unsupported) : unsupported(unsupported) {}
    void Setup(const Frontend::MiiSelectorConfig& config) override {
        Frontend::MiiSelector::Setup(config);
        unsupported = true;
        Finalize(1, {});
    }
private:
    bool& unsupported;
};

inline void Initialize(Core::System& system, const std::string& root, bool& unsupported) {
    std::filesystem::create_directories(root);
    FileUtil::SetUserPath(root + "/");
    Common::Log::Initialize();
    Common::Log::Start();
    Settings::values.graphics_api = Settings::GraphicsAPI::Software;
    Settings::values.is_new_3ds = false;
    Settings::values.output_type = AudioCore::SinkType::Null;
    Settings::values.use_gdbstub = false;
    Settings::values.init_ticks_type = Settings::InitTicks::Fixed;
    Settings::values.init_ticks_override = 0;
    Settings::values.init_clock = Settings::InitClock::FixedTime;
    Settings::values.init_time = 946684800;
    for (const auto& module : Service::service_module_map)
        Settings::values.lle_modules.emplace(module.name, false);
    system.RegisterSoftwareKeyboard(std::make_shared<Keyboard>(unsupported));
    system.RegisterMiiSelector(std::make_shared<MiiSelector>(unsupported));
    system.RegisterImageInterface(std::make_shared<Frontend::ImageInterface>());
}
} // namespace CtrWorker
