#pragma once
#include "common/param_package.h"
#include "common/settings.h"
#include "core/frontend/input.h"

namespace CtrWorker {
struct InputState {
    u32 buttons = 0;
    float x = 0;
    float y = 0;
    bool touch = false;
};
class Button final : public Input::ButtonDevice {
public:
    Button(const InputState& state, unsigned index) : state(state), index(index) {}
    bool GetStatus() const override {
        return (state.buttons & (1u << index)) != 0;
    }

private:
    const InputState& state;
    unsigned index;
};
class ButtonFactory final : public Input::Factory<Input::ButtonDevice> {
public:
    explicit ButtonFactory(const InputState& state) : state(state) {}
    std::unique_ptr<Input::ButtonDevice> Create(const Common::ParamPackage& params) override {
        const auto index = params.Get("index", 0);
        if (index < 0 || index >= Settings::NativeButton::NumButtons)
            return std::make_unique<Input::ButtonDevice>();
        return std::make_unique<Button>(state, index);
    }

private:
    const InputState& state;
};
class Touch final : public Input::TouchDevice {
public:
    explicit Touch(const InputState& state) : state(state) {}
    std::tuple<float, float, bool> GetStatus() const override {
        return {state.x, state.y, state.touch};
    }

private:
    const InputState& state;
};
class TouchFactory final : public Input::Factory<Input::TouchDevice> {
public:
    explicit TouchFactory(const InputState& state) : state(state) {}
    std::unique_ptr<Input::TouchDevice> Create(const Common::ParamPackage&) override {
        return std::make_unique<Touch>(state);
    }

private:
    const InputState& state;
};
inline void RegisterInput(InputState& state) {
    Input::RegisterFactory<Input::ButtonDevice>("ctr", std::make_shared<ButtonFactory>(state));
    Input::RegisterFactory<Input::TouchDevice>("ctr", std::make_shared<TouchFactory>(state));
    auto& profile = Settings::values.current_input_profile;
    for (unsigned i = 0; i < profile.buttons.size(); ++i)
        profile.buttons[i] = "engine:ctr,index:" + std::to_string(i);
    profile.touch_device = "engine:ctr";
}
} // namespace CtrWorker
