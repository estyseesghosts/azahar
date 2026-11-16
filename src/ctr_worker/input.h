#pragma once
#include <array>
#include <cmath>
#include <json.hpp>
#include "common/param_package.h"
#include "common/settings.h"
#include "core/frontend/input.h"

namespace CtrWorker {
struct InputState {
    u32 buttons = 0;
    float x = 0;
    float y = 0;
    bool touch = false;
    std::array<float,2> circle{}, cstick{};
    Common::Vec3<float> acceleration{}, gyroscope{};
};
class Analog final : public Input::AnalogDevice {
public:
    Analog(const InputState& state, bool cstick) : state(state), cstick(cstick) {}
    std::tuple<float,float> GetStatus() const override {
        auto value = cstick ? state.cstick : state.circle;
        const float length = std::hypot(value[0],value[1]);
        if (length>1.f) { value[0]/=length; value[1]/=length; }
        return {value[0],value[1]};
    }
private:
    const InputState& state; bool cstick;
};
class AnalogFactory final : public Input::Factory<Input::AnalogDevice> {
public:
    explicit AnalogFactory(const InputState& state) : state(state) {}
    std::unique_ptr<Input::AnalogDevice> Create(const Common::ParamPackage& p) override {
        return std::make_unique<Analog>(state,p.Get("index",0)==1);
    }
private: const InputState& state;
};
class Motion final : public Input::MotionDevice {
public:
    explicit Motion(const InputState& state):state(state) {}
    std::tuple<Common::Vec3<float>,Common::Vec3<float>> GetStatus() const override {
        return {state.acceleration,state.gyroscope};
    }
private: const InputState& state;
};
class MotionFactory final : public Input::Factory<Input::MotionDevice> {
public:
    explicit MotionFactory(const InputState& state):state(state) {}
    std::unique_ptr<Input::MotionDevice> Create(const Common::ParamPackage&) override {
        return std::make_unique<Motion>(state);
    }
private: const InputState& state;
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
inline void ApplyInput(InputState& input,const nlohmann::json& p) {
    InputState next;
    next.buttons=p.at("buttons").get<u32>();
    const auto x=p.at("x").get<u32>(),y=p.at("y").get<u32>();
    if (next.buttons >= (1u<<Settings::NativeButton::NumButtons) || x>=320 || y>=240)
        throw std::invalid_argument("invalid input state");
    next.x=x/320.f;next.y=y/240.f;next.touch=p.at("touch").get<bool>();
    next.circle=p.at("circle_pad").get<std::array<float,2>>();
    next.cstick=p.at("c_stick").get<std::array<float,2>>();
    const auto accel=p.at("acceleration").get<std::array<float,3>>();
    const auto gyro=p.at("gyroscope").get<std::array<float,3>>();
    auto valid=[](float v,float limit){return std::isfinite(v)&&std::abs(v)<=limit;};
    for(auto v:next.circle)if(!valid(v,1))throw std::invalid_argument("circle pad range");
    for(auto v:next.cstick)if(!valid(v,1))throw std::invalid_argument("C stick range");
    for(auto v:accel)if(!valid(v,16))throw std::invalid_argument("acceleration range");
    for(auto v:gyro)if(!valid(v,4000))throw std::invalid_argument("gyroscope range");
    next.acceleration={accel[0],accel[1],accel[2]};next.gyroscope={gyro[0],gyro[1],gyro[2]};
    const auto slider=p.at("slider_3d").get<float>(),volume=p.at("volume").get<float>();
    if(!valid(slider,1)||slider<0||!valid(volume,1)||volume<0)throw std::invalid_argument("slider range");
    input=next;
    Settings::values.factor_3d=static_cast<u32>(slider*100.f);
    Settings::values.volume=volume;
}
inline nlohmann::json SnapshotInput(const InputState& state) {
    return {{"buttons",state.buttons},{"x",static_cast<u32>(std::lround(state.x*320.f))},
        {"y",static_cast<u32>(std::lround(state.y*240.f))},{"touch",state.touch},
        {"circle_pad",state.circle},{"c_stick",state.cstick},
        {"acceleration",{state.acceleration.x,state.acceleration.y,state.acceleration.z}},
        {"gyroscope",{state.gyroscope.x,state.gyroscope.y,state.gyroscope.z}},
        {"slider_3d",Settings::values.factor_3d.GetValue()/100.f},
        {"volume",Settings::values.volume.GetValue()}};
}
inline void RegisterInput(InputState& state) {
    Input::RegisterFactory<Input::ButtonDevice>("ctr", std::make_shared<ButtonFactory>(state));
    Input::RegisterFactory<Input::TouchDevice>("ctr", std::make_shared<TouchFactory>(state));
    Input::RegisterFactory<Input::AnalogDevice>("ctr", std::make_shared<AnalogFactory>(state));
    Input::RegisterFactory<Input::MotionDevice>("ctr", std::make_shared<MotionFactory>(state));
    auto& profile = Settings::values.current_input_profile;
    for (unsigned i = 0; i < profile.buttons.size(); ++i)
        profile.buttons[i] = "engine:ctr,index:" + std::to_string(i);
    profile.touch_device = "engine:ctr";
    profile.analogs[Settings::NativeAnalog::CirclePad] = "engine:ctr,index:0";
    profile.analogs[Settings::NativeAnalog::CStick] = "engine:ctr,index:1";
    profile.motion_device = "engine:ctr";
}
} // namespace CtrWorker
