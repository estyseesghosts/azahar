#pragma once
#include <deque>
#include <mutex>
#include <optional>
#include "audio_core/worker_sink.h"
#include "core/arm/arm_interface.h"
#include "core/frontend/control_callback.h"
#include "core/hle/kernel/kernel.h"
#include "ctr_worker/frames.h"
#include "ctr_worker/camera.h"
#include "ctr_worker/debug.h"
#include "ctr_worker/frontend.h"
#include "ctr_worker/input.h"
#include "ctr_worker/transport.h"

namespace CtrWorker {
using Json = nlohmann::json;
class Control {
public:
    explicit Control(std::string root) : root(std::filesystem::absolute(root)) {}
    int Run() {
        ReserveControlOutput();
        Initialize(system, root.string(), unsupported);
        RegisterInput(input);
        RegisterCamera();
        Settings::values.output_type = AudioCore::SinkType::Worker;
        Frontend::control_callback = [this] { Drain(true); };
        std::thread reader{[this] {
            while (!stopping) {
                Json request;
                if (!Receive(request, stopping))
                    break;
                {
                    std::scoped_lock lock{mutex};
                    if (queue.size() >= 16)
                        break;
                    queue.push_back(std::move(request));
                }
                system.NotifyPendingWork();
            }
            disconnected = true;
            system.NotifyPendingWork();
        }};
        try {
            while (!stopping && !disconnected) {
                Drain(false);
                if (state == "running") {
                    const auto result = system.RunLoop();
                    if (result != Core::System::ResultStatus::Success || unsupported ||
                        window.frames >= target || std::chrono::steady_clock::now() >= deadline) {
                        state = "paused";
                        last_error = unsupported ? "unsupported_applet"
                                     : result != Core::System::ResultStatus::Success ? "core_error"
                                     : window.frames < target ? "host_deadline"
                                                              : "";
                        if (pending_run) {
                            Reply(*pending_run,
                                  last_error.empty() ? "ok"
                                  : unsupported      ? "unsupported"
                                                     : "not_ready",
                                  Snapshot());
                            pending_run.reset();
                        }
                    }
                } else {
                    system.ProcessPendingWorkUntil(std::chrono::steady_clock::now() +
                                                   std::chrono::milliseconds(10));
                }
            }
        } catch (const std::exception& error) {
            std::cerr << "worker_control_error: " << error.what() << '\n';
            exit_code = 1;
        }
        stopping = true;
        reader.join();
        Frontend::control_callback = {};
        if (system.IsPoweredOn())
            system.Shutdown();
        AudioCore::WorkerSink::CaptureStop();
        Common::Log::Stop();
        return exit_code;
    }

private:
    Json Snapshot() {
        const auto audio = AudioCore::WorkerSink::Drain();
        return {{"debug_api", true}, {"backend_name", CTR_BACKEND_NAME}, {"source", CTR_SOURCE_SHA}, {"frames", window.frames},
                {"last_error", last_error},         {"input_owner", owner},
                {"buttons", input.buttons},         {"touch_down", input.touch},
                {"audio_samples", audio.samples},   {"audio_dropped", audio.dropped},
                {"audio_focused", AudioCore::WorkerSink::focused},
                {"audio_hash_fnv1a64", audio.hash}, {"audio_buffered", audio.buffered}};
    }
    void Reply(const Json& request, const std::string& status, Json data = nullptr) {
        Send({{"version_major", 1},
              {"version_minor", 0},
              {"request_id", request.at("request_id")},
              {"session", request.at("session")},
              {"epoch", epoch},
              {"status", status},
              {"state", state},
              {"backend", "azahar_native_software"},
              {"data", std::move(data)}});
    }
    void Drain(bool nested) {
        // Never destroy/reinitialize a core while inside its RunLoop/frame limiter.
        for (unsigned count = 0; count < 16; ++count) {
            Json request;
            {
                std::scoped_lock lock{mutex};
                if (queue.empty())
                    return;
                const auto method = queue.front().value("method", std::string{});
                if (nested && method != "status" && method != "registers" &&
                    method != "read_memory")
                    return;
                request = std::move(queue.front());
                queue.pop_front();
            }
            Handle(request);
            if (stopping)
                return;
        }
    }
    void Handle(const Json& request) {
        // Invalid envelopes end the connection: there may be no trustworthy reply identity.
        if (!request.is_object() || !request.contains("request_id") ||
            !request["request_id"].is_number_unsigned() || request["request_id"].get<u64>() == 0 ||
            !request.contains("session") || !request["session"].is_string() ||
            !request.contains("epoch") || !request["epoch"].is_number_unsigned() ||
            !request.contains("method") || !request["method"].is_string() ||
            !request.contains("version_major") || !request.contains("version_minor"))
            throw std::runtime_error("invalid request envelope");
        for (const auto& [key, value] : request.items())
            if (key != "version_major" && key != "version_minor" && key != "request_id" &&
                key != "session" && key != "epoch" && key != "method" && key != "params")
                throw std::runtime_error("unknown envelope field");
        const auto id = request["session"].get<std::string>();
        if (id.size() != 32 || id.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
            throw std::runtime_error("invalid session");
        if (request["request_id"].get<u64>() <= last_request)
            throw std::runtime_error("request IDs must increase; retries are forbidden");
        last_request = request["request_id"].get<u64>();
        if (request["version_major"] != 1 || request["version_minor"] != 0) {
            Reply(request, "unsupported");
            return;
        }
        if (!session.empty() && session != id) {
            Reply(request, "permission_denied");
            return;
        }
        if (request["epoch"] != epoch) {
            Reply(request, "stale_epoch");
            return;
        }
        const auto method = request["method"].get<std::string>();
        if (method == "hello" && session.empty())
            session = id;
        if (session.empty()) {
            Reply(request, "not_ready");
            return;
        }
        try {
            const auto params = request.value("params", Json::object());
            if (method == "hello" || method == "status") {
                Reply(request, "ok", Snapshot());
                return;
            }
            if (method == "debug") {
                if (params.value("operation", "") == "input_state") {
                    if (!system.IsPoweredOn()) throw std::invalid_argument("input requires loaded content");
                    const auto requested = params.at("owner").get<std::string>();
                    if ((requested!="live" && requested!="scenario") || (owner=="scenario" && requested!=owner)) {
                        Reply(request,"permission_denied");return;
                    }
                    ApplyInput(input,params.at("state"));owner=requested;system.ApplySettings();
                    Reply(request,"ok",{{"input",params.at("state")},{"owner",owner},{"safe_point",true},
                        {"paused",state!="running"},{"rasterizer_cache_flush",false}});return;
                }
                Reply(request, "ok", debug.Dispatch(params, state));
                return;
            }
            if (method == "stop") {
                state = "stopped";
                if (system.IsPoweredOn())
                    system.Shutdown();
                Reply(request, "ok");
                stopping = true;
                return;
            }
            if (method == "load" || method == "reset") {
                if (state == "running") {
                    Reply(request, "not_ready");
                    return;
                }
                const auto path = method == "load" ? params.at("path").get<std::string>() : content;
                if(Settings::values.input_type.GetValue()==AudioCore::InputType::Injected) {
                    const auto mic_path=root/"media/mic.wav";
                    if(!std::filesystem::is_regular_file(mic_path)) {
                        Reply(request,"not_ready",{{"error","missing_mic_asset"},{"required_asset","mic_wav"}});return;
                    }
                    AudioCore::InjectedInput::Load(mic_path);
                }
                if(Settings::values.audio_emulation.GetValue()!=Settings::AudioEmulation::HLE &&
                    !std::filesystem::is_regular_file(root/"sdmc/3ds/dspfirm.cdc")) {
                    Reply(request,"not_ready",{{"error","missing_dsp_firmware"},
                        {"required_asset","dsp_firmware"},{"session_path","sdmc/3ds/dspfirm.cdc"}});return;
                }
                if (path.empty() || !std::filesystem::is_regular_file(path) ||
                    std::filesystem::path(path).extension() != ".3dsx") {
                    Reply(request, "invalid_argument");
                    return;
                }
                if (system.IsPoweredOn())
                    system.Shutdown();
                unsupported = false;
                input = {};
                window.frames = 0;
                last_error.clear();
                owner = "live";
                AudioCore::WorkerSink::Reset();
                const auto result = system.Load(window, path);
                if (result != Core::System::ResultStatus::Success) {
                    if (system.IsPoweredOn())
                        system.Shutdown();
                    state = "idle";
                    Reply(request, "not_ready", {{"load_result", static_cast<u32>(result)}});
                    return;
                }
                content = path;
                state = "paused";
                ++epoch;
                Reply(request, "ok", Snapshot());
                return;
            }
            if (!system.IsPoweredOn()) {
                Reply(request, "not_ready");
                return;
            }
            if (method == "run" || method == "run_until") {
                if (state != "paused" || pending_run) {
                    Reply(request, "not_ready");
                    return;
                }
                const auto frames = Unsigned(params, "frames", 600);
                if (frames == 0 || frames > 600) {
                    Reply(request, "invalid_argument");
                    return;
                }
                target = window.frames + frames;
                deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
                state = "running";
                if (method == "run_until")
                    pending_run = request;
                else
                    Reply(request, "ok", Snapshot());
            } else if (method == "pause") {
                state = "paused";
                if (pending_run) {
                    Reply(*pending_run, "not_ready", {{"reason", "interrupted"}});
                    pending_run.reset();
                }
                Reply(request, "ok", Snapshot());
            } else if (method == "capture") {
                if (!window.frames) {
                    Reply(request, "not_ready");
                    return;
                }
                Reply(request, "ok",
                      {{"frames", Capture(system, root, epoch, ++capture_sequence, params.is_object()?params.value("scale",1u):1u)},
                       {"frame", window.frames}});
            } else if (method == "input") {
                const auto requested_owner = params.at("owner").get<std::string>();
                if (requested_owner != "live" && requested_owner != "scenario") {
                    Reply(request, "invalid_argument");
                    return;
                }
                if (owner == "scenario" && requested_owner != owner) {
                    Reply(request, "permission_denied");
                    return;
                }
                const auto buttons = static_cast<u32>(
                    Unsigned(params, "buttons", (1u << Settings::NativeButton::NumButtons) - 1));
                const auto x = Unsigned(params, "x", 319), y = Unsigned(params, "y", 239);
                if (buttons >= (1u << Settings::NativeButton::NumButtons) || x >= 320 || y >= 240) {
                    Reply(request, "invalid_argument");
                    return;
                }
                owner = requested_owner;
                input = {buttons, x / 320.0f, y / 240.0f, params.value("touch", false)};
                Reply(request, "ok", Snapshot());
            } else if (method == "registers") {
                const auto core = static_cast<u32>(Unsigned(params, "core", 3));
                if (core >= system.GetNumCores()) {
                    Reply(request, "invalid_argument");
                    return;
                }
                Json registers = Json::array();
                for (unsigned i = 0; i < 16; ++i)
                    registers.push_back(system.GetCore(core).GetReg(i));
                Reply(request, "ok",
                      {{"core", core},
                       {"registers", registers},
                       {"cpsr", system.GetCore(core).GetCPSR()},
                       {"safe_point", true}});
            } else if (method == "read_memory") {
                const auto address = Unsigned(params, "address", 0xffffffffull),
                           length = Unsigned(params, "length", 4096);
                const auto process = system.Kernel().GetCurrentProcess();
                if (!process || length == 0 || length > 4096 || address + length > 0x100000000ull ||
                    address > 0xffffffffull) {
                    Reply(request, "invalid_argument");
                    return;
                }
                for (u64 i = 0; i < length; ++i)
                    if (!system.Memory().IsValidVirtualAddress(*process,
                                                               static_cast<u32>(address + i))) {
                        Reply(request, "invalid_argument");
                        return;
                    }
                std::vector<u8> bytes(length);
                system.Memory().ReadBlock(*process, static_cast<u32>(address), bytes.data(),
                                          length);
                Reply(request, "ok",
                      {{"address", address}, {"bytes", bytes}, {"safe_point", true}});
            } else
                Reply(request, "unsupported");
        } catch (const std::out_of_range&) {
            Reply(request, "invalid_argument");
        } catch (const std::invalid_argument& error) {
            Reply(request, "invalid_argument", {{"reason",error.what()}});
        } catch (const Json::exception&) {
            Reply(request, "invalid_argument");
        } catch (const std::filesystem::filesystem_error&) {
            Reply(request, "invalid_argument");
        } catch (const std::runtime_error& error) {
            Reply(request, "unsupported", {{"reason", error.what()}});
        }
    }
    static u64 Unsigned(const Json& params, const char* key, u64 maximum) {
        if (!params.contains(key) || !params.at(key).is_number_unsigned() ||
            params.at(key).get<u64>() > maximum)
            throw std::invalid_argument("expected bounded unsigned integer");
        return params.at(key).get<u64>();
    }
    Core::System& system = Core::System::GetInstance();
    std::filesystem::path root;
    Window window;
    DebugTools debug{system, root};
    InputState input;
    std::string session, content, last_error, state = "idle", owner = "live";
    u64 epoch = 1, target = 0, capture_sequence = 0, last_request = 0;
    bool unsupported = false;
    int exit_code = 0;
    std::chrono::steady_clock::time_point deadline;
    std::optional<Json> pending_run;
    std::mutex mutex;
    std::deque<Json> queue;
    std::atomic_bool stopping = false, disconnected = false;
};
} // namespace CtrWorker
