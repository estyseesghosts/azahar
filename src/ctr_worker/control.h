#pragma once
#include <cstdio>
#include <deque>
#include <mutex>
#include <optional>
#include "audio_core/worker_sink.h"
#include "core/arm/arm_interface.h"
#include "core/frontend/control_callback.h"
#include "core/hle/kernel/kernel.h"
#include "core/system_titles.h"
#include "ctr_worker/frames.h"
#include "ctr_worker/camera.h"
#include "ctr_worker/debug.h"
#include "ctr_worker/frontend.h"
#include "ctr_worker/input.h"
#include "ctr_worker/transport.h"
#ifdef ENABLE_VULKAN
#include "video_core/renderer_vulkan/vk_gpu_status.h"
#endif

namespace CtrWorker {
using Json = nlohmann::json;
class Control {
public:
    explicit Control(std::string root) : root(std::filesystem::absolute(root)) {}
    int Run() {
        ReserveControlOutput();
        writer.Start();
        Initialize(system, root.string(), unsupported);
        RegisterInput(input);
        RegisterCamera();
        debug.Attach();
        debug.apply_input = [this](const Json& restored) {
            ApplyInput(input, restored.at("state"));
            owner = restored.at("owner").get<std::string>();
        };
        debug.get_input = [this] { return Json{{"owner", owner}, {"state", SnapshotInput(input)}}; };
        debug.get_frame = [this] { return window.frames; };
        debug.set_frame = [this](u64 frame) { window.frames = frame; };
        // Called only for subscribed categories (DebugTools::Record); stops are reliable.
        debug.notification = [this](const Json& data, bool reliable) {
            writer.Post({{"notification", true}, {"version_major", 1}, {"version_minor", 0},
                         {"session", session}, {"epoch", epoch}, {"data", data}},
                        reliable);
        };
        Settings::values.output_type = AudioCore::SinkType::Worker;
        Frontend::control_callback = [this] { Drain(true); };
#ifdef ENABLE_VULKAN
        active = this;
        main_thread = std::this_thread::get_id();
        Vulkan::SetGpuFailureHandler([](const Vulkan::GpuFailure& failure) {
            active->ExitOnGpuFailure(failure);
        });
#endif
        std::thread reader{[this] {
            stdin_reader.Enter();
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
            stdin_reader.Exit();
            system.NotifyPendingWork();
        }};
        try {
            while (!stopping && !disconnected && !writer.Failed()) {
                debug.Poll();
                Drain(false);
                if (state == "running") {
                    // Build the JSON input snapshot only when a frame checkpoint will be stored.
                    if (debug.WantsFrameCheckpoint(window.frames))
                        debug.Remember(window.frames,{{"owner",owner},{"state",SnapshotInput(input)}});
                    const auto result = system.RunLoop();
                    debug.CheckFramePredicate(window.frames);
                    if (debug.IsStopped() || result != Core::System::ResultStatus::Success || unsupported ||
                        window.frames >= target || std::chrono::steady_clock::now() >= deadline) {
                        state = "paused";
                        if (!debug.IsStopped())
                            debug.Stop(result != Core::System::ResultStatus::Success ? "exception" : "frame",
                                       {{"frame", window.frames}});
                        debug.MarkHistoryStop();
                        last_error = unsupported ? "unsupported_applet"
                                     : result != Core::System::ResultStatus::Success ? "core_error"
                                     : debug.IsStopped() && debug.StopReason().value("reason", "") != "frame" ? ""
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
                    // Returns as soon as the reader queues a request. ProcessPendingWorkUntil
                    // waited out the deadline after a request arrived, so every request that
                    // is not drained nested (run_until, input, preview, pause, debug commands)
                    // waited up to one 15.6 ms timer tick on a paused worker (lotus#22).
                    system.ProcessPendingWorkOrWait(std::chrono::steady_clock::now() +
                                                    std::chrono::milliseconds(10));
                }
            }
        } catch (const std::exception& error) {
#ifdef ENABLE_VULKAN
            if (const auto gpu = Vulkan::DescribeGpuFailure(error)) {
                ReportGpuFailure(*gpu);
                device_lost = gpu->device_lost;
                exit_code = GPU_FAILURE_EXIT;
            } else
#endif
            {
                std::cerr << "worker_control_error: " << error.what() << '\n';
                exit_code = 1;
            }
        }
        if (writer.Failed())
            exit_code = 1;
        stopping = true;
        stdin_reader.Interrupt();
        reader.join();
        Frontend::control_callback = {};
        debug.Detach();
        // After an allocation failure the renderer is shut down normally, which releases its
        // VMA allocations. After device loss Vulkan teardown can itself fail; the process exits
        // without it and the driver reclaims the device's memory (lotus#46).
        if (device_lost) {
            writer.Close();
            Common::Log::Stop();
            std::fflush(nullptr);
            std::_Exit(exit_code);
        }
        try {
            if (system.IsPoweredOn())
                system.Shutdown();
        } catch (const std::exception& error) {
            std::cerr << "worker_shutdown_error: " << error.what() << '\n';
            writer.Close();
            Common::Log::Stop();
            std::fflush(nullptr);
            std::_Exit(exit_code ? exit_code : 1);
        }
        AudioCore::WorkerSink::CaptureStop();
        writer.Close();
        Common::Log::Stop();
        return exit_code;
    }

private:
    Json Snapshot() {
        const auto audio = AudioCore::WorkerSink::Drain();
        return {{"debug_api", true}, {"backend_name", CTR_BACKEND_NAME}, {"source", CTR_SOURCE_SHA}, {"frames", window.frames},
                {"stop", debug.StopReason()}, {"events", debug.EventStatus()}, {"last_error", last_error},         {"input_owner", owner},
                {"buttons", input.buttons},         {"touch_down", input.touch},
                {"audio_samples", audio.samples},   {"audio_dropped", audio.dropped},
                {"audio_focused", AudioCore::WorkerSink::focused},
                {"audio_hash_fnv1a64", audio.hash}, {"audio_buffered", audio.buffered},
                {"preview", PreviewRing::Supported() ? "shared_memory_v1" : "capture"},
                {"transport", writer.Stats()}, {"gpu_memory", GpuMemory()},
                {"features", Features()}};
    }
    /// Optional control features this build implements (lotus#42). The host refuses a request
    /// that needs a feature missing here instead of sending it to a worker that would ignore
    /// it. Names are lotus_protocol::capabilities::feature constants.
    static Json Features() {
        Json features = Json::array({"flush_storage", "event_subscriptions", "gpu_capture_levels", "state_hash", "deterministic_async", "analog_input"});
        if (PreviewRing::Supported())
            features.push_back("preview_nonblocking");
#ifdef ENABLE_VULKAN
        features.push_back("gpu_memory");
#endif
        return features;
    }
    /// VMA heap budgets and this process's device-memory blocks (lotus#46); null without a
    /// Vulkan renderer.
    static Json GpuMemory() {
#ifdef ENABLE_VULKAN
        const auto stats = Vulkan::QueryGpuMemory();
        if (!stats.available)
            return nullptr;
        Json heaps = Json::array();
        for (const auto& heap : stats.heaps)
            heaps.push_back({{"device_local", heap.device_local},
                             {"size", heap.size},
                             {"budget", heap.budget},
                             {"usage", heap.usage},
                             {"block_bytes", heap.block_bytes},
                             {"block_bytes_high_water", heap.block_bytes_high_water},
                             {"allocation_bytes", heap.allocation_bytes}});
        return {{"budget_source", stats.budget_extension ? "VK_EXT_memory_budget"
                                                         : "vma_estimate"},
                {"allocation_failures", stats.allocation_failures},
                {"heaps", std::move(heaps)}};
#else
        return nullptr;
#endif
    }
#ifdef ENABLE_VULKAN
    /// One stderr line the host classifies (lotus failure.rs), plus the frame and budgets.
    /// The frame counter is the emulation thread's; it is left out on renderer threads.
    void ReportGpuFailure(const Vulkan::GpuFailure& error) {
        Vulkan::AcknowledgeFault();
        Json report{{"cause", error.cause},
                    {"vk_result", error.vk_result},
                    {"vk_result_name", error.vk_result_name},
                    {"object", error.object},
                    {"gpu_memory", GpuMemory()}};
        if (std::this_thread::get_id() == main_thread)
            report["frame"] = window.frames;
        std::cerr << "worker_gpu_error: " << report.dump() << std::endl;
        LOG_CRITICAL(Render_Vulkan, "worker_gpu_error: {}", report.dump());
    }
    /// The failure handler (lotus#46): report, flush the log, end this session's process. The
    /// failure may be inside JIT code or on a renderer thread, where nothing can be unwound or
    /// shut down safely; process exit releases the device memory. The host sees the pipe close,
    /// reads the report from the stderr and log tails, and keeps every other session running.
    void ExitOnGpuFailure(const Vulkan::GpuFailure& error) {
        static std::atomic_bool exiting = false;
        if (exiting.exchange(true)) {
            for (;;)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        ReportGpuFailure(error);
        Common::Log::Stop();
        std::fflush(nullptr);
        std::_Exit(GPU_FAILURE_EXIT);
    }
    static inline Control* active = nullptr;
    static inline std::thread::id main_thread;
#endif
    void Reply(const Json& request, const std::string& status, Json data = nullptr) {
        writer.Post({{"version_major", 1},
              {"version_minor", 0},
              {"request_id", request.at("request_id")},
              {"session", request.at("session")},
              {"epoch", epoch},
              {"status", status},
              {"state", state},
              {"backend", "azahar_native_software"},
              {"data", std::move(data)}},
             true);
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
        auto method = request["method"].get<std::string>();
        if (method == "hello" && session.empty())
            session = id;
        if (session.empty()) {
            Reply(request, "not_ready");
            return;
        }
        try {
            auto params = request.value("params", Json::object());
            if(method=="debug" && params.value("operation","")=="boot_home_menu") {
                const auto region=params.at("region").get<u32>();
                if(region>=Core::NUM_SYSTEM_TITLE_REGIONS)throw std::invalid_argument("invalid HOME Menu region");
                const auto path=Core::GetHomeMenuNcchPath(region);
                if(!std::filesystem::is_regular_file(path)){
                    Reply(request,"not_ready",{{"error","home_menu_missing"},{"region",region}});return;
                }
                method="load";params={{"path",path}};
            }
            if (method == "hello") debug.ConfigureEvents(params, true);
            if (method == "hello" || method == "status") {
                Reply(request, "ok", Snapshot());
                return;
            }
            if (method == "debug") {
                if (params.value("operation", "") == "input_state") {
                    if((system.Movie().GetPlayMode()==Core::Movie::PlayMode::Playing || system.Movie().GetPlayMode()==Core::Movie::PlayMode::MovieFinished))throw std::invalid_argument("movie playback owns input");
                    if (!system.IsPoweredOn()) throw std::invalid_argument("input requires loaded content");
                    const auto requested = params.at("owner").get<std::string>();
                    if ((requested!="live" && requested!="scenario") || (owner=="scenario" && requested!=owner)) {
                        Reply(request,"permission_denied");return;
                    }
                    ApplyInput(input,params.at("state"));owner=requested;system.ApplySettings();
                    debug.ForceCheckpoint();
                    Reply(request,"ok",{{"input",params.at("state")},{"owner",owner},{"safe_point",true},
                        {"paused",state!="running"},{"rasterizer_cache_flush",false}});return;
                }
                auto debug_params = params;
                debug_params["worker_frame"] = window.frames;
                debug_params["worker_input"] = {{"owner",owner},{"state",SnapshotInput(input)}};
                auto result = debug.Dispatch(debug_params, state);
                if (params.value("operation", "") == "load_state" || params.value("operation", "") == "citrace_replay" ||
                    params.value("operation", "") == "reverse_step" || params.value("operation", "") == "reverse_continue") {
                    ++epoch;
                    capture_sequence = 0;
                    window.frames = result.at("worker_frame").get<u64>();
                    const auto restored=result.at("worker_input");
                    ApplyInput(input,restored.at("state"));owner=restored.at("owner").get<std::string>();
                    if(params.value("operation", "") == "load_state") debug.Stop("manual", {{"state_loaded", true}});
                }
                if (result.value("resume_requested", false)) {
                    result["paused"]=false;
                    debug.Resume();
                    target = window.frames + result.value("budget_frames",600u);
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(result.value("timeout_ms",20000u));
                    state = "running";
                }
                Reply(request, "ok", std::move(result));
                return;
            }
            if (method == "stop") {
                system.Movie().Shutdown();
                debug.Clear();
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
                const auto extension=std::filesystem::path(path).extension().string();
                const std::set<std::string> supported={".3dsx",".elf",".3ds",".cci",".cxi",".app",".z3dsx",".zcci",".zcxi"};
                if (path.empty() || !std::filesystem::is_regular_file(path) || !supported.contains(extension)) {
                    Reply(request, "invalid_argument");
                    return;
                }
                debug.SetContentIdentity(path);
                debug.Clear();
                if (system.IsPoweredOn())
                    system.Shutdown();
                unsupported = false;
                input = {};
                window.frames = 0;
                last_error.clear();
                owner = "live";
                AudioCore::WorkerSink::Reset();
                debug.MovieBeforeLoad();
                const auto result = system.Load(window, path);
                if (result != Core::System::ResultStatus::Success) {
                    if (system.IsPoweredOn())
                        system.Shutdown();
                    state = "idle";
                    Reply(request, "not_ready", {{"load_result", static_cast<u32>(result)}});
                    return;
                }
                content = path;
                debug.MovieAfterLoad();
                state = "paused";
                ++epoch;
                Reply(request, "ok", Snapshot());
                return;
            }
            if (method == "flush_storage") {
                // Make guest storage on disk match what the guest has written, so the host can
                // copy a card at one guest timeline point. FS service calls may run on host
                // threads (HLERequestContext::RunAsync, kernel/hle_ipc.h) while the guest waits;
                // they count as pending until the guest thread wakes, so a pending operation is
                // refused rather than raced. Guest files are FileUtil::IOFile over std::FILE
                // (common/file_util.h, CORE_FILE). FSFILE_Write reaches the OS at once, because
                // Service::FS::File::Write calls GetSize, which seeks (common/file_util.cpp,
                // GetSize(FILE*)); other IOFile writers have no such seek, hence the flush.
                if (state == "running") {
                    Reply(request, "not_ready", {{"reason", "running"}});
                    return;
                }
                if (system.IsPoweredOn() && system.Kernel().AreAsyncOperationsPending()) {
                    Reply(request, "not_ready", {{"reason", "async_fs_pending"}});
                    return;
                }
                // C11 7.21.5.2: a null stream flushes every output stream of the process.
                const bool flushed = std::fflush(nullptr) == 0;
                Reply(request, flushed ? "ok" : "unsupported", {{"flushed", flushed}});
                return;
            }
            if (!system.IsPoweredOn()) {
                Reply(request, "not_ready");
                return;
            }
            if (method == "run" || method == "run_until") {
                if(debug.IsGpuReplayView())throw std::invalid_argument("GPU replay view: load a checkpoint or reset before CPU execution");
                if (state != "paused" || pending_run) {
                    Reply(request, "not_ready");
                    return;
                }
                const auto frames = Unsigned(params, "frames", 600);
                if (frames == 0 || frames > 600) {
                    Reply(request, "invalid_argument");
                    return;
                }
                debug.Resume();
                target = window.frames + frames;
                deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
                state = "running";
                if (method == "run_until")
                    pending_run = request;
                else
                    Reply(request, "ok", Snapshot());
            } else if (method == "pause") {
                debug.Stop("manual", Json::object());
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
            } else if (method == "preview") {
                if (!PreviewRing::Supported()) {
                    Reply(request, "unsupported");
                    return;
                }
                if (!window.frames) {
                    Reply(request, "not_ready");
                    return;
                }
                Reply(request, "ok", preview.Write(system, epoch, window.frames, state == "running"));
            } else if (method == "input") {
                if((system.Movie().GetPlayMode()==Core::Movie::PlayMode::Playing || system.Movie().GetPlayMode()==Core::Movie::PlayMode::MovieFinished))throw std::invalid_argument("movie playback owns input");
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
                const auto circle = Stick(params, "circle_pad", input.circle),
                           cstick = Stick(params, "c_stick", input.cstick);
                if (buttons >= (1u << Settings::NativeButton::NumButtons) || x >= 320 || y >= 240 ||
                    !circle || !cstick) {
                    Reply(request, "invalid_argument");
                    return;
                }
                owner = requested_owner;
                // Only the sent fields change (lotus#60): a button/touch update no longer zeroes
                // the sticks, and motion/slider state set by input_state is kept.
                input.buttons = buttons;
                input.x = x / 320.0f;
                input.y = y / 240.0f;
                input.touch = params.value("touch", false);
                input.circle = *circle;
                input.cstick = *cstick;
                debug.ForceCheckpoint();
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
#ifdef ENABLE_VULKAN
            if (Vulkan::DescribeGpuFailure(error))
                throw;
#endif
            Reply(request, "unsupported", {{"reason", error.what()}});
        }
    }
    /// Optional analog stick `[x, y]`, each finite in -1..1 (the range input_state accepts,
    /// ctr_worker/input.h ApplyInput); absent keeps `current`, malformed is nullopt.
    static std::optional<std::array<float, 2>> Stick(const Json& params, const char* key,
                                                     std::array<float, 2> current) {
        if (!params.contains(key))
            return current;
        const auto& value = params.at(key);
        if (!value.is_array() || value.size() != 2 || !value[0].is_number() || !value[1].is_number())
            return std::nullopt;
        const std::array<float, 2> stick{value[0].get<float>(), value[1].get<float>()};
        for (const float axis : stick)
            if (!std::isfinite(axis) || std::abs(axis) > 1.0f)
                return std::nullopt;
        return stick;
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
    PreviewRing preview;
    bool unsupported = false, device_lost = false;
    int exit_code = 0;
    /// Exit code after a typed GPU failure, distinct from 1 (protocol or control error).
    static constexpr int GPU_FAILURE_EXIT = 4;
    std::chrono::steady_clock::time_point deadline;
    std::optional<Json> pending_run;
    std::mutex mutex;
    std::deque<Json> queue;
    std::atomic_bool stopping = false, disconnected = false;
    StdinReader stdin_reader;
    ControlWriter writer;
};
} // namespace CtrWorker
