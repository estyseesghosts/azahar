// Worker-side settings and safe-point inspection. No product/UI dependencies.
#pragma once
#include <algorithm>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <boost/regex.hpp>
#include <cryptopp/sha.h>
#include "common/hash.h"
#include "common/logging/backend.h"
#include "common/logging/log_entry.h"
#include "ctr_worker/settings_bindings.h"
#include "audio_core/worker_sink.h"
#include "audio_core/injected_input.h"
#include "audio_core/hle/shared_memory.h"
#include "audio_core/dsp_interface.h"
#include "core/hle/service/mic/mic_u.h"
#include "core/hle/service/nfc/nfc.h"
#include "ctr_worker/camera.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/hle/kernel/thread.h"
#include "core/hle/kernel/mutex.h"
#include "core/perf_stats.h"
#include "core/movie.h"
#include "core/hle/service/am/am.h"
#include "core/hle/service/ptm/ptm.h"
#include "core/cheats/cheats.h"
#include "core/cheats/gateway_cheat.h"
#include "common/zstd_compression.h"
#include "common/file_derived.h"
#include "core/loader/loader.h"
#include "core/hle/kernel/ipc_debugger/recorder.h"
#include "core/hle/service/cfg/cfg.h"
#include "core/hle/service/cfg/cfg_defaults.h"
#include "core/frontend/debug_channel.h"
#include "ctr_worker/debug_gpu.h"
#include "ctr_worker/debug_citrace.h"

namespace CtrWorker {
inline void DefaultProfile() {
    Settings::values.graphics_api = Settings::GraphicsAPI::Software;
    Settings::values.is_new_3ds = false;
    // Wave 2's Auto selected Static when host input backends were disabled.
    Settings::values.input_type = AudioCore::InputType::Static;
    Settings::values.output_type = AudioCore::SinkType::Worker;
    Settings::values.use_gdbstub = false;
    Settings::values.init_ticks_type = Settings::InitTicks::Fixed;
    Settings::values.init_ticks_override = 0;
    Settings::values.init_clock = Settings::InitClock::FixedTime;
    Settings::values.init_time = 946684800;
}
class DebugTools {
public:
    using Json = nlohmann::json;
    explicit DebugTools(Core::System& system, const std::filesystem::path& root)
        : system(system), root(root), bindings(SettingsBindings()) {}

#ifdef CTR_EXPERIMENTAL
    void Attach() {
        system.Movie().SetRecordingBudget(32u<<20);
        Common::Log::SetObserver([this](const Common::Log::Entry& entry) {
            QueueEvent("native_log", {{"host_microseconds",entry.timestamp.count()},
                {"severity",Common::Log::GetLevelName(entry.log_level)},
                {"category",Common::Log::GetLogClassName(entry.log_class)},
                {"file",entry.filename ? entry.filename : ""},{"line",entry.line_num},
                {"message",entry.message.substr(0,8192)},{"time_domain","host_monotonic"}});
        });
        citrace = std::make_unique<GpuTrace>(system,root);
        gpu = std::make_unique<GpuTools>(system,root,
            [this](const char* kind,Json data){Record(kind,std::move(data));},
            [this](const char* reason,Json data){Stop(reason,std::move(data));});
        DebugChannel::before_instruction = [this](auto& core, auto* thread) {
            if (stopped) return true;
            if (replaying && replay_instructions == replay_halt_instruction) { HaltReplay(); return true; }
            if (stepping) return false;
            if(!predicate.is_null() && predicate.value("core",0u)==core.GetID()) {
                const auto kind=predicate.value("kind","");bool matches=false;
                if(kind=="pc")matches=core.GetPC()==predicate.at("address").get<u32>();
                if(kind=="memory")matches=Matches({{"kind","memory_equals"},{"address",predicate.at("address")},
                    {"width",predicate.at("width")},{"value",predicate.at("value")}},core);
                if(matches){Stop("predicate",{{"predicate",predicate},{"pc",core.GetPC()},{"core",core.GetID()}});return true;}
            }
            const auto process = thread->owner_process.lock();
            for (auto& [id, bp] : breakpoints) {
                if (bp.kind != "execute" || bp.address != core.GetPC()) continue;
                if (skip_core == core.GetID() && skip_pc == core.GetPC()) {
                    skip_core = 0xffffffff;
                    continue;
                }
                if (bp.process && (!process || *bp.process != process->process_id)) continue;
                ++bp.hits;
                if (bp.hits < bp.hit_after || !Matches(bp.condition, core)) continue;
                if (!bp.log.empty()) { Record("logpoint", {{"breakpoint", id}, {"text", bp.log}, {"pc", core.GetPC()}}); continue; }
                if (Hit("breakpoint", {{"breakpoint", id}, {"address", bp.address}, {"core", core.GetID()},
                                   {"thread", thread->thread_id}, {"process", process ? process->process_id : 0}},
                        replay_instructions))
                    return true;
                break;
            }
            if (replaying) ++replay_instructions;
            return false;
        };
        DebugChannel::memory_access = [this](u32 address, u32 length, bool write) {
            if (stopped) return;
            for (auto& [id, bp] : breakpoints) {
                const auto current = system.Kernel().GetCurrentProcess();
                if (!current || current->process_id != bp.registered_process) continue;
                if (bp.kind == "execute" || (bp.kind == "read" && write) ||
                    (bp.kind == "write" && !write)) continue;
                if (u64(address) < u64(bp.address) + bp.length && u64(bp.address) < u64(address) + length) {
                    ++bp.hits;
                    if (bp.hits < bp.hit_after || !Matches(bp.condition, system.GetRunningCore())) continue;
                    if (!bp.log.empty()) {
                        Record("logpoint", {{"breakpoint", id}, {"text", bp.log}, {"address", address}, {"write", write}});
                        continue;
                    }
                    Hit("watchpoint", {{"breakpoint", id}, {"address", address}, {"write", write},
                        {"core", system.GetRunningCore().GetID()}, {"access_completed", true},
                        {"pc", system.GetRunningCore().GetPC()}},
                        replay_instructions ? replay_instructions - 1 : 0);
                    break;
                }
            }
        };
        DebugChannel::guest_log = [this](u32 address, const std::string& text) {
            Record("guest_log", {{"address", address}, {"text", text.substr(0, 8192)}});
        };
        DebugChannel::memory_fault = [this](u32 address,u32 width,bool write) {
            Stop("exception", {{"type","unmapped_memory"},{"address",address},{"width",width},{"write",write},
                {"pc",system.GetRunningCore().GetPC()},{"core",system.GetRunningCore().GetID()},
                {"semantics","stopped after native unmapped-access handler; no hardware abort fidelity claim"}});
        };
        DebugChannel::exception = [this](u32 pc, u32 type) {
            Stop("exception", {{"pc", pc}, {"exception", type},
                              {"core", system.GetRunningCore().GetID()}});
        };
        DebugChannel::svc_break = [this](u32 reason) {
            Stop("svc_break", {{"reason", reason}, {"core", system.GetRunningCore().GetID()}});
        };
        DebugChannel::svc = [this](u32 id, bool enter) {
            if (!trace_svc && (predicate.is_null() || predicate.value("kind","")!="svc")) return;
            const auto core = system.GetRunningCore().GetID();
            const auto now = system.CoreTiming().GetGlobalTicks();
            if (enter) svc_started[core] = now;
            Record(enter ? "svc_enter" : "svc_exit",
                   {{"svc", id}, {"core", core}, {"duration_guest_ticks", enter ? 0 : now-svc_started[core]}});
        };
        DebugChannel::hio = [this](u32 address) {
            // libctru PackedGdbHioRequest v1: 152 bytes, independently of Azahar's GDB stub.
            const auto bytes = Read(address, 152);
            if (std::memcmp(bytes.data(), "GDB\0", 4) != 0)
                throw std::invalid_argument("invalid HIO request magic");
            u32 version;
            std::memcpy(&version, bytes.data()+4, 4);
            if (version != 1) throw std::invalid_argument("unsupported HIO version");
            std::string function(reinterpret_cast<const char*>(bytes.data()+8), 17);
            function = function.substr(0, function.find('\0'));
            u64 params[8];
            std::memcpy(params, bytes.data()+40, sizeof(params));
            if (hio_forward) {
                if (hio_pending) throw std::invalid_argument("HIO request already pending");
                std::string packet = "F" + function;
                u32 strings = 0;
                for (u32 i = 0; i < 8 && bytes[25+i]; ++i) {
                    const auto type = bytes[25+i];
                    if (type == 's') {
                        u32 length; std::memcpy(&length, bytes.data()+104+4*strings++, 4);
                        packet += fmt::format(",{:x}/{:x}", static_cast<u32>(params[i]), length);
                    } else if (type == 'i' || type == 'I' || type == 'p') {
                        packet += fmt::format(",{:x}", static_cast<u32>(params[i]));
                    } else if (type == 'l' || type == 'L') {
                        packet += fmt::format(",{:x}", params[i]);
                    } else throw std::invalid_argument("invalid HIO parameter format");
                }
                hio_pending = address;
                Stop("hio", {{"packet", packet}, {"address", address}});
                return;
            }
            s64 retval = -1;
            s32 error = 38;
            if (function == "write" && (params[0] == 1 || params[0] == 2) && params[2] <= 4096 && params[1] <= 0xffffffff) {
                const auto data = Read(static_cast<u32>(params[1]), params[2]);
                Record("hio_stdout", {{"fd", params[0]}, {"text", std::string(data.begin(), data.end())}});
                retval = params[2];
                error = 0;
            }
            std::vector<u8> reply(16, 0);
            std::memcpy(reply.data(), &retval, 8);
            std::memcpy(reply.data()+8, &error, 4);
            Write(address+136, reply);
        };
    }
    void Detach() {
        Common::Log::SetObserver({});
        gpu.reset();
        citrace.reset();
        DebugChannel::before_instruction = {};
        DebugChannel::memory_access = {};
        DebugChannel::guest_log = {};
        DebugChannel::exception = {};
        DebugChannel::memory_fault = {};
        DebugChannel::svc_break = {};
        DebugChannel::svc = {};
        DebugChannel::hio = {};
        DebugChannel::single_step = false;
    }
    void Clear() {
        if (system.IsPoweredOn() && ipc_callback) {
            auto& recorder = system.Kernel().GetIPCRecorder();
            recorder.SetEnabled(false);
            recorder.UnbindCallback(ipc_callback);
            ipc_callback.reset();
        }
        trace_svc = false;
        if (gpu) gpu->Clear();
        if (citrace) citrace->Clear();
        if (system.IsPoweredOn()) {
            ArmWatches(false);
        }
        breakpoints.clear();
        scan.clear();
        history.clear();history_bytes=0;history_frame=~0ull;rewind_enabled=false;
        replaying=false;position_at_hit=false;
        predicate=nullptr;
        hio_pending = 0;
        stop_reason = Json::object();
        skip_core = 0xffffffff;
        stopped = false;
        stepping = false;
        DebugChannel::single_step = false;
    }
    void Resume() {
        if (gpu) gpu->Resume();
        if (stopped && stop_reason.contains("core") && stop_reason["reason"] == "breakpoint") {
            skip_core = stop_reason["core"];
            skip_pc = system.GetCore(skip_core).GetPC();
        }
        stopped = false;
        for (u32 i = 0; i < system.GetNumCores(); ++i) system.GetCore(i).ClearBreakFlag();
    }
    void Stop(const char* reason, Json data) {
        if (stopped) return;
        stopped = true;
        position_at_hit = std::string{reason} == "breakpoint";
        data["reason"] = reason;
        stop_reason = data;
        predicate=nullptr;
        std::erase_if(breakpoints, [](const auto& entry) { return entry.second.temporary; });
        DebugChannel::single_step = !breakpoints.empty();
        for (u32 i = 0; i < system.GetNumCores(); ++i) {
            system.GetCore(i).SetBreakFlag();
            system.GetCore(i).PrepareReschedule();
        }
        Record("stopped", data);
    }
    void Poll() {
        std::deque<std::pair<std::string, Json>> batch;
        { std::scoped_lock lock{pending_mutex}; std::swap(batch, pending_events); }
        for (auto& [kind,data] : batch) Record(kind.c_str(), std::move(data));
    }
    void QueueEvent(const char* kind, Json data) {
        std::scoped_lock lock{pending_mutex};
        if (pending_events.size() == 1024) { pending_events.pop_front(); ++pending_lost; }
        pending_events.emplace_back(kind, std::move(data));
    }
    void SetTrace(bool enabled) {
        trace_svc = enabled;
        auto& recorder = system.Kernel().GetIPCRecorder();
        if (enabled && !ipc_callback) {
            ipc_callback = recorder.BindCallback([this](const auto& request) {
                auto raw = request.untranslated_request_cmdbuf;
                if (raw.size()>64) raw.resize(64);
                auto reply = request.untranslated_reply_cmdbuf;
                if (reply.size()>64) reply.resize(64);
                QueueEvent("ipc", {{"id",request.id},{"status",static_cast<int>(request.status)},
                    {"client_process",request.client_process.id},{"client_thread",request.client_thread.id},
                    {"service",request.client_port.name},{"function",request.function_name},{"hle",request.is_hle},
                    {"request_words",raw},{"reply_words",reply},
                    {"decoded",!request.function_name.empty()},{"observation","queued_to_emulation_safe_point"}});
            });
        }
        recorder.SetEnabled(enabled);
        if (!enabled && ipc_callback) { recorder.UnbindCallback(ipc_callback);ipc_callback.reset(); }
    }
    void Record(const char* kind, Json data) {
        if (replaying) return; // replayed history must not re-emit past events
        data["kind"] = kind;
        data["sequence"] = ++event_sequence;
        data["guest_ticks"] = system.IsPoweredOn() ? system.CoreTiming().GetGlobalTicks() : 0;
        if (events.size() == 1024) { events.pop_front(); ++events_lost; }
        events.push_back(data);
        if (notification) notification(data);
        if(!stopped && !predicate.is_null()) {
            const auto type=predicate.value("kind","");bool matched=false;
            if(type=="svc")matched=std::string{kind}==(predicate.value("enter",true)?"svc_enter":"svc_exit") && data.value("svc",~0u)==predicate.at("id").get<u32>();
            if(type=="draw")matched=std::string{kind}=="pica" && data.value("event",~0u)==2 && data.value("draw",0ull)>=predicate.at("draw").get<u64>();
            if(type=="log" && (std::string{kind}=="guest_log" || std::string{kind}=="hio_stdout" || std::string{kind}=="native_log")) {
                const auto text=data.value("text",data.value("message",std::string{}));
                try { matched=boost::regex_search(text,predicate_regex); }
                catch(const std::exception&) { Stop("predicate",{{"error","regex complexity limit"}});return; }
            }
            if(matched)Stop("predicate",{{"predicate",predicate},{"matched_event",data.at("sequence")}});
        }
    }
    Json Stream(const Json& p, bool logs) {
        const auto after = p.at("after").get<u64>();
        const auto limit = p.at("limit").get<u32>();
        if (!limit || limit > 128) throw std::invalid_argument("stream limit 1..128");
        Json result = Json::array();
        for (const auto& event : events) {
            if (event["sequence"].get<u64>() <= after) continue;
            if (logs && event["kind"] != "guest_log" && event["kind"] != "hio_stdout" && event["kind"] != "native_log") continue;
            if (!result.empty() && result.dump().size()+event.dump().size()>48000) break;
            result.push_back(event);
            if (result.size() == limit) break;
        }
        return {{"events", result}, {"lost_total", events_lost}, {"pending_lost_total",pending_lost.load()},
                {"latest", event_sequence}, {"next",result.empty()?event_sequence:result.back().at("sequence").get<u64>()},
                {"history_gap",!events.empty() && after+1<events.front().at("sequence").get<u64>()}};
    }
    bool IsStopped() const { return stopped; }
    bool IsGpuReplayView() const { return citrace && citrace->IsReplayView(); }
    Json StopReason() const { return stop_reason; }
    void SetContentIdentity(const std::string& path) {
        CryptoPP::SHA256 hash;std::array<u8,65536> block{};
        std::ifstream file(path,std::ios::binary);if(!file)throw std::invalid_argument("cannot read content identity");
        while(file) {file.read(reinterpret_cast<char*>(block.data()),block.size());hash.Update(block.data(),file.gcount());}
        if(!file.eof())throw std::invalid_argument("content identity read failed");
        std::array<u8,CryptoPP::SHA256::DIGESTSIZE> digest{};hash.Final(digest.data());
        const auto identity=Hex(digest);
        if(movie_plan=="play") {
            Json meta;std::ifstream(root/"movies"/(movie_name+".json"))>>meta;
            if(meta.value("rom_sha256","")!=identity)throw std::invalid_argument("movie ROM content mismatch");
        }
        rom_sha256=identity;
    }
    void MovieBeforeLoad() {
        system.Movie().Shutdown();
        if(movie_plan=="record")system.Movie().PrepareForRecording();
        if(movie_plan=="play")system.Movie().PrepareForPlayback((root/"movies"/(movie_name+".ctm")).string());
    }
    void MovieAfterLoad() {
        if(movie_plan=="record") {
            system.Movie().StartRecording((root/"movies"/(movie_name+".ctm")).string(),"LOTUS");
            std::ofstream(root/"movies"/(movie_name+".json"))<<Json{{"source",CTR_SOURCE_SHA},{"settings",SettingsSnapshot()},{"rom_sha256",rom_sha256}}.dump();
        }
        if(movie_plan=="play")system.Movie().StartPlayback((root/"movies"/(movie_name+".ctm")).string());
        movie_plan.clear();
    }
    void CheckFramePredicate(u64 frame) {
        if(!stopped && !predicate.is_null() && predicate.value("kind","")=="frame" && frame>=predicate.at("frame").get<u64>())
            Stop("predicate",{{"predicate",predicate},{"frame",frame}});
    }
    void Remember(u64 frame, const Json& input, std::optional<u32> core={}) {
        if(!rewind_enabled || (!core && history_frame==frame))return;
        if(system.Kernel().AreAsyncOperationsPending()){++history_lost;return;}
        ArmWatches(false);std::vector<u8> bytes;
        try {bytes=system.SaveStateBuffer();}catch(...){ArmWatches(true);throw;}
        ArmWatches(true);
        if(bytes.size()>history_budget)throw std::invalid_argument("single snapshot exceeds rewind memory budget");
        while(!history.empty() && (history.size()>=history_capacity || history_bytes+bytes.size()>history_budget)) {
            history_bytes-=history.front().bytes.size();history.pop_front();++history_lost;
        }
        history_bytes+=bytes.size();history_frame=frame;
        std::map<u64,u64> hits;
        for (const auto& [id, bp] : breakpoints) hits[id] = bp.hits;
        history.push_back({std::move(bytes),frame,core,input,SettingsSnapshot(),Json::object(),0,std::move(hits)});
    }
    void MarkHistoryStop() { if(rewind_enabled && stopped && !history.empty())history.back().stop=stop_reason; }
    Json HistoryStatus() const {
        return {{"enabled",rewind_enabled},{"snapshots",history.size()},{"bytes",history_bytes},
            {"capacity",history_capacity},{"budget_bytes",history_budget},{"lost_snapshots",history_lost},
            {"instruction_history","explicit step operations; continuous execution records frame safe points"},
            {"reverse_continue","replays from frame or instruction checkpoints with instruction stepping; lands before the previous breakpoint or watchpoint access"}};
    }
    Json Reverse(std::optional<u32> core) {
        if(!rewind_enabled || history.empty())throw std::invalid_argument("rewind history unavailable");
        size_t index=history.size();
        while(index) {
            --index;
            if(core ? history[index].core==core : !history[index].stop.empty() &&
                history[index].stop.value("reason","")!="step" && history[index].stop.value("reason","")!="frame")break;
        }
        if(core && history[index].core!=core)throw std::invalid_argument("no instruction checkpoint for this core; step forward with rewind enabled");
        auto& entry=history[index];
        if(!core && entry.stop.empty())throw std::invalid_argument("no recorded debugger stop in rewind history");
        if(entry.settings!=SettingsSnapshot())throw std::invalid_argument("rewind profile changed");
        const bool trace=trace_svc;SetTrace(false);ArmWatches(false);
        if(!system.LoadStateBuffer(entry.bytes))throw std::runtime_error("rewind restore failed");
        ArmWatches(true);if(trace)SetTrace(true);
        for(u32 i=0;i<system.GetNumCores();++i){system.GetCore(i).ClearInstructionCache();system.GetCore(i).ClearBreakFlag();}
        stopped=false;skip_core=0xffffffff;
        Json result={{"worker_frame",entry.frame},{"worker_input",entry.input},{"reverse",true},
            {"history_kind",entry.core?"instruction":"frame"},{"replayed_guest_instructions",0}};
        const auto original=entry.stop;
        const bool replay=!core && !entry.core;
        if(replay)result["resume_requested"]=true;
        else {
            auto stop=original;stop["reverse"]=true;
            Stop(core?"step":original.value("reason",std::string{"manual"}).c_str(),stop);
            result["stop"]=StopReason();
        }
        while(history.size()>index){history_bytes-=history.back().bytes.size();history.pop_back();}
        history_frame=~0ull;
        return result;
    }
    // Reverse continue: breakpoint/watchpoint stops are counted per rewind
    // checkpoint while running forward. Replaying a checkpoint with instruction
    // stepping reproduces the same hit sequence; a watchpoint target is replayed
    // a second time to the instruction index of its access, so the session lands
    // before the access executes.
    // Hits counted under another breakpoint set cannot be replayed.
    void ForgetHits() {
        for (auto& entry : history) entry.window_hits = 0;
        position_at_hit = false;
    }
    bool Hit(const char* reason, Json data, u64 instruction) {
        if (replaying) {
            if (++replay_hits != replay_target) return false;
            data["reason"] = reason;
            replay_hit = std::move(data);
            replay_hit_instruction = instruction;
            HaltReplay();
            return true;
        }
        if (rewind_enabled && !history.empty()) ++history.back().window_hits;
        Stop(reason, std::move(data));
        return true;
    }
    void HaltReplay() {
        stopped = true;
        for (u32 i = 0; i < system.GetNumCores(); ++i) {
            system.GetCore(i).SetBreakFlag();
            system.GetCore(i).PrepareReschedule();
        }
    }
    void RestoreHistory(size_t index) {
        const auto& entry = history[index];
        const bool trace = trace_svc;
        SetTrace(false);
        ArmWatches(false);
        if (!system.LoadStateBuffer(entry.bytes)) throw std::runtime_error("rewind restore failed");
        ArmWatches(true);
        if (trace) SetTrace(true);
        for (u32 i = 0; i < system.GetNumCores(); ++i) {
            system.GetCore(i).ClearInstructionCache();
            system.GetCore(i).ClearBreakFlag();
        }
        for (auto& [id, bp] : breakpoints) {
            const auto it = entry.bp_hits.find(id);
            bp.hits = it == entry.bp_hits.end() ? 0 : it->second;
        }
        apply_input(entry.input);
        set_frame(entry.frame);
        stopped = false;
        skip_core = 0xffffffff;
    }
    // Runs the restored checkpoint until HaltReplay; false on divergence or budget.
    bool Replay(u64 halt_instruction, u64 hit_target, u64 frame_limit) {
        replaying = true;
        replay_hits = 0;
        replay_instructions = 0;
        replay_target = hit_target;
        replay_halt_instruction = halt_instruction;
        replay_hit = nullptr;
        const bool single = DebugChannel::single_step;
        DebugChannel::single_step = true;
        auto callback = std::exchange(Frontend::control_callback, {});
        auto finish = [&] {
            Frontend::control_callback = std::move(callback);
            DebugChannel::single_step = single;
            replaying = false;
        };
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        bool ok = true;
        try {
            while (!stopped) {
                if (std::chrono::steady_clock::now() >= deadline || get_frame() > frame_limit) {
                    ok = false;
                    break;
                }
                if (system.RunLoop() != Core::System::ResultStatus::Success) {
                    ok = false;
                    break;
                }
            }
        } catch (...) {
            finish();
            throw;
        }
        finish();
        std::scoped_lock lock{pending_mutex};
        pending_events.clear(); // native logs produced by the replay duplicate the past
        return ok && stopped;
    }
    Json ReverseContinue() {
        if (!rewind_enabled || history.empty()) throw std::invalid_argument("rewind history unavailable");
        if (!stopped) throw std::invalid_argument("reverse continue requires a stopped session");
        if (breakpoints.empty()) throw std::invalid_argument("reverse continue needs a breakpoint or watchpoint");
        if (hio_pending) throw std::invalid_argument("reverse execution cannot cross a pending HIO request");
        if (system.Kernel().AreAsyncOperationsPending())
            throw std::invalid_argument("asynchronous guest operations pending; step forward and retry");
        size_t k = history.size() - 1;
        u64 target = history[k].window_hits;
        if (position_at_hit && target) --target;
        while (!target) {
            if (!k) throw std::invalid_argument("no earlier breakpoint or watchpoint hit in rewind history");
            target = history[--k].window_hits;
        }
        if (history[k].settings != SettingsSnapshot()) throw std::invalid_argument("rewind profile changed");
        // Keep the present so a diverging replay cannot lose the user's position.
        ArmWatches(false);
        std::vector<u8> present;
        try {
            present = system.SaveStateBuffer();
        } catch (...) {
            ArmWatches(true);
            throw;
        }
        ArmWatches(true);
        const auto present_stop = stop_reason;
        const auto present_frame = get_frame();
        const auto present_input = get_input();
        std::map<u64, u64> present_hits;
        for (const auto& [id, bp] : breakpoints) present_hits[id] = bp.hits;
        const bool present_at_hit = position_at_hit;
        auto restore_present = [&] {
            const bool trace = trace_svc;
            SetTrace(false);
            ArmWatches(false);
            system.LoadStateBuffer(present);
            ArmWatches(true);
            if (trace) SetTrace(true);
            for (u32 i = 0; i < system.GetNumCores(); ++i) system.GetCore(i).ClearInstructionCache();
            for (auto& [id, bp] : breakpoints)
                if (present_hits.count(id)) bp.hits = present_hits[id];
            apply_input(present_input);
            set_frame(present_frame);
            stopped = false;
            Stop(present_stop.value("reason", std::string{"manual"}).c_str(), present_stop);
            position_at_hit = present_at_hit;
        };
        const auto limit = present_frame + 2;
        RestoreHistory(k);
        if (!Replay(~0ull, target, limit)) {
            restore_present();
            throw std::runtime_error("reverse replay did not reproduce the recorded hit; present state restored");
        }
        auto hit = replay_hit;
        const auto instruction = replay_hit_instruction;
        const bool watch = hit.value("reason", "") == "watchpoint";
        if (watch) {
            RestoreHistory(k);
            if (!Replay(instruction, ~0ull, limit) || replay_instructions != instruction) {
                restore_present();
                throw std::runtime_error("reverse replay did not reach the watched access; present state restored");
            }
        }
        while (history.size() > k + 1) {
            history_bytes -= history.back().bytes.size();
            history.pop_back();
        }
        // A watchpoint landing is before its access, which will be counted again going forward.
        history[k].window_hits = watch ? target - 1 : target;
        history_frame = ~0ull;
        stopped = false;
        const auto reason = hit.value("reason", std::string{"breakpoint"});
        hit.erase("reason");
        hit["reverse"] = true;
        hit["checkpoint"] = k;
        hit["hit_ordinal"] = target;
        hit["replayed_guest_instructions"] = instruction;
        if (watch) {
            hit["access_completed"] = false;
            hit["position"] = "before the access instruction executes";
            hit["pc"] = system.GetCore(hit.value("core", 0u)).GetPC();
        }
        Stop(reason.c_str(), hit);
        return {{"worker_frame", get_frame()}, {"worker_input", history[k].input}, {"reverse", true},
                {"history_kind", "replay"}, {"replayed_guest_instructions", instruction},
                {"stop", StopReason()}};
    }
    std::function<void(const Json&)> apply_input;
    std::function<Json()> get_input;
    std::function<u64()> get_frame;
    std::function<void(u64)> set_frame;
    std::function<void(const Json&)> notification;
#endif

    std::shared_ptr<Service::CFG::Module> Config() {
        if (system.IsPoweredOn()) return Service::CFG::GetModule(system);
        if (!boot_cfg) boot_cfg = std::make_shared<Service::CFG::Module>(system);
        return boot_cfg;
    }
    static std::string Hex(std::span<const u8> bytes) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;out.reserve(bytes.size()*2);
        for (const auto b : bytes) { out += digits[b >> 4];out += digits[b & 15]; }
        return out;
    }
    void EnsureSettings() {
        if (cfg_bound) return;
        cfg_bound = true;
        bindings.push_back({"cfg.play_coins","cfg-savedata","src/core/hle/service/ptm/ptm.cpp",
            []{return Json(Service::PTM::Module::GetPlayCoins());},[]{return Json(0);},
            [](const Json& value){if(!value.is_number_integer()||value.get<s64>()<0||value.get<s64>()>300)
                throw std::invalid_argument("play coins range 0..300");Service::PTM::Module::SetPlayCoins(value.get<u16>());},
            {{"minimum",0},{"maximum",300}},nullptr});
        for (const auto& [id, defaults] : Service::CFG::GetDefaultConfigBlocks()) {
            const auto name = "cfg." + fmt::format("{:08x}", static_cast<u32>(id));
            cfg_names.push_back(name);
            const auto size = defaults.data.size();
            const auto default_hex = Hex(defaults.data);
            bindings.push_back({cfg_names.back().c_str(), "cfg-savedata", "src/core/hle/service/cfg/cfg_defaults.cpp",
                [this, id, size] {
                    std::vector<u8> bytes(size);
                    if (!Config()->ReadProfileBlock(id, size, bytes.data()).IsSuccess())
                        throw std::runtime_error("CFG block not readable");
                    return Hex(bytes);
                },
                [default_hex] { return default_hex; },
                [this, id, size](const Json& j) {
                    if (!j.is_string() || j.get_ref<const std::string&>().size() != size*2)
                        throw std::invalid_argument("CFG value must be exact-length hex bytes");
                    const auto text = j.get<std::string>();
                    std::vector<u8> bytes;
                    for (size_t i=0;i<text.size();i+=2) {
                        const auto high = std::string("0123456789abcdef").find(text[i]);
                        const auto low = std::string("0123456789abcdef").find(text[i+1]);
                        if (high > 15 || low > 15) throw std::invalid_argument("invalid CFG hex");
                        bytes.push_back(static_cast<u8>(high*16+low));
                    }
                    const auto cfg = Config();
                    if (!cfg->WriteProfileBlock(id, size, bytes.data()).IsSuccess() ||
                        !cfg->UpdateConfigNANDSavegame().IsSuccess())
                        throw std::runtime_error("CFG savedata update failed");
                }, {{"encoded_bytes", size}, {"format", "hex"}}, nullptr});
        }
    }
    Json SettingsSnapshot() {
        EnsureSettings();
        Json result = Json::object();
        for (auto& b : bindings) result[b.name] = b.get();
        return result;
    }
    Json Registers(u32 id) {
        if (id >= system.GetNumCores()) throw std::invalid_argument("invalid core");
        auto& core = system.GetCore(id);
        Core::ARM_Interface::ThreadContext context;
        core.SaveContext(context);
        const auto thread = system.Kernel().GetThreadManager(id).GetCurrentThread();
        return {{"core", id}, {"registers", context.cpu_registers}, {"cpsr", context.cpsr},
                {"vfp", context.fpu_registers}, {"fpscr", context.fpscr}, {"fpexc", context.fpexc},
                {"thread", thread ? thread->thread_id : 0}, {"mode", context.cpsr & 31},
                {"safe_point", true}, {"spsr_available", false}};
    }
    void CheckMemory(u32 address, size_t length) {
        const auto process = system.Kernel().GetCurrentProcess();
        if (!process || !length || length > 4096 || u64(address) + length > 0x100000000ull)
            throw std::invalid_argument("invalid memory range");
        for (size_t i = 0; i < length; ++i) {
            const auto addr = address + static_cast<u32>(i);
            const auto vma = process->vm_manager.FindVMA(addr);
            if (vma == process->vm_manager.vma_map.end() ||
                vma->second.meminfo_state == Kernel::MemoryState::IO ||
                !system.Memory().IsValidVirtualAddress(*process, addr))
                throw std::invalid_argument("unmapped or MMIO memory");
        }
    }
    std::vector<u8> Read(u32 address, size_t length) {
        CheckMemory(address, length);
        std::vector<u8> bytes(length);
        system.Memory().ReadBlock(*system.Kernel().GetCurrentProcess(), address, bytes.data(), length);
        return bytes;
    }
    void Write(u32 address, const std::vector<u8>& bytes) {
        CheckMemory(address, bytes.size());
        system.Memory().WriteBlock(*system.Kernel().GetCurrentProcess(), address,
                                   bytes.data(), bytes.size());
        system.InvalidateCacheRange(address, bytes.size());
    }
    Json Dispatch(const Json& p, const std::string& state) {
        auto result = DispatchInner(p, state);
        result["paused"] = state != "running";
        result["safe_point"] = true;
        result["rasterizer_cache_flush"] = result.value("rasterizer_cache_flush",false) || p.value("operation", "") == "citrace_start" || p.value("operation", "") == "read_memory" ||
            p.value("operation", "") == "write_memory" || p.value("operation", "") == "save_state";
        result["guest_ticks"] = system.IsPoweredOn() ? system.CoreTiming().GetGlobalTicks() : 0;
        result["renderer"] = static_cast<int>(Settings::values.graphics_api.GetValue());
        result["source"] = CTR_SOURCE_SHA;
        result["backend_name"] = CTR_BACKEND_NAME;
        result["gpu_replay_view"] = IsGpuReplayView();
        return result;
    }
    Json DispatchInner(const Json& p, const std::string& state) {
        Poll();
        EnsureSettings();
        const auto op = p.at("operation").get<std::string>();
        if(IsGpuReplayView() && (op=="step"||op=="step_over"||op=="step_out"||op=="run_to"||op=="run_until"||op=="citrace_start"||op=="save_state"))
            throw std::invalid_argument("GPU replay view: load a checkpoint or reset before CPU execution/checkpointing");
        if(op=="content_transform") {
            const auto path=(root/"media/content.rom").string();const auto info=Loader::GetLoaderFileInfo(path);
            const bool compress=p.at("compress");
            if(!info.is_valid||!info.is_compress_supported||compress==info.is_compressed)throw std::invalid_argument("content compression type mismatch");
            if(!compress) {
                FileUtil::Z3DSFileHeader header;std::ifstream file(path,std::ios::binary);
                if(!file.read(reinterpret_cast<char*>(&header),sizeof(header)) || header.uncompressed_size>(64u<<20))
                    throw std::invalid_argument("decompression exceeds 64 MiB budget");
            }
            const auto relative=std::filesystem::path("content")/("transformed."+(compress?info.recommended_compressed_extension:info.recommended_plain_extension));
            std::filesystem::create_directories(root/"content");
            const bool success=compress?FileUtil::CompressZ3DSFile(path,(root/relative).string(),info.underlying_magic,
                info.default_compress_frame_size,nullptr,info.default_metadata):FileUtil::DeCompressZ3DSFile(path,(root/relative).string());
            if(!success)throw std::runtime_error("content transform failed");
            return {{"compressed",compress},{"artifacts",Json::array({{{"path",relative.generic_string()},{"format","rom"}}})}};
        }
        if(op=="install_cia") {
            if(system.IsPoweredOn())throw std::invalid_argument("install content before booting");
            const auto status=Service::AM::InstallCIA((root/"media/content.cia").string());
            if(status!=Service::AM::InstallStatus::Success)throw std::invalid_argument("CIA install failed: "+std::to_string(static_cast<u32>(status)));
            return {{"installed",true},{"storage","session NAND/SDMC"}};
        }
        if(op=="system_regenerate") {
            if(system.IsPoweredOn())throw std::invalid_argument("regenerate system identity before boot");
            auto cfg=Config();
            if(p.at("console_id").get<bool>()) {auto [random,id]=cfg->GenerateConsoleUniqueId();cfg->SetConsoleUniqueId(random,id);cfg->UpdateConfigNANDSavegame();}
            if(p.at("mac").get<bool>()){cfg->GetMacAddress()=Service::CFG::GenerateRandomMAC();cfg->SaveMacAddress();}
            return {{"regenerated_console_id",p.at("console_id")},{"regenerated_mac",p.at("mac")},{"session_private",true}};
        }
        if(op=="movie_record"||op=="movie_play"||op=="movie_stop"||op=="movie_status") {
            auto& movie=system.Movie();
            if(op=="movie_record"||op=="movie_play") {
                if(system.IsPoweredOn())throw std::invalid_argument("prepare movie before loading content");
                const auto name=p.at("name").get<std::string>();
                if(name.empty()||name.size()>32||name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")!=std::string::npos)
                    throw std::invalid_argument("invalid movie name");
                std::filesystem::create_directories(root/"movies");
                if(op=="movie_play") {
                    const auto path=root/"movies"/(name+".ctm");
                    if(std::filesystem::file_size(path)>(32u<<20)+4096 || movie.ValidateMovie(path.string())!=Core::Movie::ValidationResult::OK)
                        throw std::invalid_argument("incompatible or invalid movie");
                    Json meta;std::ifstream(root/"movies"/(name+".json"))>>meta;
                    if(meta.at("source")!=CTR_SOURCE_SHA || meta.at("settings")!=SettingsSnapshot())throw std::invalid_argument("movie profile or pin mismatch");
                    movie.SetReadOnly(p.at("read_only"));
                }
                movie_name=name;movie_plan=op=="movie_record"?"record":"play";
            }
            const auto dropped=movie.GetDroppedInputs();
            if(op=="movie_stop") {movie.Shutdown();movie_plan.clear();}
            Json result={{"mode",static_cast<u32>(movie.GetPlayMode())},{"prepared",movie_plan},{"name",movie_name},
                {"input_index",movie.GetCurrentInputIndex()},{"total_inputs",movie.GetTotalInputCount()},
                {"dropped_inputs",dropped},{"recording_budget_bytes",32u<<20}};
            const auto relative=std::filesystem::path("movies")/(movie_name+".ctm");
            if(op=="movie_stop" && !movie_name.empty() && std::filesystem::is_regular_file(root/relative))
                result["artifacts"]=Json::array({{{"path",relative.generic_string()},{"format","ctm"}}});
            return result;
        }
        if (op == "settings_list") {
            Json result = Json::array();
            const auto offset = p.value("offset", 0u), limit = p.value("limit", 32u);
            if (!limit || limit > 32 || offset > bindings.size()) throw std::invalid_argument("invalid settings page");
            for (size_t i = offset; i < std::min<size_t>(bindings.size(), offset+limit); ++i) {
                auto& b = bindings[i];
                Json descriptor = {{"name", b.name}, {"type", b.get().type_name()},
                    {"default", b.defaults()}, {"value", b.get()}, {"apply", b.apply},
                    {"range", b.range}, {"choices", b.choices},
                    {"consumer_sources", b.source}};
                if (!result.empty() && result.dump().size() + descriptor.dump().size() > 48000) break;
                result.push_back(std::move(descriptor));
            }
            const auto next = offset + result.size();
            return {{"settings", result}, {"total", bindings.size()},
                    {"next", next < bindings.size() ? Json(next) : Json(nullptr)}};
        }
        if (op == "settings_diff") {
            Json result = Json::object();
            for (auto& b : bindings)
                if (b.get() != b.defaults()) result[b.name] = {{"stock", b.defaults()}, {"value", b.get()}};
            return {{"diff", result}};
        }
        if (op == "settings_get" || op == "settings_set") {
            const auto name = p.at("name").get<std::string>();
            auto it = std::find_if(bindings.begin(), bindings.end(),
                                  [&](const auto& b) { return name == b.name; });
            if (it == bindings.end()) throw std::invalid_argument("unknown setting");
            if (op == "settings_set") {
                if (system.IsPoweredOn() && std::string{it->apply} != "live")
                    throw std::invalid_argument("boot setting requires an unloaded session");
                const auto& value = p.at("value");
                if ((name == "use_gdbstub" || name == "enable_rpc_server" ||
                     name == "use_custom_storage") && value != false)
                    throw std::invalid_argument("worker settings cannot enable external listeners or storage");
                if (name == "output_type" && value != 6)
                    throw std::invalid_argument("worker audio must use its bounded sink");
#ifndef ENABLE_VULKAN
                if (name == "graphics_api" && value != 0)
                    throw std::invalid_argument("renderer not compiled");
#else
                if (name == "graphics_api" && value != 0 && value != 2)
                    throw std::invalid_argument("worker supports software and Vulkan");
#endif
                if (!it->choices.is_null() && std::find(it->choices.begin(), it->choices.end(), value) == it->choices.end())
                    throw std::invalid_argument("invalid enum setting");
                it->set(value);
                if (system.IsPoweredOn()) system.ApplySettings();
            }
            return {{"name", name}, {"value", it->get()}, {"apply", it->apply}};
        }
        if (op == "asset_mount" || op == "nfc_remove") {
            const auto kind=p.value("kind", "");
            if(op=="nfc_remove" || kind=="nfc") {
                if(!system.IsPoweredOn())throw std::invalid_argument("NFC requires loaded content");
                const auto service=system.ServiceManager().GetService<Service::NFC::Module::Interface>("nfc:u");
                if(!service)throw std::invalid_argument("NFC service unavailable");
                if(op=="nfc_remove")service->RemoveAmiibo();
                else if(!service->LoadAmiibo((root/"media/nfc.bin").string()))throw std::invalid_argument("invalid NFC asset");
            } else if(kind=="camera_bmp") {
                auto mounted=MountCamera(system,root);mounted["mounted"]=kind;mounted["session_private"]=true;
                return mounted;
            } else if(kind=="mic_wav") {
                AudioCore::InjectedInput::Load(root/"media/mic.wav");
                Settings::values.input_type=AudioCore::InputType::Injected;
                if(system.IsPoweredOn())Service::MIC::ReloadMic(system);
            }
            return {{"mounted",kind},{"session_private",true}};
        }
        if (op == "audio_focus") {
            AudioCore::WorkerSink::SetFocus(p.at("enabled").get<bool>());
            return {{"focused", AudioCore::WorkerSink::focused}};
        }
        if (op == "audio_capture") {
            const auto directory = root / "audio";
            std::filesystem::create_directories(directory);
            if (p.at("enabled").get<bool>()) AudioCore::WorkerSink::CaptureStart(directory / "capture.wav");
            else AudioCore::WorkerSink::CaptureStop();
            Json result = {{"path", "audio/capture.wav"}, {"pcm_bytes", AudioCore::WorkerSink::capture_bytes},
                    {"limit_reached", AudioCore::WorkerSink::capture_full},
                    {"sample_rate", AudioCore::native_sample_rate}, {"channels", 2}, {"sample_format", "s16le"},
                    {"domain", "raw_DSP_before_host_volume_and_stretching"}};
            if (!p.at("enabled").get<bool>() && std::filesystem::exists(directory/"capture.wav"))
                result["artifacts"]=Json::array({{{"path","audio/capture.wav"},{"format","wav"}}});
            return result;
        }
        if (!system.IsPoweredOn()) throw std::runtime_error("load content first");
        const bool paused = state == "paused";
        Json result;
        if(op=="dsp_load_firmware") {
            if(!paused || Settings::values.audio_emulation.GetValue()==Settings::AudioEmulation::HLE)
                throw std::invalid_argument("explicit firmware bootstrap requires paused LLE");
            const auto path=root/"sdmc/3ds/dspfirm.cdc";const auto size=std::filesystem::file_size(path);
            if(size<0x300||size>(4u<<20))throw std::invalid_argument("DSP firmware size budget");
            std::vector<u8> bytes(size);std::ifstream file(path,std::ios::binary);
            file.exceptions(std::ios::failbit|std::ios::badbit);file.read(reinterpret_cast<char*>(bytes.data()),size);
            if(std::memcmp(bytes.data()+0x100,"DSP1",4))throw std::invalid_argument("invalid DSP1 firmware");
            system.DSP().LoadComponent(bytes);
            return {{"loaded",true},{"mode","LLE"},{"firmware_source","private session asset"},
                {"ownership","explicit debugger bootstrap; guest must not load a second component"}};
        }
        if (op == "dsp_inspect") {
            if(Settings::values.audio_emulation.GetValue()!=Settings::AudioEmulation::HLE)
                throw std::invalid_argument("DSP inspector supports HLE shared state only");
            Json regions=Json::array();
            for(auto offset:{AudioCore::HLE::region0_offset,AudioCore::HLE::region1_offset}) {
                const auto& memory=*reinterpret_cast<const AudioCore::HLE::SharedMemory*>(system.Memory().GetDspMemory(offset));
                Json voices=Json::array();
                for(u32 i=0;i<AudioCore::HLE::num_sources;++i) {
                    const auto& config=memory.source_configurations.config[i];
                    const auto& status=memory.source_statuses.status[i];
                    Json gains=Json::array();for(const auto& bus:config.gain){Json row=Json::array();
                        for(auto gain:bus)row.push_back(static_cast<float>(gain));gains.push_back(row);}
                    voices.push_back({{"voice",i},{"enabled",config.enable!=0},{"playing",status.is_enabled!=0},
                        {"source_physical_address",static_cast<u32>(config.physical_address)},
                        {"samples",static_cast<u32>(config.length)},{"position",static_cast<u32>(status.buffer_position)},
                        {"rate_multiplier",static_cast<float>(config.rate_multiplier)},
                        {"format",static_cast<u32>(config.format.Value())},{"channels",static_cast<u32>(config.mono_or_stereo.Value())},
                        {"buffer_id",static_cast<u16>(status.current_buffer_id)},{"gains",gains}});
                }
                const auto& mix=memory.dsp_configuration;
                regions.push_back({{"dsp_offset",offset},{"frame_counter",static_cast<u16>(memory.frame_counter)},
                    {"dropped_frames",static_cast<u16>(memory.dsp_status.dropped_frames)},
                    {"master_volume",static_cast<float>(mix.master_volume)},
                    {"output_format",static_cast<u32>(mix.output_format)},
                    {"headphones_connected",static_cast<u16>(mix.headphones_connected)}, {"voices",voices}});
            }
            return {{"mode","HLE"},{"regions",regions},{"snapshot","DSP shared configurations and statuses"},
                {"sample_rate",AudioCore::native_sample_rate}};
        }
        if (op == "registers") result = Registers(p.at("core").get<u32>());
        else if(op=="titles") {
            const auto media=p.at("media").get<u32>(),offset=p.at("offset").get<u32>(),limit=p.at("limit").get<u32>();
            if(media>2||!limit||limit>128)throw std::invalid_argument("invalid title page");
            const auto am=Service::AM::GetModule(system);Json titles=Json::array();
            for(auto id:am->DebugTitles(media,offset,limit))titles.push_back(fmt::format("{:016x}",id));
            return {{"titles",titles},{"media",media},{"offset",offset},{"next",titles.size()==limit?Json(offset+limit):Json(nullptr)},
                {"observation","mutex-protected AM title-list snapshot"}};
        }
        else if(op=="cheats"||op=="cheat_add"||op=="cheat_enable"||op=="cheat_remove") {
            auto& engine=system.CheatEngine();
            if(op!="cheats"&&!paused)throw std::invalid_argument("cheat mutation requires pause");
            if(op=="cheat_add") {
                if(engine.GetCheats().size()>=64)throw std::invalid_argument("64-cheat cap");
                const auto code=p.at("code").get<std::string>();
                if(code.size()>8192||p.at("name").get<std::string>().size()>128||p.at("comments").get<std::string>().size()>1024)
                    throw std::invalid_argument("cheat size budget");
                std::istringstream lines(code);std::string line;u32 count=0;
                while(std::getline(lines,line))if(!line.empty()){
                    if(++count>256||!Cheats::GatewayCheat::CheatLine(line).valid)throw std::invalid_argument("invalid Gateway cheat code");
                }
                if(!count)throw std::invalid_argument("empty cheat code");
                auto cheat=std::make_shared<Cheats::GatewayCheat>(p.at("name"),code,p.at("comments"));
                cheat->SetEnabled(p.at("enabled"));engine.AddCheat(std::move(cheat));
            }
            if(op=="cheat_enable"||op=="cheat_remove") {
                const auto index=p.at("index").get<u32>();if(index>=engine.GetCheats().size())throw std::invalid_argument("cheat index out of range");
                if(op=="cheat_remove")engine.RemoveCheat(index);else engine.GetCheats()[index]->SetEnabled(p.at("enabled"));
            }
            Json cheats=Json::array();u32 index=0;
            for(const auto& cheat:engine.GetCheats()) {
                if(cheats.size()==64)break;
                cheats.push_back({{"index",index++},{"name",cheat->GetName().substr(0,128)},
                    {"code",cheat->GetCode().substr(0,8192)},{"comments",cheat->GetComments().substr(0,1024)},{"enabled",cheat->IsEnabled()}});
                if(cheats.dump().size()>48000){cheats.erase(cheats.size()-1);break;}
            }
            return {{"cheats",cheats},{"total",engine.GetCheats().size()},{"truncated",cheats.size()<engine.GetCheats().size()}};
        }
        else if (op == "read_memory")
            result = {{"address", p.at("address")}, {"bytes", Read(p.at("address"), p.at("length"))}};
        else if (op == "threads" || op == "processes") {
            Json processes = Json::array(), threads = Json::array(), waits = Json::array();
            for (const auto& process : system.Kernel().GetProcessList()) {
                processes.push_back({{"id", process->process_id}, {"name", process->GetName()},
                                     {"status", static_cast<int>(process->status)}});
                for (const auto& thread : process->GetThreadList()) {
                    threads.push_back({{"id", thread->thread_id}, {"process", process->process_id},
                        {"name", thread->name}, {"core", thread->processor_id},
                        {"status", static_cast<int>(thread->status)}, {"priority", thread->current_priority},
                        {"pc_saved", thread->context.cpu_registers[15]},
                        {"suspended", !thread->CanSchedule()}, {"wait_address", thread->wait_address}});
                    for (const auto& object : thread->wait_objects) {
                        u32 owner = 0;
                        if (auto mutex = Kernel::DynamicObjectCast<Kernel::Mutex>(object))
                            if (mutex->holding_thread) owner = mutex->holding_thread->thread_id;
                        waits.push_back({{"thread", thread->thread_id}, {"object", object->GetObjectId()},
                            {"type", object->GetTypeName()}, {"name", object->GetName()}, {"owner_thread", owner}});
                    }
                }
            }
            result = {{"processes", processes}, {"threads", threads}, {"wait_edges", waits}};
        } else if (op == "memory_map") {
            Json regions = Json::array();
            for (const auto& process : system.Kernel().GetProcessList())
                for (const auto& [base, vma] : process->vm_manager.vma_map)
                    if (vma.type != Kernel::VMAType::Free)
                        regions.push_back({{"process", process->process_id}, {"address", base},
                            {"length", vma.size}, {"permissions", static_cast<u32>(vma.permissions)},
                            {"state", static_cast<u32>(vma.meminfo_state)}});
            result = {{"regions", regions}};
        } else if (op == "perf") {
            const auto stats = system.GetLastPerfStats();
            result = {{"host_seconds", {{"vblank", stats.time_vblank_interval}, {"svc", stats.time_hle_svc},
                {"ipc", stats.time_hle_ipc}, {"gpu", stats.time_gpu}, {"swap", stats.time_swap}}},
                {"system_fps", stats.system_fps}, {"game_fps", stats.game_fps},
                {"speed_ratio", stats.emulation_speed}};
        } else {
#ifndef CTR_EXPERIMENTAL
            throw std::runtime_error("operation requires CITnLO experimental backend");
#else
            if(op=="citrace_start") {
                if(!paused)throw std::invalid_argument("CiTrace start requires pause");
                auto save=p;save["operation"]="save_state";save["name"]="lotus-citrace";
                Dispatch(save,state);return citrace->Start();
            }
            if(op=="citrace_stop")return citrace->Stop();
            if(op=="citrace_status")return citrace->Status();
            if(op=="citrace_replay") {
                if(!paused)throw std::invalid_argument("CiTrace replay requires pause");
                const auto trace=citrace->Read(); // Validate all input before mutating guest state.
                if(citrace->Status().value("recording",false))throw std::invalid_argument("stop recording before replay");
                auto load=p;load["operation"]="load_state";load["name"]="lotus-citrace";
                const auto base=Dispatch(load,state);const auto replay=citrace->Replay(trace);
                auto result=replay;result["worker_frame"]=base.at("worker_frame").get<u64>()+replay.at("frames").get<u64>();
                result["worker_input"]=base.at("worker_input");return result;
            }
            if (op == "gpu_configure" || op == "gpu_draws" || op == "gpu_draw" ||
                op == "shader_trace" || op == "surface") return gpu->Dispatch(p);
            if (op == "hio_forward") {
                hio_forward = p.at("enabled");
                if (!hio_forward && hio_pending) {
                    std::vector<u8> reply(16, 0xff); s32 error = 38;
                    std::memcpy(reply.data()+8, &error, 4);
                    std::fill(reply.begin()+12, reply.end(), 0);
                    Write(hio_pending+136, reply); hio_pending = 0;
                }
                return {{"forwarding", hio_forward}};
            }
            if (op == "hio_reply") {
                if (!hio_pending || !paused) throw std::invalid_argument("no paused HIO request");
                const auto value = p.at("value").get<s64>();
                const auto error = p.at("errno").get<u32>();
                std::vector<u8> reply(16, 0);
                std::memcpy(reply.data(), &value, 8); std::memcpy(reply.data()+8, &error, 4);
                reply[12] = p.at("interrupted").get<bool>();
                Write(hio_pending+136, reply); hio_pending = 0;
                return {{"completed", true}};
            }
            if (op == "thread_registers" || op == "write_thread_register") {
                for (const auto& process : system.Kernel().GetProcessList())
                    for (const auto& thread : process->GetThreadList()) {
                        if (thread->thread_id != p.at("thread").get<u32>()) continue;
                        for (u32 id = 0; id < system.GetNumCores(); ++id) {
                            if (system.Kernel().GetThreadManager(id).GetCurrentThread() != thread.get()) continue;
                            if (op == "thread_registers") return Registers(id);
                            auto edit = p; edit["operation"] = "write_register"; edit["core"] = id;
                            return DispatchInner(edit, state);
                        }
                        auto& context = thread->context;
                        if (op == "write_thread_register") {
                            if (!paused) throw std::invalid_argument("mutation requires pause");
                            auto index = p.at("register").get<u32>(), value = p.at("value").get<u32>();
                            if (index < 16) context.cpu_registers[index] = value;
                            else if (index == 16) context.cpsr = value;
                            else if (index < 81) context.fpu_registers[index-17] = value;
                            else if (index == 81) context.fpscr = value;
                            else if (index == 82) context.fpexc = value;
                            else throw std::invalid_argument("invalid register");
                        }
                        return {{"thread", thread->thread_id}, {"saved_context", true},
                            {"registers", context.cpu_registers}, {"cpsr", context.cpsr},
                            {"vfp", context.fpu_registers}, {"fpscr", context.fpscr}, {"fpexc", context.fpexc}};
                    }
                throw std::invalid_argument("unknown thread");
            }
            if (op == "events" || op == "logs") return Stream(p, op == "logs");
            if (op == "rewind_status")return HistoryStatus();
            if (op == "trace") { SetTrace(p.at("enabled")); return {{"enabled", trace_svc}, {"ipc",trace_svc}}; }
            if (!paused) throw std::invalid_argument("mutation requires paused execution");
            if(op=="run_until") {
                auto next=p.at("predicate");const auto kind=next.at("kind").get<std::string>();
                const auto frames=p.at("frames").get<u32>(),timeout=p.at("timeout_ms").get<u32>();
                if(!frames||frames>600||!timeout||timeout>20000)throw std::invalid_argument("predicate run budget");
                if(kind=="pc"||kind=="memory") {
                    if(next.at("core").get<u32>()>=system.GetNumCores())throw std::invalid_argument("invalid predicate core");
                    if(kind=="memory") {
                        const auto width=next.at("width").get<u32>();
                        if(width!=1&&width!=2&&width!=4&&width!=8)throw std::invalid_argument("predicate memory width");
                        CheckMemory(next.at("address"),width);
                    }
                } else if(kind=="log") {
                    const auto pattern=next.at("regex").get<std::string>();
                    if(pattern.empty()||pattern.size()>256)throw std::invalid_argument("log predicate regex budget");
                    try {predicate_regex=boost::regex(pattern);}catch(...){throw std::invalid_argument("invalid log predicate regex");}
                } else if(kind=="draw")gpu->Dispatch({{"operation","gpu_configure"},{"enabled",true},{"stop_events",Json::array()}});
                else if(kind!="svc"&&kind!="frame")throw std::invalid_argument("unknown predicate");
                predicate=std::move(next);
                DebugChannel::single_step=!breakpoints.empty()||kind=="pc"||kind=="memory";
                return {{"resume_requested",true},{"budget_frames",frames},{"timeout_ms",timeout},{"predicate",predicate}};
            }
            if(op=="rewind_configure") {
                const auto capacity=p.at("capacity").get<u32>(),budget=p.at("budget_mib").get<u32>();
                if(!capacity||capacity>128||budget<16||budget>256)throw std::invalid_argument("invalid rewind budget");
                rewind_enabled=p.at("enabled");history_capacity=capacity;history_budget=u64(budget)<<20;
                history.clear();history_bytes=history_lost=0;history_frame=~0ull;return HistoryStatus();
            }
            if(op=="reverse_step")return Reverse(p.at("core").get<u32>());
            if(op=="reverse_continue")return ReverseContinue();

            if (op == "breakpoint_configure") {
                auto& bp = breakpoints.at(p.at("id").get<u64>());
                if (!p.at("process").is_null()) bp.process = p.at("process").get<u32>(); else bp.process.reset();
                bp.hit_after = p.at("hit_after");
                bp.condition = p.at("condition");
                bp.log = p.at("log").is_null() ? "" : p.at("log").get<std::string>();
                if (bp.log.size()>512) throw std::invalid_argument("logpoint exceeds budget");
                ForgetHits();
                return {{"configured", p.at("id")}};
            }
            if (op == "run_to" || op == "step_over" || op == "step_out") {
                auto id = p.at("core").get<u32>();
                if (id >= system.GetNumCores()) throw std::invalid_argument("invalid core");
                auto& core = system.GetCore(id);
                const bool thumb = core.GetCPSR() & 32;
                u32 address = 0;
                if (op == "run_to") address = p.at("address");
                else if (op == "step_out") {
                    const auto trace = DispatchInner({{"operation","backtrace"},{"core",id},{"limit",2}},state);
                    address = trace.at("frames").size()>1 ? trace.at("frames").at(1).at("pc").get<u32>() & ~1u
                                                         : core.GetReg(14) & ~1u;
                }
                else {
                    const auto bytes = Read(core.GetPC(), 4); u32 word;std::memcpy(&word,bytes.data(),4);
                    const bool call = thumb ? ((word & 0xf800) == 0xf000 || (word & 0xff87) == 0x4780)
                        : ((word & 0x0f000000) == 0x0b000000 || (word & 0x0ffffff0) == 0x012fff30);
                    if (!call) return DispatchInner({{"operation","step"},{"core",id},{"count",1}}, state);
                    address = core.GetPC() + (thumb && (word & 0xff87) == 0x4780 ? 2 : 4);
                }
                auto bp = DispatchInner({{"operation","breakpoint_set"},{"address",address},
                    {"length",thumb ? 2 : 4},{"kind","execute"}}, state);
                breakpoints.at(bp.at("id").get<u64>()).temporary = true;
                return {{"resume_requested",true},{"temporary_breakpoint",bp.at("id")},{"address",address},
                        {"other_cores","run_normally"},{"budget_frames",600}};
            }
            if (op == "handles") {
                Json handles = Json::array();
                for (const auto& process : system.Kernel().GetProcessList())
                    for (const auto& [handle, object] : process->handle_table.DebugHandles()) {
                        if (handles.size() == 256) return {{"handles", handles}, {"truncated", true}};
                        handles.push_back({{"process",process->process_id},{"handle",handle},
                            {"object",object->GetObjectId()},{"type",object->GetTypeName()},{"name",object->GetName()}});
                    }
                return {{"handles",handles},{"truncated",false}};
            }
            if (op == "deadlocks") {
                const auto snapshot = DispatchInner({{"operation","threads"}},state);
                std::map<u32,std::vector<u32>> edges;
                for (const auto& edge : snapshot.at("wait_edges"))
                    if (edge.at("owner_thread").get<u32>()) edges[edge.at("thread")].push_back(edge.at("owner_thread"));
                Json cycles=Json::array();
                for (const auto& [start, owners] : edges) {
                    std::vector<u32> path;std::set<u32> seen;
                    std::function<void(u32)> visit=[&](u32 node) {
                        if (path.size()>128 || cycles.size()>=64) return;
                        if (node==start && !path.empty()) { cycles.push_back(path);return; }
                        if (!seen.insert(node).second) return;
                        path.push_back(node);for (auto owner : edges[node]) visit(owner);path.pop_back();
                    };
                    visit(start);
                }
                return {{"mutex_cycles",cycles},{"wait_edges",snapshot.at("wait_edges")},
                        {"scope","mutex ownership only; events and external waits require inspection"}};
            }
            if (op == "crash_report") {
                const auto id = p.at("core").get<u32>();const auto regs=Registers(id);
                Json report={{"failure_domain","guest"},{"stop",StopReason()},{"registers",regs},
                    {"backtrace",DispatchInner({{"operation","backtrace"},{"core",id},{"limit",32}},state)},
                    {"recent_events",Stream({{"after",event_sequence>32?event_sequence-32:0},{"limit",32}},false)}};
                for (auto [name,address] : {std::pair{"pc_bytes",system.GetCore(id).GetPC()},
                                           std::pair{"stack_bytes",system.GetCore(id).GetReg(13)}})
                    try { report[name]={{"address",address},{"bytes",Read(address,64)}}; } catch (...) { report[name]=nullptr; }
                return report;
            }
            if (op == "pointer_chain") {
                u32 address=p.at("base");Json hops=Json::array();
                const auto offsets=p.at("offsets").get<std::vector<s32>>();
                if(offsets.size()>32) throw std::invalid_argument("pointer chain cap");
                for(auto offset:offsets) {
                    auto bytes=Read(address,4);u32 pointer;std::memcpy(&pointer,bytes.data(),4);
                    const auto next=s64(pointer)+offset;
                    if(next<0 || next>0xffffffffll) throw std::invalid_argument("pointer overflow");
                    hops.push_back({{"address",address},{"pointer",pointer},{"offset",offset}});
                    address=static_cast<u32>(next);
                }
                return {{"address",address},{"hops",hops}};
            }
            if (op == "scan" || op == "scan_narrow" || op == "scan_results") {
                if (op == "scan") {
                    const auto address=p.at("address").get<u32>(),length=p.at("length").get<u32>();
                    scan_width=p.at("width");
                    if (!length || length>(1u<<20) || u64(address)+length>0x100000000ull ||
                        (scan_width!=1&&scan_width!=2&&scan_width!=4&&scan_width!=8) || length%scan_width)
                        throw std::invalid_argument("invalid scan bounds");
                    scan.clear();
                    for (u32 offset=0;offset<length;) {
                        const auto size=std::min<u32>(4096,length-offset);
                        auto bytes=Read(address+offset,size);
                        for(u32 i=0;i<size;i+=scan_width) {
                            u64 value=0;for(u32 b=0;b<scan_width;++b)value|=u64(bytes[i+b])<<(8*b);
                            if(value==p.at("value").get<u64>())scan.push_back({address+offset+i,value});
                        }
                        offset+=size;
                    }
                } else if (op == "scan_narrow") {
                    const auto mode=p.at("mode").get<std::string>();std::vector<Candidate> kept;
                    for(const auto& candidate:scan) {
                        const auto bytes=Read(candidate.address,scan_width);u64 value=0;
                        for(u32 b=0;b<scan_width;++b)value|=u64(bytes[b])<<(8*b);
                        const bool keep=mode=="changed"?value!=candidate.value:mode=="unchanged"?value==candidate.value:
                            mode=="exact"?value==p.at("value").get<u64>():mode=="range"?
                            value>=p.at("value").get<u64>()&&value<=p.at("upper").get<u64>():false;
                        if(keep)kept.push_back({candidate.address,value});
                    }
                    scan=std::move(kept);
                }
                const auto offset=p.value("offset",0u),limit=p.value("limit",256u);
                if(!limit||limit>256||offset>scan.size())throw std::invalid_argument("invalid scan page");
                Json matches=Json::array();
                for(size_t i=offset;i<std::min<size_t>(scan.size(),offset+limit);++i)
                    matches.push_back({{"address",scan[i].address},{"value",scan[i].value}});
                return {{"matches",matches},{"total",scan.size()},{"width",scan_width}};
            }
            if (op == "breakpoints") {
                Json result = Json::array();
                for (const auto& [id, bp] : breakpoints)
                    result.push_back({{"id", id}, {"address", bp.address}, {"length", bp.length},
                                      {"kind", bp.kind}, {"hits", bp.hits}});
                return {{"breakpoints", result}, {"execution_mode", "instruction_step_when_armed"},
                        {"watchpoint_precision", "instruction_completed"}, {"maximum", 64}};
            }
            if (op == "breakpoint_set") {
                if (breakpoints.size() >= 64) throw std::invalid_argument("64-breakpoint cap");
                const auto address = p.at("address").get<u32>(), length = p.at("length").get<u32>();
                const auto kind = p.at("kind").get<std::string>();
                if (!length || length > 65536 || u64(address)+length > 0x100000000ull ||
                    (kind != "execute" && kind != "read" && kind != "write" && kind != "access"))
                    throw std::invalid_argument("invalid breakpoint");
                if (kind == "execute" && length != 2 && length != 4)
                    throw std::invalid_argument("invalid execution width");
                if (kind != "execute") {
                    if (u64(address)+length>=0x100000000ull) throw std::invalid_argument("watchpoint crosses guest boundary");
                    for (u32 offset=0;offset<length;offset+=4096)
                        CheckMemory(address+offset,std::min<u32>(4096,length-offset));
                    system.Memory().RegisterWatchpoint(*system.Kernel().GetCurrentProcess(), address, length);
                }
                const auto id = ++next_breakpoint;
                breakpoints.emplace(id, Breakpoint{address, length, kind, 0});
                ForgetHits();
                breakpoints.at(id).registered_process = system.Kernel().GetCurrentProcess()->process_id;
                DebugChannel::single_step = true;
                return {{"id", id}, {"execution_mode", "instruction_step_when_armed"},
                        {"cost", "high; single instruction dispatch while any breakpoint is armed"}};
            }
            if (op == "breakpoint_remove") {
                const auto id = p.at("id").get<u64>();
                auto it = breakpoints.find(id);
                if (it == breakpoints.end()) throw std::invalid_argument("unknown breakpoint");
                const auto& bp = it->second;
                if (bp.kind != "execute")
                    for (const auto& process : system.Kernel().GetProcessList())
                        if (process->process_id == bp.registered_process)
                            system.Memory().UnregisterWatchpoint(*process, bp.address, bp.length);
                breakpoints.erase(it);
                ForgetHits();
                DebugChannel::single_step = !breakpoints.empty();
                return {{"removed", id}};
            }
            if (op == "step") {
                const auto id = p.at("core").get<u32>(), count = p.at("count").get<u32>();
                if (id >= system.GetNumCores() || count == 0 || count > 100000)
                    throw std::invalid_argument("invalid step bounds");
                Resume();
                stepping = true;
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
                u32 done = 0;
                try {
                    for (; done < count && !stopped && std::chrono::steady_clock::now() < deadline; ++done)
                        {
                            Remember(p.value("worker_frame",0ull),p.value("worker_input",Json::object()),id);
                            if (!system.DebugStep(id)) break;
                            MarkHistoryStop();
                        }
                } catch (...) { stepping = false; throw; }
                stepping = false;
                if (!stopped) Stop("step", {{"core", id}, {"instructions", done}, {"requested_instructions",count},
                    {"host_deadline_reached",std::chrono::steady_clock::now()>=deadline}});
                auto result = Registers(id);
                result["instructions"] = done;
                result["other_cores"] = "held";
                result["stop"] = StopReason();
                return result;
            }

            if (op == "write_memory") {
                Write(p.at("address"), p.at("bytes").get<std::vector<u8>>());
                result = {{"written", p.at("bytes").size()}, {"jit_invalidated", true}};
            } else if (op == "write_register") {
                auto core_id = p.at("core").get<u32>();
                if (core_id >= system.GetNumCores()) throw std::invalid_argument("invalid core");
                auto& core = system.GetCore(core_id);
                const auto index = p.at("register").get<u32>(), value = p.at("value").get<u32>();
                if (index < 16) core.SetReg(index, value);
                else if (index == 16) core.SetCPSR(value);
                else if (index < 81) core.SetVFPReg(index - 17, value);
                else if (index == 81) core.SetVFPSystemReg(VFP_FPSCR, value);
                else if (index == 82) core.SetVFPSystemReg(VFP_FPEXC, value);
                else throw std::invalid_argument("invalid register");
                core.ClearInstructionCache();
                result = Registers(core_id);
            } else if (op == "suspend") {
                const bool suspended = p.at("suspended").get<bool>();
                for (const auto& process : system.Kernel().GetProcessList())
                    for (const auto& thread : process->GetThreadList())
                        if (p.at("thread").is_null() || thread->thread_id == p.at("thread").get<u32>()) {
                            if (suspended) thread->SetUnscheduleMode(Kernel::UnscheduleMode::FRONTEND);
                            else thread->ClearUnscheduleMode(Kernel::UnscheduleMode::FRONTEND);
                        }
                system.PrepareReschedule();
                result = {{"suspended", suspended}};
            } else if (op == "save_state" || op == "load_state" || op == "states") {
                const auto directory = root / "checkpoints";
                std::filesystem::create_directories(directory);
                if (op == "states") {
                    Json names = Json::array();
                    for (const auto& entry : std::filesystem::directory_iterator(directory))
                        if (entry.path().extension() == ".json") names.push_back(entry.path().stem().string());
                    result = {{"states", names}};
                } else {
                    const auto name = p.at("name").get<std::string>();
                    if (name.empty() || name.size() > 32 ||
                        name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
                        throw std::invalid_argument("invalid checkpoint name");
                    const auto path = directory / (name + ".bin"), metadata = directory / (name + ".json");
                    if (system.Kernel().AreAsyncOperationsPending())
                        throw std::runtime_error("checkpoint requires completed async operations");
                    if (op == "save_state") {
                        size_t existing = 0;
                        for (const auto& entry : std::filesystem::directory_iterator(directory))
                            if (entry.path().extension()==".json") ++existing;
                        if (existing>=16 && !std::filesystem::exists(metadata)) throw std::invalid_argument("16-checkpoint cap");
                        ArmWatches(false);
                        std::vector<u8> bytes;
                        try { bytes = system.SaveStateBuffer(); } catch (...) { ArmWatches(true); throw; }
                        ArmWatches(true);
                        if (bytes.size() > (256u << 20)) throw std::runtime_error("checkpoint exceeds 256 MiB");
                        std::ofstream file(path.string()+".tmp", std::ios::binary | std::ios::trunc);
                        file.exceptions(std::ios::failbit | std::ios::badbit);
                        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                        file.close();
                        std::ofstream meta(metadata.string()+".tmp");
                        meta.exceptions(std::ios::failbit | std::ios::badbit);
                        meta << Json{{"rom_sha256",rom_sha256},{"archive_version",2},{"source", CTR_SOURCE_SHA}, {"settings", SettingsSnapshot()}, {"worker_frame", p.at("worker_frame")},
                                     {"worker_input",p.value("worker_input",Json::object())},
                                     {"content_xxh3_64",Common::ComputeHash64(bytes.data(),bytes.size())}}.dump();
                        meta.close();
                        std::filesystem::rename(path.string()+".tmp",path);
                        std::filesystem::rename(metadata.string()+".tmp",metadata);
                    } else {
                        Json meta;
                        std::ifstream(metadata) >> meta;
                        if (meta.value("rom_sha256","")!=rom_sha256 || meta.value("archive_version",0)!=2 || meta.at("source") != CTR_SOURCE_SHA || meta.at("settings") != SettingsSnapshot())
                            throw std::invalid_argument("checkpoint pin or settings mismatch");
                        const auto size = std::filesystem::file_size(path);
                        if (size > (256u << 20)) throw std::invalid_argument("checkpoint exceeds budget");
                        std::vector<u8> bytes(size);
                        std::ifstream file(path, std::ios::binary);
                        file.exceptions(std::ios::failbit | std::ios::badbit);
                        file.read(reinterpret_cast<char*>(bytes.data()), size);
                        if (meta.at("content_xxh3_64").get<u64>() != Common::ComputeHash64(bytes.data(),bytes.size()))
                            throw std::invalid_argument("checkpoint integrity mismatch");
                        Clear();
                        if (!system.LoadStateBuffer(std::move(bytes))) throw std::runtime_error("checkpoint load failed");
                        for (u32 i = 0; i < system.GetNumCores(); ++i) system.GetCore(i).ClearInstructionCache();
                    }
                    result = {{"name", name}, {"source", CTR_SOURCE_SHA}};
                    if (op == "load_state") { Json meta; std::ifstream(metadata) >> meta; result["worker_frame"] = meta.at("worker_frame");result["worker_input"]=meta.at("worker_input"); }
                }
            } else if (op == "backtrace") {
                const auto id = p.at("core").get<u32>(), limit = p.at("limit").get<u32>();
                if (limit == 0 || limit > 128 || id >= system.GetNumCores())
                    throw std::invalid_argument("invalid backtrace bounds");
                auto& core = system.GetCore(id);
                Json frames = Json::array({{{"pc", core.GetPC()}, {"sp", core.GetReg(13)}}});
                u32 fp = core.GetReg((core.GetCPSR() & 32) ? 7 : 11);
                std::set<u32> visited;
                for (u32 i = 1; i < limit && fp && !(fp & 3) && visited.insert(fp).second; ++i) {
                    try {
                        // AAPCS frame chain emitted by Clang: saved FP at FP, LR at FP+4.
                        // A frame with a zero parent still contributes its return address.
                        const auto bytes = Read(fp, 8);
                        u32 next, lr;
                        std::memcpy(&next, bytes.data(), 4);
                        std::memcpy(&lr, bytes.data() + 4, 4);
                        if (!lr || (next && (next <= fp || next - fp > (1 << 20)))) break;
                        frames.push_back({{"pc", lr}, {"sp", fp+8}, {"frame_pointer", fp}});
                        fp = next;
                    } catch (const std::exception&) { break; }
                }
                result = {{"frames", frames}, {"unwind", "AAPCS_saved_FP_LR"},
                          {"complete", false}, {"note", "requires frame pointers; DWARF unwinding is separate"}};
            } else throw std::runtime_error("unsupported debug operation");
#endif
        }
        result["paused"] = paused;
        result["safe_point"] = true;
        result["rasterizer_cache_flush"] = op == "read_memory" || op == "write_memory" || op == "save_state";
        result["guest_ticks"] = system.CoreTiming().GetGlobalTicks();
        return result;
    }
private:
#ifdef CTR_EXPERIMENTAL
    struct Breakpoint {
        u32 address, length; std::string kind; u64 hits;
        std::optional<u32> process;
        u32 registered_process = 0;
        u64 hit_after = 0;
        Json condition;
        std::string log;
        bool temporary = false;
    };
    void ArmWatches(bool enabled) {
        for (const auto& [id, bp] : breakpoints)
            if (bp.kind != "execute")
                for (const auto& process : system.Kernel().GetProcessList())
                    if (process->process_id == bp.registered_process) {
                        if (enabled) system.Memory().RegisterWatchpoint(*process,bp.address,bp.length);
                        else system.Memory().UnregisterWatchpoint(*process,bp.address,bp.length);
                    }
    }
    bool Matches(const Json& condition, Core::ARM_Interface& core) {
        if (condition.is_null()) return true;
        const auto kind = condition.at("kind").get<std::string>();
        if (kind == "register_equals") {
            const auto index = condition.at("register").get<u32>();
            if (index > 16) return false;
            const auto value = index == 16 ? core.GetCPSR() : core.GetReg(index);
            return (value & condition.at("mask").get<u32>()) ==
                (condition.at("value").get<u32>() & condition.at("mask").get<u32>());
        }
        if (kind == "memory_equals") {
            try {
                const auto bytes = Read(condition.at("address"), condition.at("width"));
                u64 value = 0; for (size_t i=0;i<bytes.size();++i) value |= u64(bytes[i]) << (8*i);
                return value == condition.at("value").get<u64>();
            } catch (...) { return false; }
        }
        return false;
    }
    struct Candidate { u32 address; u64 value; };
    struct HistoryEntry {
        std::vector<u8> bytes;u64 frame;std::optional<u32> core;Json input,settings,stop;
        u64 window_hits=0;            // breakpoint/watchpoint stops observed after this checkpoint
        std::map<u64,u64> bp_hits;    // breakpoint hit counters at this checkpoint
    };
    bool replaying=false, position_at_hit=false;
    u64 replay_target=0, replay_hits=0, replay_instructions=0, replay_halt_instruction=~0ull, replay_hit_instruction=0;
    Json replay_hit;
    std::deque<HistoryEntry> history;
    bool rewind_enabled=false;
    size_t history_capacity=32;
    u64 history_bytes=0,history_budget=64u<<20,history_lost=0,history_frame=~0ull;
    std::vector<Candidate> scan;
    u32 scan_width = 0;
    std::unique_ptr<GpuTools> gpu;
    std::unique_ptr<GpuTrace> citrace;
    std::string rom_sha256;
    IPCDebugger::CallbackHandle ipc_callback;
    std::mutex pending_mutex;
    std::deque<std::pair<std::string,Json>> pending_events;
    std::atomic<u64> pending_lost{0};
    std::array<u64,4> svc_started{};
    std::map<u64, Breakpoint> breakpoints;
    u64 next_breakpoint = 0, event_sequence = 0, events_lost = 0;
    std::deque<Json> events;
    bool stopped = false, stepping = false, trace_svc = false, hio_forward = false;
    u32 hio_pending = 0;
    u32 skip_core = 0xffffffff, skip_pc = 0;
    Json stop_reason;
    Json predicate;
    boost::regex predicate_regex;
    std::string movie_plan,movie_name;
#endif
    Core::System& system;
    std::filesystem::path root;
    std::vector<SettingBinding> bindings;
    std::deque<std::string> cfg_names;
    std::shared_ptr<Service::CFG::Module> boot_cfg;
    bool cfg_bound = false;
};
} // namespace CtrWorker
