// Worker-side settings and safe-point inspection. No product/UI dependencies.
#pragma once
#include <algorithm>
#include <chrono>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <span>
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
#include "ctr_worker/checkpoint.h"

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
    // HLE async sections (hle_ipc.h RunAsync/RunOnThreadWorker) otherwise run on host threads and
    // wake the guest thread when the host finishes, so the wake tick follows host timing and two
    // runs of the same ROM diverge. On, they run on the emulation thread and sleep their emulated
    // delay (lotus#29). Upstream default is off.
    Settings::values.deterministic_async_operations = true;
}
class DebugTools {
    struct HistoryEntry; // defined with the history members; named by Restore()
public:
    using Json = nlohmann::json;
    explicit DebugTools(Core::System& system, const std::filesystem::path& root)
        : system(system), root(root), bindings(SettingsBindings()) {}

#ifdef CTR_EXPERIMENTAL
    void Attach() {
        system.Movie().SetRecordingBudget(32u<<20);
        Common::Log::SetObserver([this](const Common::Log::Entry& entry) {
            if (!Wanted(NATIVE_LOG)) return;
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
        gpu->wants_events=[this]{return Wanted(PICA);};
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
                if (!bp.log.empty()) {
                    if (Wanted(LOG)) Record("logpoint", {{"breakpoint", id}, {"text", bp.log}, {"pc", core.GetPC()}});
                    continue;
                }
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
                        if (Wanted(LOG)) Record("logpoint", {{"breakpoint", id}, {"text", bp.log}, {"address", address}, {"write", write}});
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
            if (!Wanted(LOG)) return;
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
            if (!Wanted(SVC)) return;
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
                if (Wanted(LOG)) Record("hio_stdout", {{"fd", params[0]}, {"text", std::string(data.begin(), data.end())}});
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
        DebugChannel::code_breakpoints.clear();
    }
    // Execute breakpoints run under the JIT (DebugChannel::code_breakpoints). Instruction
    // stepping remains for memory watchpoints and pc/memory predicates: a JIT block cannot
    // stop between a watched access and the rest of the block, and Dynarmic's memory-abort
    // halt re-executes the instruction after its writeback (load_store.cpp GetAddress writes
    // Rn before the access; a32_emit_x64_memory.cpp EmitCheckMemoryAbort resets PC to it).
    bool NeedsInstructionStep() const {
        if (!predicate.is_null()) {
            const auto kind = predicate.value("kind", "");
            if (kind == "pc" || kind == "memory") return true;
        }
        return std::any_of(breakpoints.begin(), breakpoints.end(),
                           [](const auto& entry) { return entry.second.kind != "execute"; });
    }
    // Call after any change to breakpoints or predicate. Dynarmic defers ClearCache while a
    // block is executing, so this is safe from callbacks inside a JIT run.
    void SyncExecution() {
        std::set<u32> code;
        for (const auto& [id, bp] : breakpoints)
            if (bp.kind == "execute") code.insert(bp.address);
        if (code != DebugChannel::code_breakpoints) {
            DebugChannel::code_breakpoints = std::move(code);
            if (system.IsPoweredOn())
                for (u32 i = 0; i < system.GetNumCores(); ++i) system.GetCore(i).ClearInstructionCache();
        }
        DebugChannel::single_step = NeedsInstructionStep();
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
        history.clear();
        compressor.Reset();
        history_bytes=0;history_frame=~0ull;rewind_enabled=false;history_interval=1;history_force=false;hits_untracked=false;history_level=3;history_queue=1;checkpoint_stats={};lost={};
        replaying=false;position_at_hit=false;
        predicate=nullptr;predicate_mask=0;
        hio_pending = 0;
        stop_reason = Json::object();
        skip_core = 0xffffffff;
        stopped = false;
        stepping = false;
        SyncExecution();
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
        predicate=nullptr;predicate_mask=0;
        std::erase_if(breakpoints, [](const auto& entry) { return entry.second.temporary; });
        SyncExecution();
        for (u32 i = 0; i < system.GetNumCores(); ++i) {
            system.GetCore(i).SetBreakFlag();
            system.GetCore(i).PrepareReschedule();
        }
        Record("stopped", data);
        if (!replaying) stop_reason["sequence"] = event_sequence;
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
                if (!Wanted(IPC)) return;
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
        const auto category = CategoryOf(kind);
        if (notification && (notify_mask & category)) notification(data, category == STOP);
        if (history_mask & category) {
            if (events.size() == 1024) { events.pop_front(); ++events_lost; }
            events.push_back(data);
        }
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
    // Event categories (lotus#26). A category is built only while it is subscribed for
    // notification, kept for `events`/`logs` (history) or needed by the active run_until
    // predicate; stops are always kept. SVC, IPC and PICA events additionally need their
    // explicit switch (trace, gpu_configure).
    enum Category : u32 { STOP = 1, LOG = 2, NATIVE_LOG = 4, SVC = 8, IPC = 16, PICA = 32, ALL = 63 };
    static constexpr std::array<std::pair<const char*, u32>, 6> CATEGORIES{{
        {"stopped", STOP}, {"log", LOG}, {"native_log", NATIVE_LOG}, {"svc", SVC}, {"ipc", IPC}, {"pica", PICA}}};
    static u32 CategoryOf(std::string_view kind) {
        if (kind == "guest_log" || kind == "hio_stdout" || kind == "logpoint") return LOG;
        if (kind == "native_log") return NATIVE_LOG;
        if (kind == "svc_enter" || kind == "svc_exit") return SVC;
        if (kind == "ipc") return IPC;
        if (kind == "pica") return PICA;
        return STOP;
    }
    bool Wanted(u32 category) const {
        return ((notify_mask | history_mask | predicate_mask) & category) != 0;
    }
    static u32 Mask(const Json& names) {
        if (!names.is_array()) throw std::invalid_argument("event categories must be an array");
        u32 mask = 0;
        for (const auto& name : names) {
            const auto found = std::find_if(CATEGORIES.begin(), CATEGORIES.end(),
                [&](const auto& c) { return name.is_string() && name.get<std::string>() == c.first; });
            if (found == CATEGORIES.end()) throw std::invalid_argument("unknown event category");
            mask |= found->second;
        }
        return mask;
    }
    static Json Names(u32 mask) {
        Json names = Json::array();
        for (const auto& [name, bit] : CATEGORIES) if (mask & bit) names.push_back(name);
        return names;
    }
    // hello: `notifications` (bool, v0.0.3) enables every category unless `subscriptions`
    // lists them. events_configure: `notify` and/or `history`; omitted fields keep their value.
    Json ConfigureEvents(const Json& p, bool hello) {
        if (hello) {
            const bool enabled = p.is_object() && p.value("notifications", false);
            notify_mask = !enabled ? 0 : p.contains("subscriptions") ? Mask(p.at("subscriptions")) : ALL;
            if (p.is_object() && p.contains("history")) history_mask = Mask(p.at("history")) | STOP;
        } else {
            if (p.contains("notify")) notify_mask = Mask(p.at("notify"));
            if (p.contains("history")) history_mask = Mask(p.at("history")) | STOP;
        }
        return EventStatus();
    }
    Json EventStatus() const {
        return {{"notify", Names(notify_mask)}, {"history", Names(history_mask)},
                {"predicate", Names(predicate_mask)}, {"latest", event_sequence},
                {"history_lost_total", events_lost}, {"pending_lost_total", pending_lost.load()}};
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
    // Frame checkpoint due: every `history_interval` frames, after a restore (frame moved
    // back) and after an input change. Reverse replay restarts a window with the input held
    // at its checkpoint, so input must not change inside a window. No allocation.
    bool WantsFrameCheckpoint(u64 frame) const {
        if(!rewind_enabled)return false;
        if(history_force)return true; // may repeat a frame number: input changed mid-frame
        if(history_frame==frame)return false;
        return history_frame==~0ull || frame<history_frame || frame-history_frame>=history_interval;
    }
    void ForceCheckpoint() { history_force=true; }
    void Remember(u64 frame, const Json& input, std::optional<u32> core={}) {
        if(!rewind_enabled || (!core && !WantsFrameCheckpoint(frame)))return;
        if(!core)history_force=false;
        SettleHistory();
        if(system.Kernel().AreAsyncOperationsPending()){++lost.async_operations;return;}
        // Emulation-thread cost of this checkpoint: queue backpressure, serialization and,
        // with compression_queue 0, compression (lotus#32).
        const auto start=std::chrono::steady_clock::now();
        auto checkpoint=std::make_shared<Checkpoint>();
        checkpoint->level=history_level;
        if(history_queue){
            const u64 waited=compressor.WaitForSlot(history_queue);
            if(waited){++checkpoint_stats.backlog_waits;checkpoint_stats.backlog_wait_ns+=waited;}
            SettleHistory();
        }
        ArmWatches(false);
        const auto serialize_start=std::chrono::steady_clock::now();
        try {system.SerializeState(checkpoint->serialized);}catch(...){ArmWatches(true);throw;}
        ArmWatches(true);
        checkpoint_stats.serialize_ns+=Since(serialize_start);
        checkpoint->header=system.StateHeader();
        checkpoint->serialized_bytes=checkpoint->serialized.size();
        ++checkpoint_stats.count;checkpoint_stats.serialized_bytes+=checkpoint->serialized_bytes;
        while(!history.empty() && history.size()>=history_capacity){DropOldest();++lost.capacity;}
        std::map<u64,u64> hits;
        for (const auto& [id, bp] : breakpoints) hits[id] = bp.hits;
        history_frame=frame;
        history.push_back({checkpoint,frame,core,input,SettingsSnapshot(),Json::object(),0,std::move(hits),
                           skip_core,skip_pc});
        hits_untracked=false;
        if(history_queue)compressor.Submit(std::move(checkpoint));
        else {checkpoint->Compress();++checkpoint_stats.inline_compressions;}
        checkpoint_stats.sync_ns+=Since(start);
        SettleHistory();
    }
    static u64 Since(std::chrono::steady_clock::time_point start) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
    }
    void DropOldest() {
        history_bytes-=history.front().stored;history.pop_front();
    }
    void DropNewest() {
        history_bytes-=history.back().stored;history.pop_back();
    }
    // Accounts checkpoints whose compression finished, then applies the memory budget to the
    // stored (compressed) bytes, oldest first. Pending checkpoints are reported separately and
    // bounded by compression_queue. Emulation thread only.
    void SettleHistory() {
        for(auto& entry:history){
            if(entry.settled || !entry.state->done.load(std::memory_order_acquire))continue;
            entry.settled=true;entry.stored=entry.state->StoredBytes();history_bytes+=entry.stored;
            checkpoint_stats.compress_ns+=entry.state->compress_ns;checkpoint_stats.stored_bytes+=entry.stored;
            if(entry.state->failed)++checkpoint_stats.compress_failures;
        }
        // A checkpoint larger than the whole budget cannot be kept (the synchronous path
        // refused it); it is dropped and counted instead of evicting everything else.
        for(size_t i=0;i<history.size();){
            if(history[i].settled && history[i].stored>history_budget){
                history_bytes-=history[i].stored;history.erase(history.begin()+i);++lost.oversize;
            } else ++i;
        }
        while(history_bytes>history_budget && !history.empty()){DropOldest();++lost.budget;}
    }
    bool Restore(const HistoryEntry& entry) {
        const auto start=std::chrono::steady_clock::now();
        bool serialized=false;
        const bool ok=entry.state->Restore(system,serialized);
        ++checkpoint_stats.restores;checkpoint_stats.restores_serialized+=serialized;
        checkpoint_stats.restore_ns+=Since(start);
        return ok;
    }
    void MarkHistoryStop() { if(rewind_enabled && stopped && !history.empty())history.back().stop=stop_reason; }
    Json HistoryStatus() {
        SettleHistory();
        const auto load=compressor.Current();
        return {{"enabled",rewind_enabled},{"interval_frames",history_interval},{"snapshots",history.size()},{"bytes",history_bytes},
            {"capacity",history_capacity},{"budget_bytes",history_budget},
            {"lost_snapshots",lost.capacity+lost.budget+lost.async_operations+lost.oversize},
            // Why checkpoints were lost: evicted for capacity or the memory budget, not taken
            // while guest async operations were pending, or larger than the whole budget.
            {"lost",{{"capacity",lost.capacity},{"budget",lost.budget},{"async_operations",lost.async_operations},
                     {"oversize",lost.oversize}}},
            {"compression_level",history_level},
            // lotus#32: checkpoints waiting for or in compression on the worker's compression
            // thread and their serialized bytes, bounded by compression_queue.
            {"compression_queue",history_queue},{"compression_pending",load.pending},
            {"compression_pending_bytes",load.pending_bytes},{"compression_pending_peak_bytes",load.peak_pending_bytes},
            // Host nanoseconds since rewind_configure: checkpoint phases and restores.
            // checkpoint_sync_ns is all time spent on the emulation thread, including backlog
            // waits and, with compression_queue 0, compression. checkpoint_compress_ns counts
            // compression wherever it ran, for settled checkpoints.
            {"checkpoints",checkpoint_stats.count},{"checkpoint_serialize_ns",checkpoint_stats.serialize_ns},
            {"checkpoint_compress_ns",checkpoint_stats.compress_ns},
            {"checkpoint_sync_ns",checkpoint_stats.sync_ns},
            {"checkpoint_backlog_waits",checkpoint_stats.backlog_waits},
            {"checkpoint_backlog_wait_ns",checkpoint_stats.backlog_wait_ns},
            {"checkpoint_inline_compressions",checkpoint_stats.inline_compressions},
            {"checkpoint_compress_failures",checkpoint_stats.compress_failures},
            {"checkpoint_serialized_bytes",checkpoint_stats.serialized_bytes},
            {"checkpoint_stored_bytes",checkpoint_stats.stored_bytes},
            {"restores",checkpoint_stats.restores},{"restore_ns",checkpoint_stats.restore_ns},
            // Restores of a checkpoint still uncompressed: loaded without decompression.
            {"restores_serialized",checkpoint_stats.restores_serialized},
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
        if(!Restore(entry))throw std::runtime_error("rewind restore failed");
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
        while(history.size()>index)DropNewest();
        history_frame=~0ull;
        return result;
    }
    // Reverse continue: breakpoint/watchpoint stops are counted per rewind
    // checkpoint while running forward. Replaying a checkpoint with instruction
    // stepping reproduces the same hit sequence; a watchpoint target is replayed
    // a second time to the instruction index of its access, so the session lands
    // before the access executes.
    // Hits counted under another breakpoint set cannot be replayed. A replay from an older
    // checkpoint would count executions from before the change as hits, so hits stay
    // uncounted until the next checkpoint opens a window under the current set.
    void ForgetHits() {
        for (auto& entry : history) entry.window_hits = 0;
        position_at_hit = false;
        if (rewind_enabled) { hits_untracked = true; ForceCheckpoint(); }
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
        if (rewind_enabled && !history.empty() && !hits_untracked) ++history.back().window_hits;
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
        if (!Restore(entry)) throw std::runtime_error("rewind restore failed");
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
        // A checkpoint taken while resuming from an execute breakpoint must not re-hit it on replay.
        skip_core = entry.skip_core;
        skip_pc = entry.skip_pc;
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
            system.SerializeState(present);
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
            system.LoadStateSerialized(present);
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
        while (history.size() > k + 1) DropNewest();
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
    std::function<void(const Json&, bool reliable)> notification;
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
    // Per-component hashes of the paused guest, for finding the first state two runs disagree
    // on (lotus#29). `memory`: FCRAM, VRAM, DSP RAM and New 3DS extra RAM in `chunk_kib`
    // pieces, so a difference has a physical address. `cpu`: each core's context and timer.
    // `sections`: each top-level part of System::serialize (timing queue, services, archives,
    // DSP, memory with page tables, kernel, GPU); skipped while an async HLE operation runs on
    // a host thread, which save_state refuses for the same reason. Serializing has a save's side
    // effects (GPU cache flush, cross-thread timing events queued), as a rewind checkpoint does,
    // so runs being compared must all hash at the same frames.
    // `dump`: also write the serialized bytes and section offsets to <root>/state-dumps/<dump>.bin
    // and .json, for comparing the bytes of a differing section.
    Json StateHash(u32 chunk_kib, bool sections, const std::string& dump) {
        if (chunk_kib < 4 || chunk_kib > 65536 || (chunk_kib & (chunk_kib - 1)))
            throw std::invalid_argument("chunk_kib: power of two, 4..65536");
        const auto hex = [](u64 value) { return fmt::format("{:016x}", value); };
        const bool n3ds = Settings::values.is_new_3ds.GetValue();
        const size_t chunk = size_t(chunk_kib) << 10;
        Json memory = Json::object();
        const auto region = [&](const char* name, PAddr base, size_t size) {
            if (!size) return;
            const u8* data = system.Memory().GetPhysicalPointer(base);
            if (!data) throw std::runtime_error("unmapped physical region");
            Json chunks = Json::array();
            for (size_t offset = 0; offset < size; offset += chunk)
                chunks.push_back(hex(Common::ComputeHash64(data + offset, std::min(chunk, size - offset))));
            memory[name] = {{"base", base}, {"size", size}, {"chunks", chunks}};
        };
        region("fcram", Memory::FCRAM_PADDR, n3ds ? Memory::FCRAM_N3DS_SIZE : Memory::FCRAM_SIZE);
        region("vram", Memory::VRAM_PADDR, Memory::VRAM_SIZE);
        region("dsp_ram", Memory::DSP_RAM_PADDR, Memory::DSP_RAM_SIZE);
        region("n3ds_extra_ram", Memory::N3DS_EXTRA_RAM_PADDR, n3ds ? Memory::N3DS_EXTRA_RAM_SIZE : 0);
        Json cpu = Json::array();
        for (u32 id = 0; id < system.GetNumCores(); ++id) {
            Core::ARM_Interface::ThreadContext context;
            system.GetCore(id).SaveContext(context);
            const auto thread = system.Kernel().GetThreadManager(id).GetCurrentThread();
            const auto timer = system.CoreTiming().GetTimer(id);
            const auto state = Json{context.cpu_registers, context.cpsr, context.fpu_registers,
                                    context.fpscr, context.fpexc}.dump();
            cpu.push_back({{"core", id}, {"pc", context.cpu_registers[15]},
                {"thread", thread ? thread->thread_id : 0}, {"ticks", timer->GetTicks()},
                {"idle_ticks", timer->GetIdleTicks()},
                {"context", hex(Common::ComputeHash64(state.data(), state.size()))}});
        }
        const bool async_pending = system.Kernel().AreAsyncOperationsPending();
        Json result = {{"guest_ticks", system.CoreTiming().GetGlobalTicks()}, {"cpu", cpu},
            {"memory", memory}, {"chunk_kib", chunk_kib}, {"async_pending", async_pending},
            {"sections", nullptr}};
        if (sections && !async_pending) {
            std::vector<u8> bytes;
            std::vector<std::pair<const char*, std::size_t>> marks;
            ArmWatches(false);
            try { system.SerializeSections(bytes, marks); } catch (...) { ArmWatches(true); throw; }
            ArmWatches(true);
            Json list = Json::array();
            std::size_t start = 0;
            for (const auto& [name, end] : marks) {
                list.push_back({{"name", name}, {"bytes", end - start},
                    {"hash", hex(Common::ComputeHash64(bytes.data() + start, end - start))}});
                start = end;
            }
            result["sections"] = list;
            result["serialized_hash"] = hex(Common::ComputeHash64(bytes.data(), bytes.size()));
            if (!dump.empty()) {
                if (dump.size() > 32 || dump.find_first_not_of(
                        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != std::string::npos)
                    throw std::invalid_argument("invalid dump name");
                const auto directory = root / "state-dumps";
                std::filesystem::create_directories(directory);
                std::ofstream file(directory / (dump + ".bin"), std::ios::binary | std::ios::trunc);
                file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                file.close();
                if (!file) throw std::runtime_error(fmt::format("dump .bin: {}", std::strerror(errno)));
                std::ofstream offsets(directory / (dump + ".json"));
                offsets << list.dump();
                offsets.close();
                if (!offsets) throw std::runtime_error(fmt::format("dump .json: {}", std::strerror(errno)));
                result["dump"] = (directory / (dump + ".bin")).string();
            }
        }
        return result;
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
                    // A movie carries its console identity (CFG save data, e.g. the
                    // per-root random console ID); apply it, roll back on mismatch.
                    std::vector<std::pair<SettingBinding*,Json>> previous;
                    const auto& recorded=meta.at("settings");
                    for(auto& b:bindings)
                        if(std::string{b.apply}=="cfg-savedata"&&recorded.contains(b.name)&&recorded.at(b.name)!=b.get()) {
                            previous.emplace_back(&b,b.get());b.set(recorded.at(b.name));
                        }
                    if(meta.at("source")!=CTR_SOURCE_SHA || recorded!=SettingsSnapshot()) {
                        for(auto it=previous.rbegin();it!=previous.rend();++it)it->first->set(it->second);
                        throw std::invalid_argument("movie profile or pin mismatch");
                    }
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
                    throw std::invalid_argument(std::string{it->apply} + " setting requires an unloaded session");
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
            const bool enabled = p.at("enabled").get<bool>();
            const auto capture = enabled ? AudioCore::WorkerSink::CaptureStart(root / "audio/capture.wav") :
                                           AudioCore::WorkerSink::CaptureStop();
            Json result = {{"path", "audio/capture.wav"}, {"pcm_bytes", capture.pcm_bytes},
                    {"state", capture.Name()}, {"limit_reached", capture.limit_reached},
                    {"queue_overflow", capture.queue_overflow},
                    {"queued_pcm_bytes", capture.queued_bytes},
                    {"queue_peak_pcm_bytes", capture.queue_peak_bytes},
                    {"queue_capacity_pcm_bytes", AudioCore::WorkerWavCapture::queue_capacity},
                    {"dropped_blocks", capture.dropped_blocks}, {"dropped_frames", capture.dropped_frames},
                    {"sample_rate", AudioCore::native_sample_rate}, {"channels", 2}, {"sample_format", "s16le"},
                    {"domain", "raw_DSP_before_host_volume_and_stretching"}};
            if (capture.error)
                result["error"] = capture.error;
            if (!enabled && capture.Published())
                result["artifacts"]=Json::array({{{"path","audio/capture.wav"},{"format","wav"}}});
            return result;
        }
#ifdef CTR_EXPERIMENTAL
        // Before content too: a host subscribes once, at hello or right after.
        if (op == "events_configure") return ConfigureEvents(p, false);
#endif
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
            if (op == "state_hash") return StateHash(p.value("chunk_kib", 1024u), p.value("sections", true), p.value("dump", std::string{}));
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
                predicate_mask=kind=="log"?LOG|NATIVE_LOG:kind=="svc"?SVC:kind=="draw"?PICA:0;
                SyncExecution();
                return {{"resume_requested",true},{"budget_frames",frames},{"timeout_ms",timeout},{"predicate",predicate}};
            }
            if(op=="rewind_configure") {
                const auto capacity=p.at("capacity").get<u32>(),budget=p.at("budget_mib").get<u32>();
                if(!capacity||capacity>128||budget<16||budget>256)throw std::invalid_argument("invalid rewind budget");
                const auto interval=p.value("interval_frames",1u);
                if(!interval||interval>60)throw std::invalid_argument("rewind interval 1..60 frames");
                // zstd level of rewind checkpoints only; every level restores the same state.
                const auto level=p.value("compression_level",3);
                if(level<-7||level>19)throw std::invalid_argument("rewind compression_level -7..19");
                // Checkpoints compressed off the emulation thread at once (lotus#32); 0
                // compresses each one on the emulation thread.
                const auto queue=p.value("compression_queue",1u);
                if(queue>4)throw std::invalid_argument("rewind compression_queue 0..4");
                rewind_enabled=p.at("enabled");history_capacity=capacity;history_budget=u64(budget)<<20;
                history_interval=interval;history_force=false;history_level=level;history_queue=queue;checkpoint_stats={};
                history.clear();
                compressor.Reset();
                history_bytes=0;lost={};history_frame=~0ull;return HistoryStatus();
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
                return {{"breakpoints", result},
                        {"execution_mode", DebugChannel::single_step ? "instruction_step" : "jit"},
                        {"execute_breakpoints", "jit_block_split"},
                        {"watchpoints", "instruction_step_when_armed"},
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
                SyncExecution();
                return {{"id", id},
                        {"execution_mode", DebugChannel::single_step ? "instruction_step" : "jit"},
                        {"cost", kind == "execute"
                                     ? "low; JIT block ends and halts at the address, single-steps it"
                                     : "high; single instruction dispatch while a watchpoint is armed"}};
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
                SyncExecution();
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
        std::shared_ptr<Checkpoint> state;u64 frame;std::optional<u32> core;Json input,settings,stop;
        u64 window_hits=0;            // breakpoint/watchpoint stops observed after this checkpoint
        std::map<u64,u64> bp_hits;    // breakpoint hit counters at this checkpoint
        u32 skip_core=0xffffffff, skip_pc=0; // resume-from-breakpoint skip in effect at this checkpoint
        bool settled=false;           // compression finished and `stored` is in history_bytes
        u64 stored=0;
    };
    bool hits_untracked=false;        // breakpoint set changed since the newest checkpoint
    bool replaying=false, position_at_hit=false;
    u64 replay_target=0, replay_hits=0, replay_instructions=0, replay_halt_instruction=~0ull, replay_hit_instruction=0;
    Json replay_hit;
    std::deque<HistoryEntry> history;
    CheckpointCompressor compressor; // lotus#32; skips checkpoints the history has dropped
    bool rewind_enabled=false;
    size_t history_capacity=32;
    u64 history_bytes=0,history_budget=64u<<20,history_frame=~0ull,history_interval=1;
    int history_level=3; // ZSTD_CLEVEL_DEFAULT, what SaveStateBuffer() uses
    u32 history_queue=1;
    struct {u64 count=0,serialize_ns=0,compress_ns=0,sync_ns=0,backlog_waits=0,backlog_wait_ns=0,inline_compressions=0,
            compress_failures=0,serialized_bytes=0,stored_bytes=0,restores=0,restores_serialized=0,restore_ns=0;} checkpoint_stats;
    struct {u64 capacity=0,budget=0,async_operations=0,oversize=0;} lost;
    bool history_force=false;
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
    // Read by the native log observer on logging threads.
    std::atomic<u32> notify_mask{0}, history_mask{ALL}, predicate_mask{0};
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
