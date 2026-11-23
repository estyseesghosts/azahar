// Worker-side settings and safe-point inspection. No product/UI dependencies.
#pragma once
#include <algorithm>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include "ctr_worker/settings_bindings.h"
#include "audio_core/worker_sink.h"
#include "audio_core/injected_input.h"
#include "core/hle/service/mic/mic_u.h"
#include "core/hle/service/nfc/nfc.h"
#include "ctr_worker/camera.h"
#include "core/core.h"
#include "core/core_timing.h"
#include "core/hle/kernel/thread.h"
#include "core/hle/kernel/mutex.h"
#include "core/perf_stats.h"
#include "core/hle/service/cfg/cfg.h"
#include "core/hle/service/cfg/cfg_defaults.h"

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
        EnsureSettings();
        const auto op = p.at("operation").get<std::string>();
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
        if (!system.IsPoweredOn()) throw std::runtime_error("load content first");
        const bool paused = state == "paused";
        Json result;
        if (op == "registers") result = Registers(p.at("core").get<u32>());
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
            if (!paused) throw std::invalid_argument("mutation requires paused execution");
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
                        const auto bytes = system.SaveStateBuffer();
                        if (bytes.size() > (256u << 20)) throw std::runtime_error("checkpoint exceeds 256 MiB");
                        std::ofstream file(path, std::ios::binary | std::ios::trunc);
                        file.exceptions(std::ios::failbit | std::ios::badbit);
                        file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
                        std::ofstream meta(metadata);
                        meta.exceptions(std::ios::failbit | std::ios::badbit);
                        meta << Json{{"source", CTR_SOURCE_SHA}, {"settings", SettingsSnapshot()}}.dump();
                    } else {
                        Json meta;
                        std::ifstream(metadata) >> meta;
                        if (meta.at("source") != CTR_SOURCE_SHA || meta.at("settings") != SettingsSnapshot())
                            throw std::invalid_argument("checkpoint pin or settings mismatch");
                        const auto size = std::filesystem::file_size(path);
                        if (size > (256u << 20)) throw std::invalid_argument("checkpoint exceeds budget");
                        std::vector<u8> bytes(size);
                        std::ifstream file(path, std::ios::binary);
                        file.exceptions(std::ios::failbit | std::ios::badbit);
                        file.read(reinterpret_cast<char*>(bytes.data()), size);
                        if (!system.LoadStateBuffer(std::move(bytes))) throw std::runtime_error("checkpoint load failed");
                        for (u32 i = 0; i < system.GetNumCores(); ++i) system.GetCore(i).ClearInstructionCache();
                    }
                    result = {{"name", name}, {"source", CTR_SOURCE_SHA}};
                }
            } else if (op == "backtrace") {
                const auto id = p.at("core").get<u32>(), limit = p.at("limit").get<u32>();
                if (limit == 0 || limit > 128 || id >= system.GetNumCores())
                    throw std::invalid_argument("invalid backtrace bounds");
                auto& core = system.GetCore(id);
                Json frames = Json::array({{{"pc", core.GetPC()}, {"sp", core.GetReg(13)}}});
                u32 fp = core.GetReg((core.GetCPSR() & 32) ? 7 : 11);
                std::set<u32> visited;
                for (u32 i = 1; i < limit && fp >= 12 && visited.insert(fp).second; ++i) {
                    try {
                        const auto bytes = Read(fp - 12, 16);
                        u32 next, sp, lr;
                        std::memcpy(&next, bytes.data(), 4);
                        std::memcpy(&sp, bytes.data() + 4, 4);
                        std::memcpy(&lr, bytes.data() + 8, 4);
                        if (!lr || next <= fp || next - fp > (1 << 20)) break;
                        frames.push_back({{"pc", lr}, {"sp", sp}, {"frame_pointer", fp}});
                        fp = next;
                    } catch (const std::exception&) { break; }
                }
                result = {{"frames", frames}, {"unwind", "APCS_frame_pointer"},
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
    Core::System& system;
    std::filesystem::path root;
    std::vector<SettingBinding> bindings;
    std::deque<std::string> cfg_names;
    std::shared_ptr<Service::CFG::Module> boot_cfg;
    bool cfg_bound = false;
};
} // namespace CtrWorker
