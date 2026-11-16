// CiTrace v1 GPU action replay. The paired checkpoint preserves LUTs and other
// initial GPU state absent from the upstream v1 header. CPU execution stays held.
#pragma once
#include <map>
#include "common/hash.h"
#include "core/tracer/recorder.h"
#include "core/frontend/debug_channel.h"
#include "video_core/gpu.h"
#include "video_core/pica/pica_core.h"
#include "video_core/renderer_base.h"

namespace CtrWorker {
class GpuTrace {
public:
    using Json = nlohmann::json;
    GpuTrace(Core::System& system, const std::filesystem::path& root) : system(system),root(root) {
        DebugChannel::gpu_action=[this](u32 action,u32 index){Action(action,index);};
    }
    ~GpuTrace(){DebugChannel::gpu_action={};}
    void Clear(){recorder.reset();pages.clear();frames=0;replay_view=false;}
    bool IsReplayView() const {return replay_view;}
    Json Start() {
        Clear();
        CiTrace::Recorder::InitialState initial;
        auto& pica=system.GPU().PicaCore();
        const auto copy=[](std::vector<u32>& dest,const auto& source){
            static_assert(sizeof(source)%4==0);
            dest.resize(sizeof(source)/4);std::memcpy(dest.data(),&source,sizeof(source));
        };
        copy(initial.pica_registers,pica.regs);copy(initial.lcd_registers,pica.regs_lcd);
        copy(initial.vs_program_binary,pica.vs_setup.GetProgramCode());
        copy(initial.vs_swizzle_data,pica.vs_setup.GetSwizzleData());
        // The checkpoint, not these optional v1 fields, restores packed float24,
        // default attributes, geometry pipeline and LUT state without conversion.
        recorder=std::make_unique<CiTrace::Recorder>(initial);
        return Status();
    }
    Json Status() const {
        return {{"gpu_replay_view",replay_view},{"recording",bool(recorder)},{"frames",frames},
            {"elements",recorder?recorder->Elements():0},{"data_bytes",recorder?recorder->DataBytes():0},
            {"dropped",recorder?recorder->Dropped():0},{"truncated",recorder&&recorder->Truncated()},
            {"element_cap",262144},{"data_budget_bytes",48u<<20},
            {"capture_cost","opt-in full GPU-visible memory page scan per GPU action"},
            {"initial_state","paired lotus-citrace checkpoint; includes LUTs and shader state"}};
    }
    Json Stop() {
        if(!recorder)throw std::invalid_argument("no active CiTrace recording");
        Action(4,0); // Preserve final buffer swaps and CPU writes after the last VBlank.
        auto result=Status();
        std::filesystem::create_directories(root/"gpu");
        recorder->Finish((root/"gpu/trace.ctf").string());
        std::ifstream saved(root/"gpu/trace.ctf",std::ios::binary);
        std::vector<u8> bytes((std::istreambuf_iterator<char>(saved)),{});
        std::ofstream metadata(root/"gpu/trace.json");metadata.exceptions(std::ios::badbit|std::ios::failbit);
        metadata<<Json{{"content_xxh3_64",Common::ComputeHash64(bytes.data(),bytes.size())},
            {"truncated",recorder->Truncated()},{"checkpoint","lotus-citrace"}}.dump();metadata.close();
        result["artifacts"]=Json::array({{{"path","gpu/trace.ctf"},{"format","citrace"}}});
        recorder.reset();pages.clear();result["recording"]=false;return result;
    }
    static bool PhysicalRange(u32 address,u32 size,bool new3ds) {
        const u64 end=u64(address)+size;
        return size&&((address>=Memory::VRAM_PADDR&&end<=u64(Memory::VRAM_PADDR)+Memory::VRAM_SIZE)||
            (address>=Memory::FCRAM_PADDR&&end<=u64(Memory::FCRAM_PADDR)+(new3ds?Memory::FCRAM_N3DS_SIZE:Memory::FCRAM_SIZE)));
    }
    struct Validated {
        std::vector<u8> bytes;
        CiTrace::CTHeader header;
        std::vector<CiTrace::CTStreamElement> stream;
    };
    Validated Read() {
        const auto path=root/"gpu/trace.ctf";
        const auto size=std::filesystem::file_size(path);
        if(size<sizeof(CiTrace::CTHeader)||size>(64u<<20))throw std::invalid_argument("CiTrace file size budget");
        Validated trace;trace.bytes.resize(size);
        std::ifstream file(path,std::ios::binary);file.exceptions(std::ios::badbit|std::ios::failbit);
        file.read(reinterpret_cast<char*>(trace.bytes.data()),size);
        Json metadata;std::ifstream(root/"gpu/trace.json")>>metadata;
        if(metadata.value("truncated",true)||metadata.at("content_xxh3_64").get<u64>()!=Common::ComputeHash64(trace.bytes.data(),trace.bytes.size()))
            throw std::invalid_argument("truncated or modified CiTrace recording");
        std::memcpy(&trace.header,trace.bytes.data(),sizeof(trace.header));
        const auto& h=trace.header;
        if(std::memcmp(h.magic,"CiTr",4)||h.version!=1||h.header_size!=sizeof(h)||h.stream_size>262144||
            h.stream_offset<sizeof(h)||u64(h.stream_offset)+u64(h.stream_size)*sizeof(CiTrace::CTStreamElement)!=size)
            throw std::invalid_argument("invalid CiTrace header/stream bounds");
        std::array<u32,20> ranges{};std::memcpy(ranges.data(),&h.initial_state_offsets,sizeof(ranges));
        for(u32 i=0;i<20;i+=2)if(ranges[i]<sizeof(h)||u64(ranges[i])+u64(ranges[i+1])*4>h.stream_offset)
            throw std::invalid_argument("invalid CiTrace initial-state bounds");
        trace.stream.resize(h.stream_size);
        std::memcpy(trace.stream.data(),trace.bytes.data()+h.stream_offset,trace.stream.size()*sizeof(CiTrace::CTStreamElement));
        for(const auto& entry:trace.stream) {
            if(entry.type==CiTrace::MemoryLoad) {
                const auto& m=entry.memory_load;
                if(m.size>4096||m.file_offset<sizeof(h)||u64(m.file_offset)+m.size>h.stream_offset||
                    !PhysicalRange(m.physical_address,m.size,Settings::values.is_new_3ds.GetValue()))
                    throw std::invalid_argument("invalid CiTrace physical memory load");
            } else if(entry.type==CiTrace::RegisterWrite) {
                const auto a=entry.register_write.physical_address;
                if((a&3)||!((a>=0x10400000&&a<0x10400000+sizeof(Pica::PicaCore::Regs))||
                    (a>=0x10202000&&a<0x10202000+sizeof(Pica::RegsLcd))))
                    throw std::invalid_argument("invalid CiTrace register address");
            } else if(entry.type!=CiTrace::FrameMarker)throw std::invalid_argument("invalid CiTrace stream opcode");
        }
        return trace;
    }
    Json Replay(const Validated& trace) {
        Clear();u64 replay_frames=0,loads=0,writes=0;
        auto& gpu=system.GPU();auto& pica=gpu.PicaCore();
        for(const auto& entry:trace.stream) {
            if(entry.type==CiTrace::MemoryLoad) {
                const auto& m=entry.memory_load;
                auto* dest=system.Memory().GetPhysicalPointer(m.physical_address);
                if(!dest||system.Memory().GetPhysicalPointer(m.physical_address+m.size-1)!=dest+m.size-1)
                    throw std::invalid_argument("CiTrace memory unavailable in this profile");
                gpu.FlushRegion(m.physical_address,m.size);
                gpu.InvalidateRegion(m.physical_address,m.size);
                std::memcpy(dest,trace.bytes.data()+m.file_offset,m.size);++loads;
            } else if(entry.type==CiTrace::RegisterWrite) {
                const auto a=entry.register_write.physical_address,v=entry.register_write.value;
                gpu.WriteReg(a+0x0eb00000,v);
                pica.dirty_regs.SetAllDirty();++writes;
            } else {gpu.Renderer().SwapBuffers();++replay_frames;}
        }
        replay_view=true;
        return {{"cpu_resume_requires","load_state or reset"},{"frames",replay_frames},{"memory_loads",loads},{"register_writes",writes},
            {"format","CiTrace v1 + paired checkpoint"},{"cpu_executed",false},
            {"rasterizer_cache_flush",true}};
    }
private:
    bool Trigger(u32 index)const {
        return index==GPU_REG_INDEX(memory_fill_config[0].trigger)||index==GPU_REG_INDEX(memory_fill_config[1].trigger)||
            index==GPU_REG_INDEX(display_transfer_config.trigger)||
            index==GPU_REG_INDEX(internal.pipeline.command_buffer.trigger[0])||
            index==GPU_REG_INDEX(internal.pipeline.command_buffer.trigger[1]);
    }
    void Action(u32 action,u32 index) {
        if(!recorder||recorder->Truncated())return;
        auto& gpu=system.GPU();auto& pica=gpu.PicaCore();
        // Flush before observing pages; the scan also captures CPU updates and
        // DMA results that bypass MMIO. Unchanged pages add no stream entries.
        for(const auto [base,size]:{std::pair<u32,u32>{Memory::VRAM_PADDR,Memory::VRAM_SIZE},
            {Memory::FCRAM_PADDR,Settings::values.is_new_3ds?Memory::FCRAM_N3DS_SIZE:Memory::FCRAM_SIZE}}) {
            gpu.FlushRegion(base,size);
            for(u32 offset=0;offset<size;offset+=4096) {
                const auto address=base+offset;const auto* data=system.Memory().GetPhysicalPointer(address);
                if(!data)continue;
                const auto hash=Common::ComputeHash64(data,4096);
                auto found=pages.find(address);
                if(found!=pages.end()&&found->second==hash)continue;
                // Post-action scans establish GPU-produced output as the baseline.
                // Re-inject only subsequent CPU changes; replaying GPU outputs as
                // inputs would destroy Vulkan render-target precision/cache state.
                if(action<5)recorder->MemoryAccessed(data,4096,address);
                pages[address]=hash;
                if(recorder->Truncated())return;
            }
        }
        if(action>=5)return;
        // Emit configuration before the trigger; all other triggers are omitted.
        for(u32 i=0;i<pica.regs.reg_array.size();++i)if(!Trigger(i))
            recorder->RegisterWritten(0x10400000+i*4,pica.regs.reg_array[i]);
        for(u32 i=0;i<Pica::RegsLcd::NumIds();++i)recorder->RegisterWritten(0x10202000+i*4,pica.regs_lcd[i]);
        if(action==0){recorder->FrameFinished();++frames;return;}
        if(action==4)return;
        const u32 trigger=action==1?GPU_REG_INDEX(internal.pipeline.command_buffer.trigger[0])+index:
            action==2?GPU_REG_INDEX(memory_fill_config[0].trigger)+index*4:GPU_REG_INDEX(display_transfer_config.trigger);
        recorder->RegisterWritten(0x10400000+trigger*4,pica.regs.reg_array[trigger]);
    }
    Core::System& system;std::filesystem::path root;
    std::unique_ptr<CiTrace::Recorder> recorder;
    std::map<u32,u64> pages;
    u64 frames=0;
    bool replay_view=false;
};
} // namespace CtrWorker
