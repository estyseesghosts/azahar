// Frozen GPU observations at native PICA event boundaries; no renderer-thread waits.
//
// gpu_configure selects how much work capture puts on the emulation thread (lotus#24):
// - counters: no debug context, so PicaCore keeps its batched command path; reports
//   command lists, draws and fast-path commands only.
// - events:   per-command PICA events recorded (bounded event buffer), draw metadata only.
// - draws:    events plus snapshots of selected draws (draw_range, max_draws budget);
//             resources only with resources=true.
// - full:     every draw snapshotted with its resources (the behaviour before #24, and the
//             default when `capture` is omitted).
// A snapshot copies what the draw used at the IncomingPrimitiveBatch boundary: registers,
// shader setup and, if requested, texture/index/vertex bytes after a rasterizer FlushRegion.
// Those copies and the resource hash are the synchronous cost. Hex, JSON and the artifact
// file are produced only when gpu_draw asks for that draw, never per draw.
#pragma once
#include <bitset>
#include <bit>
#include <fstream>
#include <tuple>
#include "common/hash.h"
#include "core/frontend/debug_channel.h"
#include "video_core/debug_utils/debug_utils.h"
#include "video_core/gpu.h"
#include "video_core/pica/pica_core.h"
#include "video_core/renderer_base.h"
#include "video_core/shader/shader_interpreter.h"
#include "video_core/texture/texture_decode.h"

namespace CtrWorker {
class GpuTools {
    struct Snapshot;
    struct Draw;
public:
    using Json=nlohmann::json;
    using Callback=std::function<void(const char*,Json)>;
    GpuTools(Core::System& system,const std::filesystem::path& root,Callback record,Callback stop)
        :system(system),root(root),record(std::move(record)),stop(std::move(stop)),
         context(Pica::DebugContext::Construct()) {
        // Pica::g_debug_context stays null: a context captured at GPU construction would keep
        // PicaCore on its per-command path (pica_core.cpp, ProcessCmdList `if (!debug_context)`)
        // for the whole session. The context is attached only while capture is enabled.
        DebugChannel::gpu_event=[this](u32 event,const void* data){Event(event,data);};
    }
    ~GpuTools(){Activate(false);DebugChannel::gpu_event={};}
    std::function<bool()> wants_events;
    // Emulation-thread safe point only (worker dispatch runs between RunLoop calls).
    void Activate(bool on) {
        if(system.IsPoweredOn())system.GPU().SetDebugContext(on?context:nullptr);
        if(!on){DebugChannel::gpu_vertex_output={};return;}
        DebugChannel::gpu_vertex_output=[this](const void* data){
            if(enabled&&(!halted||collect_stop_inputs)&&data&&!draws.empty()&&draws.back().snapshot) {
                auto& outputs=draws.back().outputs;if(outputs.size()<8) {
                    Pica::AttributeBuffer sanitized{};const auto* values=static_cast<const Pica::AttributeBuffer*>(data);
                    const auto count=std::popcount(this->system.GPU().PicaCore().regs.internal.vs.output_mask.Value());
                    for(u32 i=0;i<std::min<u32>(count,16);++i)sanitized[i]=(*values)[i];outputs.push_back(sanitized);
                }
            }
        };
    }
    void Clear(){Activate(false);enabled=false;breaks.reset();draws.clear();draw_sequence=command_sequence=resource_sequence=0;resources.clear();halted=false;
        snapshots_taken=snapshots_skipped=0;}
    void Resume(){halted=false;collect_stop_inputs=false;}
    std::vector<u8> Physical(u32 address,u32 length) {
        if(!length||length>(4u<<20)||u64(address)+length>0x100000000ull)
            throw std::invalid_argument("invalid physical capture range");
        auto& memory=system.Memory();
        const auto first=memory.GetPhysicalPointer(address);
        const auto last=memory.GetPhysicalPointer(address+length-1);
        if(!first||last!=first+length-1)throw std::invalid_argument("physical range crosses a memory region");
        system.GPU().Renderer().Rasterizer()->FlushRegion(address,length);
        return std::vector<u8>(first,first+length);
    }
    u64 FastPathCommands() const {return system.IsPoweredOn()?system.GPU().PicaCore().fast_path_commands:0;}
    Json Counters() const {
        if(!system.IsPoweredOn())return {{"fast_path_commands",0},{"command_lists",0},{"draw_calls",0}};
        const auto& pica=system.GPU().PicaCore();
        return {{"fast_path_commands",pica.fast_path_commands},{"command_lists",pica.command_lists},{"draw_calls",pica.draw_calls}};
    }
    static u64 Hash(const std::vector<u8>& bytes){return Common::ComputeHash64(bytes.data(),bytes.size());}
    struct ResourceCopy {u32 address,length;std::string kind;Json extra;std::vector<u8> bytes;u64 hash,version;Json aliases;};
    ResourceCopy Resource(u32 address,u32 length,const char* kind) {
        auto bytes=Physical(address,length);
        const auto hash=Hash(bytes);const auto key=std::make_tuple(address,length,std::string(kind));
        auto found=resources.find(key);
        if(found==resources.end()||found->second.first!=hash) {
            if(found==resources.end()&&resources.size()==128){resources.erase(resources.begin());++resource_versions_lost;}
            resources[key]={hash,++resource_sequence};
        }
        Json aliases=Json::array();const auto process=system.Kernel().GetCurrentProcess();
        if(process)for(auto alias:system.Memory().PhysicalToVirtualAddressForRasterizer(address))
            if(system.Memory().IsValidVirtualAddress(*process,alias)&&system.Memory().IsValidVirtualAddress(*process,alias+length-1))aliases.push_back(alias);
        return {address,length,kind,Json::object(),std::move(bytes),hash,resources.at(key).second,std::move(aliases)};
    }
    static Json ResourceJson(const ResourceCopy& r) {
        Json out={{"address",r.address},{"virtual_aliases",r.aliases},{"bytes",r.length},{"kind",r.kind},
                  {"content_xxh3_64",r.hash},{"version",r.version},
                  {"data_hex",Hex(r.bytes)},{"rasterizer_cache_flush",true}};
        for(const auto& [key,value]:r.extra.items())out[key]=value;
        return out;
    }
    static std::string Hex(std::span<const u8> bytes) {
        static constexpr char chars[]="0123456789abcdef";std::string text;text.reserve(bytes.size()*2);
        for(auto b:bytes){text+=chars[b>>4];text+=chars[b&15];}return text;
    }
    template<class T> static Json Vectors(const T& values) {
        Json out=Json::array();
        for(const auto& vector:values) {
            Json v=Json::array();for(unsigned c=0;c<4;++c)v.push_back(std::bit_cast<u32>(vector[c].ToFloat32()));
            out.push_back(v);
        }
        return out;
    }
    Json Artifact(const std::filesystem::path& relative,const Json& data) {
        std::filesystem::create_directories((root/relative).parent_path());
        std::ofstream file(root/relative,std::ios::binary|std::ios::trunc);
        file.exceptions(std::ios::badbit|std::ios::failbit);
        file<<data.dump(-1,' ',false,Json::error_handler_t::replace);file.close();
        return {{"path",relative.generic_string()},{"format","json"}};
    }
    bool WantsSnapshot(u64 id) {
        if(capture==Capture::Full)return true;
        if(capture!=Capture::Draws)return false;
        if(draw_range&&(id<draw_range->first||id>draw_range->second))return false;
        if(snapshots_taken>=max_draws){++snapshots_skipped;return false;}
        return true;
    }
    void FreezeDraw(bool indexed) {
        auto& pica=system.GPU().PicaCore();
        Draw draw;draw.id=++draw_sequence;
        draw.meta={{"draw",draw.id},{"command",command_sequence},{"guest_ticks",system.CoreTiming().GetGlobalTicks()},
            {"capture_boundary","incoming_primitive_batch"},
            {"indexed",indexed},{"vertex_count",pica.regs.internal.pipeline.num_vertices},
            {"vertex_input_attributes",pica.regs.internal.vs.max_input_attribute_index.Value()+1},
            {"vertex_output_attributes",std::popcount(pica.regs.internal.vs.output_mask.Value())}};
        if(WantsSnapshot(draw.id)) {
            ++snapshots_taken;
            auto snapshot=std::make_unique<Snapshot>();
            snapshot->setup=pica.vs_setup;snapshot->config=pica.regs.internal.vs;
            snapshot->registers.assign(std::begin(pica.regs.reg_array),std::end(pica.regs.reg_array));
            if(capture==Capture::Full||capture_resources)CaptureResources(indexed,*snapshot);
            draw.snapshot=std::move(snapshot);
        }
        if(draws.size()==8){draws.pop_front();++draws_lost;}
        draws.push_back(std::move(draw));
    }
    void CaptureResources(bool indexed,Snapshot& snapshot) {
        auto& pica=system.GPU().PicaCore();
        auto& notes=snapshot.notes;
        u64 budget=4u<<20;
        for(const auto& texture:pica.regs.internal.texturing.GetTextures()) {
            if(!texture.enabled)continue;
            const auto info=Pica::Texture::TextureInfo::FromPicaRegister(texture.config,texture.format);
            const u64 size=Pica::Texture::CalculateTileSize(info.format)*((info.width+7)/8)*((info.height+7)/8);
            if(!size||size>budget) {notes["resource_budget_exhausted"]=true;continue;}
            try {
                auto resource=Resource(info.physical_address,static_cast<u32>(size),"texture");
                resource.extra={{"width",info.width},{"height",info.height},{"format",static_cast<u32>(info.format)}};
                snapshot.resources.push_back(std::move(resource));budget-=size;
            } catch(const std::exception& e){snapshot.failed.push_back({{"address",info.physical_address},{"error",e.what()}});}
        }
        const auto& pipeline=pica.regs.internal.pipeline;
        u64 min_vertex=pipeline.vertex_offset,max_vertex=min_vertex+pipeline.num_vertices;
        bool span_valid=pipeline.num_vertices>0;
        if(indexed&&span_valid) {
            const u32 width=pipeline.index_array.format==0?1:2;
            const u64 size=u64(pipeline.num_vertices)*width;
            if(size>budget){notes["resource_budget_exhausted"]=true;span_valid=false;}
            else try {
                const u32 address=pipeline.vertex_attributes.GetPhysicalBaseAddress()+pipeline.index_array.offset;
                auto resource=Resource(address,static_cast<u32>(size),"index");
                const auto& bytes=resource.bytes;
                min_vertex=0xffff;max_vertex=0;
                for(u32 i=0;i<pipeline.num_vertices;++i){u32 vertex=bytes[i*width];
                    if(width==2)vertex|=u32(bytes[i*width+1])<<8;
                    min_vertex=std::min<u64>(min_vertex,vertex);max_vertex=std::max<u64>(max_vertex,vertex+1);}
                snapshot.resources.push_back(std::move(resource));budget-=size;
            } catch(const std::exception& error){span_valid=false;notes["index_capture_error"]=error.what();}
        }
        if(span_valid)for(const auto& loader:pipeline.vertex_attributes.attribute_loaders) {
            const u64 stride=loader.byte_count.Value();if(!stride||!loader.component_count)continue;
            const u64 address=u64(pipeline.vertex_attributes.GetPhysicalBaseAddress())+loader.data_offset.Value()+min_vertex*stride;
            const u64 size=(max_vertex-min_vertex)*stride;
            if(!size||size>budget||address+size>0x100000000ull){notes["resource_budget_exhausted"]=true;continue;}
            try {auto resource=Resource(static_cast<u32>(address),static_cast<u32>(size),"vertex");
                resource.extra={{"stride",stride},{"first_vertex",min_vertex},{"last_vertex_exclusive",max_vertex}};
                snapshot.resources.push_back(std::move(resource));budget-=size;
            }catch(const std::exception& error){snapshot.failed.push_back({{"kind","vertex"},{"address",address},{"error",error.what()}});}
        }
        snapshot.resources_captured=true;
    }
    /// The draw's capture document, built on request from the frozen copies.
    Json DrawJson(const Draw& draw) const {
        Json data=draw.meta;
        if(!draw.snapshot) {
            data["snapshot"]="metadata_only";
            data["omitted"]=Json::array({"registers","shader_setup","resources"});
            return data;
        }
        const auto& snapshot=*draw.snapshot;
        data["registers"]=snapshot.registers;
        data["vertex_program"]=snapshot.setup.GetProgramCode();
        data["swizzle"]=snapshot.setup.GetSwizzleData();
        data["uniforms_f32_bits"]=Vectors(snapshot.setup.uniforms.f);
        data["bool_uniforms"]=snapshot.setup.uniforms.b;
        data["unused_vertex_attributes"]="zero-filled in debug snapshots";
        data["rasterizer_cache_flush"]=snapshot.resources_captured;
        for(const auto& [key,value]:snapshot.notes.items())data[key]=value;
        if(snapshot.resources_captured) {
            Json resources=Json::array();
            for(const auto& resource:snapshot.resources)resources.push_back(ResourceJson(resource));
            for(const auto& failed:snapshot.failed)resources.push_back(failed);
            data["resources"]=std::move(resources);
        } else {
            data["omitted"]=Json::array({"resources"});
        }
        return data;
    }
    Pica::AttributeBuffer Input(const void* data) {
        Pica::AttributeBuffer sanitized{};const auto& source=*static_cast<const Pica::AttributeBuffer*>(data);
        const u32 count=std::min<u32>(system.GPU().PicaCore().regs.internal.vs.max_input_attribute_index+1,16);
        for(u32 i=0;i<count;++i)sanitized[i]=source[i];return sanitized;
    }
    void Event(u32 event,const void* pointer) {
        if(!enabled||capture==Capture::Counters||event>=8)return;
        if(halted) {
            if(event==4 && collect_stop_inputs && pointer && !draws.empty() && draws.back().snapshot) {
                auto& inputs=draws.back().inputs;
                if(inputs.size()<8)inputs.push_back(Input(pointer));
                else ++vertices_lost;
            }
            if(event==3)collect_stop_inputs=false;
            return;
        }
        if(event==0)++command_sequence;
        if(event==2)FreezeDraw(pointer&&*static_cast<const bool*>(pointer));
        if(event==4&&pointer&&!draws.empty()&&draws.back().snapshot) {
            auto& inputs=draws.back().inputs;
            if(inputs.size()<8)inputs.push_back(Input(pointer));
            else ++vertices_lost;
        }
        // No event JSON unless a subscriber, the history or a draw predicate wants it, or the
        // event stops (lotus#26). Counters and snapshots above do not depend on it.
        if(!breaks.test(event)&&wants_events&&!wants_events())return;
        Json data={{"event",event},{"command",command_sequence},{"draw",draw_sequence}};
        if((event==0||event==1)&&pointer) {
            const auto id=*static_cast<const u32*>(pointer);
            data["register"]=id;
            if(id<Pica::RegsInternal::NUM_REGS)data["value"]=system.GPU().PicaCore().regs.internal.reg_array[id];
        }
        if(event==6&&pointer){u32 header;std::memcpy(&header,pointer,4);data["gsp_header"]=header;}
        record("pica",data);
        if(breaks.test(event)) {halted=true;collect_stop_inputs=event==2;data["stop_boundary"]="next_CPU_safe_point";data["event_observed"]=true;stop("pica",data);}
    }
    Json Dispatch(const Json& p) {
        const auto op=p.at("operation").get<std::string>();
        if(op=="gpu_configure") {
            const auto events=p.at("stop_events").get<std::vector<u32>>();
            for(auto event:events)if(event>=8)throw std::invalid_argument("PICA event 0..7");
            const auto mode=p.value("capture",std::string("full"));
            Capture requested;
            if(mode=="counters")requested=Capture::Counters;
            else if(mode=="events")requested=Capture::Events;
            else if(mode=="draws")requested=Capture::Draws;
            else if(mode=="full")requested=Capture::Full;
            else throw std::invalid_argument("capture: counters, events, draws or full");
            if(requested==Capture::Counters&&!events.empty())
                throw std::invalid_argument("stop_events need per-command events; use capture events or more");
            std::optional<std::pair<u64,u64>> range;
            if(p.contains("draw_range")&&!p.at("draw_range").is_null()) {
                const auto bounds=p.at("draw_range").get<std::vector<u64>>();
                if(bounds.size()!=2||bounds[0]>bounds[1])throw std::invalid_argument("draw_range: [first, last]");
                range=std::make_pair(bounds[0],bounds[1]);
            }
            const auto budget=p.value("max_draws",8u);
            if(!budget||budget>4096)throw std::invalid_argument("max_draws 1..4096");
            enabled=p.at("enabled");capture=requested;draw_range=range;max_draws=budget;
            capture_resources=p.value("resources",false);snapshots_taken=snapshots_skipped=0;
            breaks.reset();for(auto event:events)breaks.set(event);
            Activate(enabled&&capture!=Capture::Counters);
            return {{"enabled",enabled},{"stop_events",p.at("stop_events")},{"capture",mode},
                {"draw_range",range?Json::array({range->first,range->second}):Json(nullptr)},{"max_draws",max_draws},
                {"resources",capture==Capture::Full||capture_resources},
                {"draw_capacity",8},{"vertices_per_draw",8},{"command_path",CommandPath()},
                {"fast_path_commands",FastPathCommands()},{"counters",Counters()}};
        }
        if(op=="gpu_draws") {
            Json list=Json::array();
            for(auto& draw:draws)list.push_back({{"draw",draw.id},{"vertices",draw.inputs.size()},
                {"command",draw.meta.at("command")},{"snapshot",static_cast<bool>(draw.snapshot)},{"artifact",draw.artifact}});
            return {{"draws",list},{"command_path",CommandPath()},{"capture",CaptureName()},
                {"fast_path_commands",FastPathCommands()},{"counters",Counters()},{"lost_draws",draws_lost},
                {"lost_vertices",vertices_lost},{"lost_resource_versions",resource_versions_lost},
                {"snapshots_taken",snapshots_taken},{"snapshots_skipped_budget",snapshots_skipped}};
        }
        if(op=="gpu_draw"||op=="shader_trace") {
            const auto id=p.at("draw").get<u64>();
            auto it=std::find_if(draws.begin(),draws.end(),[&](const auto& draw){return draw.id==id;});
            if(it==draws.end())throw std::invalid_argument("draw expired or not captured");
            if(op=="gpu_draw") {
                Json vertices=Json::array();for(size_t i=0;i<it->inputs.size();++i) {
                    Json vertex={{"input_f32_bits",Vectors(it->inputs[i])}};
                    if(i<it->outputs.size())vertex["output_f32_bits"]=Vectors(it->outputs[i]);vertices.push_back(vertex);
                }
                auto data=DrawJson(*it);data["vertices"]=vertices;
                it->artifact=Artifact(std::filesystem::path("gpu")/("draw-"+std::to_string(id%8)+".json"),data);
                return {{"draw",id},{"artifacts",Json::array({it->artifact})}};
            }
            const auto vertex=p.at("vertex").get<u32>();
            if(!it->snapshot)throw std::invalid_argument("draw has metadata only; capture it with capture=draws or full");
            if(vertex>=it->inputs.size())throw std::invalid_argument("vertex unavailable; capture with use_hw_shader=false");
            Pica::Shader::InterpreterEngine interpreter;
            const auto trace=interpreter.ProduceDebugInfo(it->snapshot->setup,it->inputs[vertex],it->snapshot->config);
            Json instructions=Json::array();
            for(const auto& instruction:trace.records) {
                Json row={{"pc",instruction.instruction_offset},{"next",instruction.next_instruction},{"mask",instruction.mask}};
                const auto vector=[](const auto& v) {return Json::array({std::bit_cast<u32>(v.x.ToFloat32()),
                    std::bit_cast<u32>(v.y.ToFloat32()),std::bit_cast<u32>(v.z.ToFloat32()),std::bit_cast<u32>(v.w.ToFloat32())});};
                if(instruction.mask&1)row["src1_f32_bits"]=vector(instruction.src1);
                if(instruction.mask&2)row["src2_f32_bits"]=vector(instruction.src2);
                if(instruction.mask&4)row["src3_f32_bits"]=vector(instruction.src3);
                if(instruction.mask&16)row["dest_f32_bits"]=vector(instruction.dest_out);
                instructions.push_back(std::move(row));
            }
            const auto relative=std::filesystem::path("gpu")/("shader-"+std::to_string(id%8)+".json");
            const auto artifact=Artifact(relative,{{"draw",id},{"vertex",vertex},{"input_f32_bits",Vectors(it->inputs[vertex])},
                {"instructions",instructions},{"output_f32_bits",trace.output_f32_bits},
                {"actual_vertex_output_f32_bits",vertex<it->outputs.size()?Vectors(it->outputs[vertex]):Json(nullptr)},
                {"matches_frozen_output",vertex<it->outputs.size()?Json(Json(trace.output_f32_bits)==Vectors(it->outputs[vertex])):Json(nullptr)},
                {"instruction_cap",8192},{"truncated",trace.truncated}});
            return {{"draw",id},{"vertex",vertex},{"instructions",instructions.size()},
                    {"artifacts",Json::array({artifact})},{"source","frozen_draw_interpreter"}};
        }
        if(op=="surface") {
            const auto address=p.at("address").get<u32>(),width=p.at("width").get<u32>(),height=p.at("height").get<u32>(),
                       format=p.at("format").get<u32>();
            if(!width||!height||width>1024||height>1024||width%8||height%8||format>13)
                throw std::invalid_argument("surface: 8-aligned dimensions 8..1024, texture format 0..13");
            Pica::Texture::TextureInfo info{address,width,height,0,static_cast<Pica::TexturingRegs::TextureFormat>(format),false};
            info.SetDefaultStride();
            auto bytes=Physical(address,static_cast<u32>(info.stride*(height/8)));
            std::vector<u8> pixels(width*height*4);
            for(u32 y=0;y<height;++y)for(u32 x=0;x<width;++x){
                const auto rgba=Pica::Texture::LookupTexture(bytes.data(),x,y,info);
                const auto i=(y*width+x)*4;pixels[i]=rgba.b();pixels[i+1]=rgba.g();pixels[i+2]=rgba.r();pixels[i+3]=rgba.a();
            }
            const auto relative=std::filesystem::path("gpu")/("surface-"+std::to_string(++surface_sequence%8)+".bgra");
            std::filesystem::create_directories(root/"gpu");
            std::ofstream file(root/relative,std::ios::binary|std::ios::trunc);
            file.exceptions(std::ios::badbit|std::ios::failbit);file.write(reinterpret_cast<const char*>(pixels.data()),pixels.size());file.close();
            return {{"address",address},{"source_xxh3_64",Hash(bytes)},{"width",width},{"height",height},
                {"rasterizer_cache_flush",true},{"artifacts",Json::array({{{"path",relative.generic_string()},
                {"format","bgra8"},{"width",width},{"height",height}}})}};
        }
        throw std::invalid_argument("unknown GPU command");
    }
private:
    enum class Capture {Counters,Events,Draws,Full};
    struct Snapshot {
        Pica::ShaderSetup setup;Pica::ShaderRegs config;
        std::vector<u32> registers;
        std::vector<ResourceCopy> resources;std::vector<Json> failed;Json notes=Json::object();bool resources_captured=false;
    };
    struct Draw {
        u64 id=0;Json meta;std::unique_ptr<Snapshot> snapshot;
        std::vector<Pica::AttributeBuffer> inputs,outputs;Json artifact;
    };
    const char* CommandPath() const {return enabled&&capture!=Capture::Counters?"per_command":"batched";}
    const char* CaptureName() const {
        switch(capture){case Capture::Counters:return "counters";case Capture::Events:return "events";
            case Capture::Draws:return "draws";default:return "full";}
    }
    Capture capture=Capture::Full;std::optional<std::pair<u64,u64>> draw_range;u32 max_draws=8;
    bool capture_resources=false;u64 snapshots_taken=0,snapshots_skipped=0;
    Core::System& system;std::filesystem::path root;Callback record,stop;
    std::shared_ptr<Pica::DebugContext> context;
    bool enabled=false,halted=false,collect_stop_inputs=false;std::bitset<8> breaks;
    u64 draw_sequence=0,command_sequence=0,resource_sequence=0,surface_sequence=0,draws_lost=0,vertices_lost=0;
    std::deque<Draw> draws;
    std::map<std::tuple<u32,u32,std::string>,std::pair<u64,u64>> resources;
    u64 resource_versions_lost=0;
};
} // namespace CtrWorker
