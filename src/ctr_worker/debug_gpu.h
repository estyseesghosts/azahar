// Frozen GPU observations at native PICA event boundaries; no renderer-thread waits.
#pragma once
#include <bitset>
#include <fstream>
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
public:
    using Json=nlohmann::json;
    using Callback=std::function<void(const char*,Json)>;
    GpuTools(Core::System& system,const std::filesystem::path& root,Callback record,Callback stop)
        :system(system),root(root),record(std::move(record)),stop(std::move(stop)) {
        if (!Pica::g_debug_context) Pica::g_debug_context=Pica::DebugContext::Construct();
        DebugChannel::gpu_event=[this](u32 event,const void* data){Event(event,data);};
    }
    ~GpuTools(){DebugChannel::gpu_event={};}
    void Clear(){enabled=false;breaks.reset();draws.clear();draw_sequence=command_sequence=0;halted=false;}
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
    static u64 Hash(const std::vector<u8>& bytes){return Common::ComputeHash64(bytes.data(),bytes.size());}
    Json Resource(u32 address,u32 length,const char* kind) {
        const auto bytes=Physical(address,length);
        return {{"address",address},{"bytes",length},{"kind",kind},
                {"content_xxh3_64",Hash(bytes)},{"version",++resource_sequence},
                {"data_hex",Hex(bytes)},{"rasterizer_cache_flush",true}};
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
    void FreezeDraw() {
        auto& pica=system.GPU().PicaCore();
        Draw draw{++draw_sequence,pica.vs_setup,pica.regs.internal.vs,{},Json::object()};
        auto& data=draw.data;
        data={{"draw",draw.id},{"command",command_sequence},{"guest_ticks",system.CoreTiming().GetGlobalTicks()},
            {"registers",pica.regs.reg_array},{"vertex_program",pica.vs_setup.GetProgramCode()},
            {"swizzle",pica.vs_setup.GetSwizzleData()},{"uniforms_f32_bits",Vectors(pica.vs_setup.uniforms.f)},
            {"bool_uniforms",pica.vs_setup.uniforms.b},{"capture_boundary","incoming_primitive_batch"},
            {"rasterizer_cache_flush",true}};
        Json resources=Json::array();
        u64 budget=4u<<20;
        for(const auto& texture:pica.regs.internal.texturing.GetTextures()) {
            if(!texture.enabled)continue;
            const auto info=Pica::Texture::TextureInfo::FromPicaRegister(texture.config,texture.format);
            const u64 size=Pica::Texture::CalculateTileSize(info.format)*((info.width+7)/8)*((info.height+7)/8);
            if(!size||size>budget) {data["resource_budget_exhausted"]=true;continue;}
            try {
                auto resource=Resource(info.physical_address,static_cast<u32>(size),"texture");
                resource["width"]=info.width;resource["height"]=info.height;resource["format"]=static_cast<u32>(info.format);
                resources.push_back(std::move(resource));budget-=size;
            } catch(const std::exception& e){resources.push_back({{"address",info.physical_address},{"error",e.what()}});}
        }
        data["resources"]=std::move(resources);
        const auto relative=std::filesystem::path("gpu")/("draw-"+std::to_string(draw.id%8)+".json");
        draw.artifact=Artifact(relative,data);
        if(draws.size()==8){draws.pop_front();++draws_lost;}
        draws.push_back(std::move(draw));
    }
    void Event(u32 event,const void* pointer) {
        if(!enabled||event>=8)return;
        if(halted) {
            if(event==4 && collect_stop_inputs && pointer && !draws.empty()) {
                auto& inputs=draws.back().inputs;
                if(inputs.size()<8)inputs.push_back(*static_cast<const Pica::AttributeBuffer*>(pointer));
                else ++vertices_lost;
            }
            if(event==3)collect_stop_inputs=false;
            return;
        }
        if(event==0)++command_sequence;
        if(event==2)FreezeDraw();
        Json data={{"event",event},{"command",command_sequence},{"draw",draw_sequence}};
        if((event==0||event==1)&&pointer) {
            const auto id=*static_cast<const u32*>(pointer);
            data["register"]=id;
            if(id<Pica::RegsInternal::NUM_REGS)data["value"]=system.GPU().PicaCore().regs.internal.reg_array[id];
        }
        if(event==6&&pointer){u32 header;std::memcpy(&header,pointer,4);data["gsp_header"]=header;}
        if(event==4&&pointer&&!draws.empty()) {
            auto& inputs=draws.back().inputs;
            if(inputs.size()<8)inputs.push_back(*static_cast<const Pica::AttributeBuffer*>(pointer));
            else ++vertices_lost;
        }
        record("pica",data);
        if(breaks.test(event)) {halted=true;collect_stop_inputs=event==2;data["stop_boundary"]="next_CPU_safe_point";data["event_observed"]=true;stop("pica",data);}
    }
    Json Dispatch(const Json& p) {
        const auto op=p.at("operation").get<std::string>();
        if(op=="gpu_configure") {
            enabled=p.at("enabled");breaks.reset();
            for(auto event:p.at("stop_events").get<std::vector<u32>>()){if(event>=8)throw std::invalid_argument("PICA event 0..7");breaks.set(event);}
            return {{"enabled",enabled},{"stop_events",p.at("stop_events")},{"draw_capacity",8},{"vertices_per_draw",8}};
        }
        if(op=="gpu_draws") {
            Json list=Json::array();
            for(auto& draw:draws)list.push_back({{"draw",draw.id},{"vertices",draw.inputs.size()},
                {"command",draw.data.at("command")},{"artifact",draw.artifact}});
            return {{"draws",list},{"lost_draws",draws_lost},{"lost_vertices",vertices_lost}};
        }
        if(op=="gpu_draw"||op=="shader_trace") {
            const auto id=p.at("draw").get<u64>();
            auto it=std::find_if(draws.begin(),draws.end(),[&](const auto& draw){return draw.id==id;});
            if(it==draws.end())throw std::invalid_argument("draw expired or not captured");
            if(op=="gpu_draw")return {{"draw",id},{"artifacts",Json::array({it->artifact})}};
            const auto vertex=p.at("vertex").get<u32>();
            if(vertex>=it->inputs.size())throw std::invalid_argument("vertex unavailable; capture with use_hw_shader=false");
            Pica::Shader::InterpreterEngine interpreter;
            const auto trace=interpreter.ProduceDebugInfo(it->setup,it->inputs[vertex],it->config);
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
                {"instructions",instructions},{"instruction_cap",8192},{"truncated",trace.truncated}});
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
    struct Draw {
        u64 id;Pica::ShaderSetup setup;Pica::ShaderRegs config;
        std::vector<Pica::AttributeBuffer> inputs;Json data;Json artifact;
    };
    Core::System& system;std::filesystem::path root;Callback record,stop;
    bool enabled=false,halted=false,collect_stop_inputs=false;std::bitset<8> breaks;
    u64 draw_sequence=0,command_sequence=0,resource_sequence=0,surface_sequence=0,draws_lost=0,vertices_lost=0;
    std::deque<Draw> draws;
};
} // namespace CtrWorker
