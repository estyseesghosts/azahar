// Deterministic finite PCM WAV microphone source. Silence follows end-of-file.
#pragma once
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <span>
#include <cstring>
#include "audio_core/input.h"

namespace AudioCore {
class InjectedInput final : public Input {
public:
    inline static std::vector<s16> samples;
    inline static u32 source_rate=32728;
    static void Load(const std::filesystem::path& path) {
        const auto size=std::filesystem::file_size(path);
        if(size<44||size>(64u<<20))throw std::invalid_argument("WAV size budget");
        std::vector<u8> bytes(size);std::ifstream file(path,std::ios::binary);
        file.exceptions(std::ios::failbit|std::ios::badbit);file.read(reinterpret_cast<char*>(bytes.data()),size);
        auto word=[&](size_t at,unsigned count)->u32 {
            if(at+count>bytes.size())throw std::invalid_argument("truncated WAV");
            u32 value=0;for(unsigned i=0;i<count;++i)value|=u32(bytes[at+i])<<(8*i);return value;
        };
        if(std::memcmp(bytes.data(),"RIFF",4)||std::memcmp(bytes.data()+8,"WAVE",4))
            throw std::invalid_argument("expected RIFF WAV");
        u32 channels=0,rate=0;std::span<const u8> pcm;
        for(size_t offset=12,count=0;offset+8<=size && count<4096;++count) {
            const auto length=word(offset+4,4);const auto start=offset+8;
            if(u64(start)+length>size)throw std::invalid_argument("truncated WAV chunk");
            if(!std::memcmp(bytes.data()+offset,"fmt ",4)) {
                if(length<16||word(start,2)!=1||word(start+14,2)!=16)throw std::invalid_argument("WAV must be PCM16");
                channels=word(start+2,2);rate=word(start+4,4);
                if((channels!=1&&channels!=2)||rate<8000||rate>96000||word(start+12,2)!=channels*2)
                    throw std::invalid_argument("WAV format range");
            } else if(!std::memcmp(bytes.data()+offset,"data",4))pcm=std::span(bytes).subspan(start,length);
            offset=start+length+(length&1);
        }
        if(!channels||!rate||pcm.empty()||pcm.size()%(channels*2))throw std::invalid_argument("missing WAV PCM");
        std::vector<s16> decoded;decoded.reserve(pcm.size()/(channels*2));
        for(size_t i=0;i<pcm.size();i+=channels*2) {
            auto sample=[&](size_t at){return static_cast<s16>(u16(pcm[at])|(u16(pcm[at+1])<<8));};
            decoded.push_back(channels==1?sample(i):static_cast<s16>((s32(sample(i))+sample(i+2))/2));
        }
        samples=std::move(decoded);source_rate=rate;
    }
    void StartSampling(const InputParameters& p) override { parameters=p;phase=0;sampling=true; }
    void StopSampling() override { sampling=false; }
    bool IsSampling() override { return sampling; }
    void AdjustSampleRate(u32 rate) override {
        const auto old=std::max(parameters.sample_rate,1u);
        phase=(phase/old)*rate+(phase%old)*rate/old;parameters.sample_rate=rate;
    }
    u64 GetReplayCursor() const override {return phase;}
    void SetReplayCursor(u64 cursor) override {
        if(cursor>u64(samples.size())*std::max(parameters.sample_rate,1u))throw std::invalid_argument("injected microphone cursor exceeds asset");
        phase=cursor;
    }
    Samples Read() override {
        if(!sampling)return {};
        Samples output;output.reserve(32);
        for(unsigned i=0;i<16;++i) {
            const auto index=phase/std::max(parameters.sample_rate,1u);
            const s16 value=index<samples.size()?samples[index]:0;
            phase=std::min(phase+source_rate,u64(samples.size())*std::max(parameters.sample_rate,1u));
            const u16 encoded=parameters.sign==Signedness::Unsigned?static_cast<u16>(s32(value)+32768):static_cast<u16>(value);
            if(parameters.sample_size==8)output.push_back(encoded>>8);
            else {output.push_back(encoded&255);output.push_back(encoded>>8);}
        }
        return output;
    }
private:
    u64 phase=0;bool sampling=false;
};
} // namespace AudioCore
