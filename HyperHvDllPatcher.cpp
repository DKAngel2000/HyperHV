#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Comctl32.lib")

namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;

struct Patch {
    size_t offset{};
    Bytes before;
    Bytes after;
    std::string label;
};
struct Profile {
    const char* name;
    std::vector<Patch> patches;
};
struct Section {
    uint32_t virtualAddress{}, virtualSize{}, rawOffset{}, rawSize{}, characteristics{};
};
struct RuntimeFunction {
    uint32_t beginRva{}, endRva{}, rawBegin{}, rawEnd{};
};
struct CallSite {
    uint32_t rva{};
    size_t offset{};
    size_t functionIndex{};
    Bytes bytes;
};

static Bytes H(const char* s) {
    Bytes out;
    for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
        unsigned value = 0;
        std::sscanf(s + i, "%2x", &value);
        out.push_back(static_cast<uint8_t>(value));
    }
    return out;
}
static Patch P(size_t off, const char* before, const char* after, const char* label) {
    return Patch{off, H(before), H(after), label};
}

static const std::vector<Profile>& Profiles() {
    static const std::vector<Profile> p = {
        {"HyperDbg", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536120100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x10754,"FF15A6BD0000","E82705FFFF90","EPT shutdown cleanup")}},
        {"HypervisorSource", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536120100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x107B4,"FF1546BD0000","E8C704FFFF90","EPT shutdown cleanup")}},
        {"Intel", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536420100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x10824,"FF15D6EC0000","E85704FFFF90","EPT shutdown cleanup")}},
        {"EPT variant D37BE6", {P(0xA04B,"E8B06BFFFF","E8106CFFFF","EPT allocation"), P(0xB284,"FF1576120100","E8175AFFFF90","EPT allocation-failure cleanup"), P(0x10764,"FF1596BD0000","E83705FFFF90","EPT shutdown cleanup")}},
        {"EPT variant 6B249F", {P(0xA05B,"E8706BFFFF","E8D06BFFFF","EPT allocation"), P(0xB294,"FF1566120100","E8D759FFFF90","EPT allocation-failure cleanup"), P(0x10744,"FF15B6BD0000","E82705FFFF90","EPT shutdown cleanup")}},
        {"EPT variant 834A39", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536420100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x107D4,"FF1526ED0000","E8A704FFFF90","EPT shutdown cleanup")}},
        {"EPT variant E2C8F9", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536520100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x10F84,"FF1576F50000","E8F7FCFEFF90","EPT shutdown cleanup")}},
        {"EPT variant 597ED3", {P(0xA48B,"E85067FFFF","E8B067FFFF","EPT allocation"), P(0xB674,"FF15860E0100","E80756FFFF90","EPT allocation-failure cleanup"), P(0x10AD4,"FF1526BA0000","E8A701FFFF90","EPT shutdown cleanup")}},
        {"EPT variant 55DA28", {P(0xA02B,"E8B06BFFFF","E8106CFFFF","EPT allocation"), P(0xB264,"FF1596120100","E8175AFFFF90","EPT allocation-failure cleanup"), P(0x10704,"FF15F6BD0000","E87705FFFF90","EPT shutdown cleanup")}},
        {"EPT variant EBECD6", {P(0xA08B,"E8506BFFFF","E8B06BFFFF","EPT allocation"), P(0xB2C4,"FF1536120100","E8B759FFFF90","EPT allocation-failure cleanup"), P(0x10764,"FF1596BD0000","E81705FFFF90","EPT shutdown cleanup")}}
    };
    return p;
}

static bool MatchAt(const Bytes& file, size_t off, const Bytes& bytes) {
    return off <= file.size() && bytes.size() <= file.size() - off &&
        std::memcmp(file.data() + off, bytes.data(), bytes.size()) == 0;
}
static uint16_t U16(const Bytes& b, size_t o) { return static_cast<uint16_t>(b[o] | (uint16_t(b[o+1]) << 8)); }
static uint32_t U32(const Bytes& b, size_t o) { return uint32_t(b[o]) | (uint32_t(b[o+1])<<8) | (uint32_t(b[o+2])<<16) | (uint32_t(b[o+3])<<24); }
static int32_t I32(const Bytes& b, size_t o) { return static_cast<int32_t>(U32(b,o)); }
static uint64_t U64(const Bytes& b, size_t o) { return uint64_t(U32(b,o)) | (uint64_t(U32(b,o+4))<<32); }
static std::string Hex(const Bytes& b) {
    static const char* digits="0123456789ABCDEF";
    std::string s; s.reserve(b.size()*2);
    for(uint8_t v:b){s.push_back(digits[v>>4]);s.push_back(digits[v&15]);}
    return s;
}

class PeImage {
public:
    explicit PeImage(const Bytes& bytes) : file(bytes) {}
    bool Parse(std::string& error) {
        if(file.size()<0x100 || file[0]!='M' || file[1]!='Z'){error="Not a PE DLL.";return false;}
        const uint32_t pe=U32(file,0x3c);
        if(pe>file.size() || pe+24>file.size() || std::memcmp(file.data()+pe,"PE\0\0",4)!=0){error="Invalid PE header.";return false;}
        const uint16_t machine=U16(file,pe+4), nsec=U16(file,pe+6), optSize=U16(file,pe+20);
        const size_t opt=pe+24;
        if(machine!=0x8664 || opt+optSize>file.size() || U16(file,opt)!=0x20b){error="Experimental matching supports x64 PE32+ DLLs only.";return false;}
        imageBase=U64(file,opt+24);
        sizeHeaders=U32(file,opt+60);
        if(optSize<112+8*16){error="PE optional header has no complete data directory.";return false;}
        const size_t secTable=opt+optSize;
        for(uint16_t i=0;i<nsec;i++){
            size_t s=secTable+size_t(i)*40;if(s+40>file.size()){error="Invalid PE section table.";return false;}
            sections.push_back(Section{U32(file,s+12),U32(file,s+8),U32(file,s+20),U32(file,s+16),U32(file,s+36)});
        }
        const size_t dirs=opt+112;
        const uint32_t importRva=U32(file,dirs+8), importSize=U32(file,dirs+12);
        const uint32_t pdataRva=U32(file,dirs+24), pdataSize=U32(file,dirs+28);
        if(!ParseImports(importRva,importSize,error)) return false;
        if(!ParseRuntimeFunctions(pdataRva,pdataSize,error)) return false;
        return true;
    }
    std::optional<size_t> RvaOffset(uint32_t rva) const {
        if(rva<sizeHeaders && rva<file.size()) return size_t(rva);
        for(const auto& s:sections){
            const uint64_t span=std::max<uint32_t>(s.virtualSize,s.rawSize);
            if(rva>=s.virtualAddress && uint64_t(rva)<uint64_t(s.virtualAddress)+span){
                uint64_t delta=uint64_t(rva)-s.virtualAddress;
                if(delta>=s.rawSize) return std::nullopt;
                uint64_t o=uint64_t(s.rawOffset)+delta;
                if(o>=file.size()) return std::nullopt;
                return size_t(o);
            }
        }
        return std::nullopt;
    }
    uint64_t imageBase{};
    uint32_t sizeHeaders{};
    std::vector<Section> sections;
    std::unordered_map<std::string,uint32_t> imports;
    std::vector<RuntimeFunction> functions;
private:
    const Bytes& file;
    std::string ReadString(uint32_t rva) const {
        auto o=RvaOffset(rva); if(!o) return {};
        std::string s;
        for(size_t i=*o;i<file.size() && file[i];i++) s.push_back(static_cast<char>(file[i]));
        return s;
    }
    bool ParseImports(uint32_t rva,uint32_t size,std::string& error){
        if(!rva || size<20){error="No PE import directory.";return false;}
        auto base=RvaOffset(rva);if(!base){error="Import directory is not file-backed.";return false;}
        for(size_t d=*base;d+20<=file.size();d+=20){
            uint32_t oft=U32(file,d),nameRva=U32(file,d+12),ft=U32(file,d+16);
            if(!oft && !nameRva && !ft) break;
            if(!ft){error="Import descriptor has no IAT.";return false;}
            const uint32_t thunkRva=oft?oft:ft;
            for(uint32_t n=0;n<8192;n++){
                auto t=RvaOffset(thunkRva+n*8),iat=RvaOffset(ft+n*8);
                if(!t || !iat || *t+8>file.size()) break;
                uint64_t value=U64(file,*t);if(!value) break;
                if((value>>63)!=0) continue;
                uint32_t importNameRva=static_cast<uint32_t>(value);
                auto nameOff=RvaOffset(importNameRva);if(!nameOff || *nameOff+2>=file.size()) continue;
                std::string name;
                for(size_t k=*nameOff+2;k<file.size() && file[k];k++) name.push_back(static_cast<char>(file[k]));
                if(!name.empty()) imports[name]=ft+n*8;
            }
        }
        return !imports.empty();
    }
    bool ParseRuntimeFunctions(uint32_t rva,uint32_t size,std::string& error){
        if(!rva || size<12 || size%12!=0){error="No usable x64 exception/function table (.pdata).";return false;}
        auto base=RvaOffset(rva);if(!base){error=".pdata is not file-backed.";return false;}
        for(size_t o=*base;o+12<=file.size() && o<*base+size;o+=12){
            uint32_t begin=U32(file,o),end=U32(file,o+4);
            if(!begin && !end) continue;
            if(begin>=end) continue;
            auto rawBegin=RvaOffset(begin),rawEnd=RvaOffset(end-1);
            if(!rawBegin || !rawEnd || *rawEnd<*rawBegin) continue;
            functions.push_back(RuntimeFunction{begin,end,static_cast<uint32_t>(*rawBegin),static_cast<uint32_t>(*rawEnd+1)});
        }
        if(functions.empty()){error="No executable x64 functions found in .pdata.";return false;}
        return true;
    }
};

static bool IsFieldLoad(const Bytes& b,size_t o){
    if(o+11>b.size()) return false;
    const uint8_t rex=b[o],modrm=b[o+2];
    if((rex&0xf8)!=0x48 || (rex&0x04)!=0 || b[o+1]!=0x8b || (modrm&0xf8)!=0x88 || (modrm&7)!=4) return false;
    if(U32(b,o+4)!=0x228 || b[o+8]!=0x48 || b[o+9]!=0x85 || b[o+10]!=0xc9) return false;
    return true;
}
static bool IsFieldStoreRax(const Bytes& b,size_t o){
    if(o+8>b.size()) return false;
    const uint8_t rex=b[o],modrm=b[o+2];
    return (rex&0xf8)==0x48 && (rex&0x04)==0 && b[o+1]==0x89 && (modrm&0xf8)==0x80 && (modrm&7)==4 && U32(b,o+4)==0x228;
}
static bool BranchIsJz(const Bytes& b,size_t o,size_t& length){
    if(o+2<=b.size() && b[o]==0x74){length=2;return true;}
    if(o+6<=b.size() && b[o]==0x0f && b[o+1]==0x84){length=6;return true;}
    return false;
}
static std::optional<size_t> FieldCallStart(const Bytes& b,size_t callOff){
    for(size_t branchLen:{size_t(2),size_t(6)}){
        if(callOff<8+3+branchLen) continue;
        size_t field=callOff-(8+3+branchLen),branch=field+11;
        size_t actual=0;
        if(IsFieldLoad(b,field) && BranchIsJz(b,branch,actual) && actual==branchLen && branch+branchLen==callOff) return field;
    }
    return std::nullopt;
}
static uint32_t IatTargetRva(const Bytes& b,size_t off,uint32_t instructionRva,size_t prefix){
    int32_t disp=I32(b,off+prefix+2);
    return static_cast<uint32_t>(int64_t(instructionRva)+prefix+6+disp);
}
static std::vector<CallSite> FindIndirectCalls(const Bytes& b,const PeImage& pe,uint32_t iat,uint8_t secondOpcode){
    std::vector<CallSite> out;
    for(size_t fi=0;fi<pe.functions.size();fi++){
        const auto& f=pe.functions[fi];
        for(size_t o=f.rawBegin;o+7<=f.rawEnd;o++){
            size_t prefix=0;
            if(b[o]==0x48 && b[o+1]==0xff) prefix=1;
            if(b[o+prefix]!=0xff || b[o+prefix+1]!=secondOpcode) continue;
            uint32_t rva=f.beginRva+static_cast<uint32_t>(o-f.rawBegin);
            if(IatTargetRva(b,o,rva,prefix)!=iat) continue;
            const size_t length=prefix+6;
            out.push_back(CallSite{rva,o,fi,Bytes(b.begin()+o,b.begin()+o+length)});
        }
    }
    return out;
}
static std::optional<size_t> FunctionIndexAt(const PeImage& pe,uint32_t rva){
    for(size_t i=0;i<pe.functions.size();i++) if(rva>=pe.functions[i].beginRva && rva<pe.functions[i].endRva) return i;
    return std::nullopt;
}
static uint32_t DirectTargetRva(const Bytes& b,size_t off,uint32_t siteRva){
    return static_cast<uint32_t>(int64_t(siteRva)+5+I32(b,off+1));
}
static bool HasAllocatorReturnAndFieldStore(const Bytes& b,size_t callOff,size_t end){
    size_t p=callOff+5;
    size_t testLen=0;
    if(p+3<=end && b[p]==0x48 && b[p+1]==0x85 && b[p+2]==0xc0) testLen=3;
    else if(p+2<=end && b[p]==0x85 && b[p+1]==0xc0) testLen=2;
    if(!testLen) return false;
    p+=testLen;
    size_t branchLen=0;if(!BranchIsJz(b,p,branchLen)) return false;
    p+=branchLen;
    const size_t limit=std::min(end,p+32);
    for(size_t i=p;i+8<=limit;i++) if(IsFieldStoreRax(b,i)) return true;
    return false;
}
static std::vector<CallSite> FindEptFreeSites(const Bytes& b,const PeImage& pe,uint32_t mmFreeIat){
    auto calls=FindIndirectCalls(b,pe,mmFreeIat,0x15);
    std::vector<CallSite> out;
    for(auto& c:calls) if(FieldCallStart(b,c.offset)) out.push_back(c);
    return out;
}
static std::pair<std::vector<CallSite>,std::vector<CallSite>> FindFieldCallSites(const Bytes& b,const PeImage& pe,uint32_t mmFreeIat,uint32_t poolFreeRva){
    std::vector<CallSite> original,patched;
    for(size_t fi=0;fi<pe.functions.size();fi++){
        const auto& f=pe.functions[fi];
        for(size_t field=f.rawBegin;field+13<=f.rawEnd;field++){
            if(!IsFieldLoad(b,field))continue;
            size_t branch=field+11,branchLen=0;if(!BranchIsJz(b,branch,branchLen))continue;
            size_t call=branch+branchLen;if(call>=f.rawEnd)continue;
            const uint32_t callRva=f.beginRva+static_cast<uint32_t>(call-f.rawBegin);
            if(call+6<=f.rawEnd&&b[call]==0xff&&b[call+1]==0x15&&IatTargetRva(b,call,callRva,0)==mmFreeIat){
                original.push_back(CallSite{callRva,call,fi,Bytes(b.begin()+call,b.begin()+call+6)});
            }
            if(call+5<=f.rawEnd&&b[call]==0xe8&&DirectTargetRva(b,call,callRva)==poolFreeRva){
                patched.push_back(CallSite{callRva,call,fi,Bytes(b.begin()+call,b.begin()+call+5)});
            }
        }
    }
    return {original,patched};
}
static std::vector<size_t> FindFunctionsCallingIat(const Bytes& b,const PeImage& pe,uint32_t iat,uint8_t second){
    auto calls=FindIndirectCalls(b,pe,iat,second);
    std::vector<size_t> out;
    for(const auto& c:calls) if(std::find(out.begin(),out.end(),c.functionIndex)==out.end()) out.push_back(c.functionIndex);
    return out;
}
static std::vector<uint32_t> FindPoolFreeHelpers(const Bytes& b,const PeImage& pe,uint32_t exFreeIat){
    std::vector<uint32_t> out;
    for(const auto& s:pe.sections){
        if((s.characteristics&0x20000000)==0)continue;
        size_t end=std::min<size_t>(b.size(),size_t(s.rawOffset)+s.rawSize);
        for(size_t o=s.rawOffset;o+12<=end;o++){
            // The reviewed helper sets the pool tag in EDX, then tail-jumps through the IAT.
            if(b[o]!=0xba)continue;
            size_t j=o+5,prefix=0;if(b[j]==0x48&&b[j+1]==0xff)prefix=1;
            if(b[j+prefix]!=0xff||b[j+prefix+1]!=0x25)continue;
            uint32_t siteRva=s.virtualAddress+static_cast<uint32_t>(o-s.rawOffset);
            if(IatTargetRva(b,j,siteRva+5,prefix)!=exFreeIat)continue;
            if(std::find(out.begin(),out.end(),siteRva)==out.end())out.push_back(siteRva);
        }
    }
    return out;
}
static std::vector<size_t> FindEptConstructors(const Bytes& b,const PeImage& pe,const std::vector<CallSite>& frees){
    std::vector<size_t> candidateFunctions;
    for(const auto& c:frees) if(std::find(candidateFunctions.begin(),candidateFunctions.end(),c.functionIndex)==candidateFunctions.end()) candidateFunctions.push_back(c.functionIndex);
    std::vector<size_t> constructors;
    for(size_t fi:candidateFunctions){
        const auto& f=pe.functions[fi];
        for(size_t o=f.rawBegin;o+5<=f.rawEnd;o++){
            if(b[o]!=0xe8 || !HasAllocatorReturnAndFieldStore(b,o,f.rawEnd)) continue;
            const uint32_t siteRva=f.beginRva+static_cast<uint32_t>(o-f.rawBegin);
            uint32_t target=DirectTargetRva(b,o,siteRva);
            auto targetFn=FunctionIndexAt(pe,target);
            if(!targetFn || pe.functions[*targetFn].beginRva!=target) continue;
            if(std::find(constructors.begin(),constructors.end(),*targetFn)==constructors.end()) constructors.push_back(*targetFn);
        }
    }
    return constructors;
}
static std::vector<CallSite> FindDirectCallsToFunction(const Bytes& b,const PeImage& pe,size_t sourceFn,uint32_t targetRva){
    std::vector<CallSite> out;const auto& f=pe.functions[sourceFn];
    for(size_t o=f.rawBegin;o+5<=f.rawEnd;o++) if(b[o]==0xe8){
        uint32_t site=f.beginRva+static_cast<uint32_t>(o-f.rawBegin);
        if(DirectTargetRva(b,o,site)==targetRva) out.push_back(CallSite{site,o,sourceFn,Bytes(b.begin()+o,b.begin()+o+5)});
    }
    return out;
}
static Bytes MakeCall(int64_t relative,bool withNop){
    Bytes b{0xe8};const int32_t d=static_cast<int32_t>(relative);
    for(int i=0;i<4;i++) b.push_back(static_cast<uint8_t>((uint32_t(d)>>(8*i))&0xff));
    if(withNop) b.push_back(0x90);
    return b;
}

struct ExperimentalResult { bool alreadyPatched{}; Profile profile; };
static bool FindExperimental(const Bytes& bytes,Profile& profile,bool& already,std::string& error){
    PeImage pe(bytes);if(!pe.Parse(error)) return false;
    auto getImport=[&](const char* name)->std::optional<uint32_t>{auto it=pe.imports.find(name);if(it==pe.imports.end())return std::nullopt;return it->second;};
    auto mmFree=getImport("MmFreeContiguousMemory"),mmAlloc=getImport("MmAllocateContiguousMemory"),exFree=getImport("ExFreePoolWithTag"),exAlloc=getImport("ExAllocatePoolWithTag");
    if(!mmFree||!mmAlloc||!exFree||!exAlloc){error="Experimental scan requires MmFreeContiguousMemory, MmAllocateContiguousMemory, ExFreePoolWithTag, and ExAllocatePoolWithTag imports.";return false;}
    auto backendFns=FindFunctionsCallingIat(bytes,pe,*mmAlloc,0x15);
    auto poolAllocFns=FindFunctionsCallingIat(bytes,pe,*exAlloc,0x15);
    auto poolFreeHelpers=FindPoolFreeHelpers(bytes,pe,*exFree);
    if(backendFns.size()!=1){error="Experimental scan found "+std::to_string(backendFns.size())+" contiguous allocation helpers.";return false;}
    if(poolAllocFns.size()!=1){error="Experimental scan found "+std::to_string(poolAllocFns.size())+" pool allocation helpers.";return false;}
    if(poolFreeHelpers.size()!=1){error="Experimental scan found "+std::to_string(poolFreeHelpers.size())+" pool free helpers.";return false;}
    const uint32_t backendRva=pe.functions[backendFns[0]].beginRva;
    const uint32_t poolAllocRva=pe.functions[poolAllocFns[0]].beginRva;
    const uint32_t poolFreeRva=poolFreeHelpers[0];
    auto fieldSites=FindFieldCallSites(bytes,pe,*mmFree,poolFreeRva);
    auto freeSites=fieldSites.first;
    auto patchedFreeSites=fieldSites.second;
    if(freeSites.size()+patchedFreeSites.size()!=2){error="Experimental scan did not find exactly two EPT table frees; found "+std::to_string(freeSites.size()+patchedFreeSites.size())+".";return false;}
    std::vector<CallSite> allFreeSites=freeSites;
    allFreeSites.insert(allFreeSites.end(),patchedFreeSites.begin(),patchedFreeSites.end());
    auto constructors=FindEptConstructors(bytes,pe,allFreeSites);
    if(constructors.size()!=1){error="Experimental scan did not find one EPT table constructor; found "+std::to_string(constructors.size())+".";return false;}
    const size_t ctor=constructors[0];
    auto allocSites=FindDirectCallsToFunction(bytes,pe,ctor,backendRva);
    auto alreadyAllocSites=FindDirectCallsToFunction(bytes,pe,ctor,poolAllocRva);
    if(allocSites.size()==1 && alreadyAllocSites.empty() && freeSites.size()==2 && patchedFreeSites.empty()){
        profile.name="Experimental PE/x64 semantic match";
        const auto& a=allocSites[0];
        auto allocTarget=pe.RvaOffset(a.rva);if(!allocTarget){error="Allocator call is not file-backed.";return false;}
        int64_t allocRel=int64_t(poolAllocRva)-(int64_t(a.rva)+5);
        if(allocRel<INT32_MIN||allocRel>INT32_MAX){error="Pool allocator is outside the direct-call range.";return false;}
        profile.patches.push_back(Patch{*allocTarget,Bytes(bytes.begin()+*allocTarget,bytes.begin()+*allocTarget+5),MakeCall(allocRel,false),"Experimental EPT allocation"});
        for(const auto& f:freeSites){
            auto off=pe.RvaOffset(f.rva);if(!off){error="EPT free call is not file-backed.";return false;}
            int64_t rel=int64_t(poolFreeRva)-(int64_t(f.rva)+5);
            if(rel<INT32_MIN||rel>INT32_MAX){error="Pool free helper is outside the direct-call range.";return false;}
            profile.patches.push_back(Patch{*off,Bytes(bytes.begin()+*off,bytes.begin()+*off+6),MakeCall(rel,true),"Experimental EPT free"});
        }
        already=false;return true;
    }
    if(allocSites.empty() && alreadyAllocSites.size()==1 && freeSites.empty() && patchedFreeSites.size()==2){already=true;profile.name="Experimental PE/x64 semantic match";return true;}
    error="Experimental scan found a partial or modified layout; no output was written.";
    return false;
}

static std::optional<Profile> MatchOriginalProfile(const Bytes& bytes){
    std::vector<Profile> matches;
    for(const auto& p:Profiles()){
        bool ok=true;for(const auto& patch:p.patches) if(!MatchAt(bytes,patch.offset,patch.before)){ok=false;break;}
        if(ok) matches.push_back(p);
    }
    if(matches.size()==1)return matches[0];
    return std::nullopt;
}
static std::optional<std::string> MatchPatchedProfile(const Bytes& bytes){
    std::vector<std::string> matches;
    for(const auto& p:Profiles()){
        bool ok=true;for(const auto& patch:p.patches) if(!MatchAt(bytes,patch.offset,patch.after)){ok=false;break;}
        if(ok)matches.emplace_back(p.name);
    }
    if(matches.size()==1)return matches[0];
    return std::nullopt;
}

static bool WritePatchedCopy(const fs::path& input,const fs::path& output,const Bytes& original,const Profile& profile,std::string& error){
    if(fs::absolute(input).wstring()==fs::absolute(output).wstring()){error="Choose a different output path; the input is never overwritten.";return false;}
    if(fs::exists(output)){error="Output already exists; choose a new path.";return false;}
    Bytes changed=original;
    for(const auto& p:profile.patches){if(!MatchAt(changed,p.offset,p.before)){error="Patch bytes changed before write at "+p.label+".";return false;}}
    for(const auto& p:profile.patches)std::copy(p.after.begin(),p.after.end(),changed.begin()+p.offset);
    for(const auto& p:profile.patches)if(!MatchAt(changed,p.offset,p.after)){error="Internal patch verification failed.";return false;}
    HANDLE h=CreateFileW(output.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE){error="Could not create output file (it may already exist).";return false;}
    DWORD written=0;bool ok=WriteFile(h,changed.data(),static_cast<DWORD>(changed.size()),&written,nullptr)&&written==changed.size();
    CloseHandle(h);
    if(!ok){DeleteFileW(output.c_str());error="Failed while writing the patched DLL.";return false;}
    return true;
}
static bool InstallWithBackup(const fs::path& input,const Bytes& original,const Profile& profile,fs::path& finalDll,fs::path& backup,std::string& error){
    std::error_code ec;
    const fs::path absoluteInput=fs::absolute(input,ec).lexically_normal();
    if(ec){error="Could not resolve the input path.";return false;}
    const fs::path target=absoluteInput.parent_path()/L"hyperhv.dll";
    backup=fs::path(absoluteInput.wstring()+L".bak");
    auto samePath=[](const fs::path& a,const fs::path& b){
        return CompareStringOrdinal(a.c_str(),-1,b.c_str(),-1,TRUE)==CSTR_EQUAL;
    };
    if(fs::exists(backup)){error="Backup already exists; no files were changed: "+backup.string();return false;}
    if(fs::exists(target)&&!samePath(target,absoluteInput)){error="A different hyperhv.dll already exists beside the input; no files were changed: "+target.string();return false;}
    finalDll=target;
    fs::path staged=target.parent_path()/(L".hyperhv.patching."+std::to_wstring(GetCurrentProcessId())+L".tmp");
    if(!WritePatchedCopy(input,staged,original,profile,error))return false;
    if(!MoveFileExW(absoluteInput.c_str(),backup.c_str(),MOVEFILE_WRITE_THROUGH)){
        DeleteFileW(staged.c_str());error="Could not rename the original to its backup; no replacement was installed.";return false;
    }
    if(!MoveFileExW(staged.c_str(),target.c_str(),MOVEFILE_WRITE_THROUGH)){
        DWORD installError=GetLastError();
        if(MoveFileExW(backup.c_str(),absoluteInput.c_str(),MOVEFILE_WRITE_THROUGH)){
            DeleteFileW(staged.c_str());error="Could not install the patched DLL. The original was restored.";
        }else{
            error="Could not install the patched DLL, and automatic restore failed. Original backup is at "+backup.string()+"; staged patch is at "+staged.string()+" (Windows error "+std::to_string(installError)+").";
        }
        return false;
    }
    return true;
}

static std::optional<fs::path> PickDll(HWND owner=nullptr){
    wchar_t file[MAX_PATH]={};OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;
    ofn.hwndOwner=owner;
    ofn.lpstrFilter=L"hyperhv.dll (*.dll)\0*.dll\0All files (*.*)\0*.*\0";ofn.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(GetOpenFileNameW(&ofn))return fs::path(file);return std::nullopt;
}
static std::optional<fs::path> PickOutput(const fs::path& input){
    wchar_t file[MAX_PATH]={};std::wstring suggestion=input.stem().wstring()+L".patched.dll";wcsncpy_s(file,suggestion.c_str(),_TRUNCATE);
    OPENFILENAMEW ofn{};ofn.lStructSize=sizeof(ofn);ofn.lpstrFile=file;ofn.nMaxFile=MAX_PATH;
    ofn.lpstrFilter=L"DLL file (*.dll)\0*.dll\0All files (*.*)\0*.*\0";ofn.Flags=OFN_PATHMUSTEXIST|OFN_OVERWRITEPROMPT;ofn.lpstrDefExt=L"dll";
    if(GetSaveFileNameW(&ofn))return fs::path(file);return std::nullopt;
}

static int Run(const std::vector<std::wstring>& args,bool guiMode=false){
    bool experimental=false,scanOnly=false;std::vector<std::wstring> positional;
    for(const auto& a:args){if(a==L"--experimental")experimental=true;else if(a==L"--scan-only")scanOnly=true;else if(a==L"--help"||a==L"-h"){std::wcout<<L"HyperHvDllPatcher [--experimental] <hyperhv.dll>\nThe original is backed up as <input>.bak and the patched file is installed as hyperhv.dll.\n";return 0;}else positional.push_back(a);}
    if(positional.size()>1){std::wcerr<<L"Supply one input DLL. The patcher installs the result as hyperhv.dll and saves the original as <input>.bak.\n";return 2;}
    const bool gui=guiMode||positional.empty();
    fs::path input;
    if(positional.empty()){auto p=PickDll();if(!p)return 0;input=*p;}else input=positional[0];
    std::ifstream in(input,std::ios::binary);if(!in){std::wcerr<<L"Cannot open input DLL.\n";return 2;}
    Bytes bytes((std::istreambuf_iterator<char>(in)),std::istreambuf_iterator<char>());in.close();if(bytes.empty()){std::wcerr<<L"Input DLL is empty.\n";return 2;}

    if(scanOnly){Profile p{};bool already=false;std::string error;if(!FindExperimental(bytes,p,already,error)){std::cerr<<"SCAN REFUSED: "<<error<<"\n";return 3;}for(const auto& x:p.patches)std::cout<<x.label<<" offset=0x"<<std::hex<<x.offset<<" before="<<Hex(x.before)<<" after="<<Hex(x.after)<<"\n";return 0;}
    auto original=MatchOriginalProfile(bytes);
    if(!original){auto done=MatchPatchedProfile(bytes);if(done){std::string m="Already patched: "+*done+". No output was written.";if(gui)MessageBoxA(nullptr,m.c_str(),"Already patched",MB_OK|MB_ICONINFORMATION);else std::cout<<m<<"\n";return 0;}}
    Profile profile{};
    if(original)profile=*original;
    else {
        if(!experimental&&!gui){std::string m="Unsupported hyperhv.dll layout. No bytes were changed. Retry with --experimental to request the conservative built-in scan.";std::cerr<<m<<"\n";return 3;}
        if(gui && MessageBoxW(nullptr,L"This DLL is not one of the reviewed builds. Try the experimental internal PE/x64 scan? It refuses ambiguous matches. The original will be backed up before replacement.",L"Experimental mode",MB_YESNO|MB_ICONWARNING)!=IDYES)return 0;
        bool already=false;std::string error;if(!FindExperimental(bytes,profile,already,error)){std::string m="Experimental scan refused to patch: "+error+" No bytes were changed.";if(gui)MessageBoxA(nullptr,m.c_str(),"Experimental scan refused",MB_OK|MB_ICONWARNING);else std::cerr<<m<<"\n";return 4;}
        if(already){std::string m="Already patched: experimental EPT layout. No output was written.";if(gui)MessageBoxA(nullptr,m.c_str(),"Already patched",MB_OK|MB_ICONINFORMATION);else std::cout<<m<<"\n";return 0;}
    }
    fs::path output,backup;
    std::string error;if(!InstallWithBackup(input,bytes,profile,output,backup,error)){if(gui)MessageBoxA(nullptr,error.c_str(),"Patch not installed",MB_OK|MB_ICONERROR);else std::cerr<<error<<"\n";return 5;}
    std::string message="Patched "+std::string(profile.name)+". Original backup: "+backup.string()+". Installed as: "+output.string()+".";
    if(profile.name==std::string("Experimental PE/x64 semantic match"))message="EXPERIMENTAL patch installed. Original backup: "+backup.string()+". Installed as: "+output.string()+". Review before use.";
    if(gui)MessageBoxA(nullptr,message.c_str(),"Patch installed",MB_OK|(profile.name==std::string("Experimental PE/x64 semantic match")?MB_ICONWARNING:MB_ICONINFORMATION));else std::cout<<message<<"\n";
    return 0;
}

enum : int { IDC_TITLE=101,IDC_SUBTITLE,IDC_ERROR,IDC_PICK_LABEL,IDC_PATH,IDC_BROWSE,IDC_PATCH_INFO,IDC_DESCRIPTION,IDC_BACKUP,IDC_STATUS,IDC_PATCH,IDC_FOOTER };
static HFONT g_font{},g_fontTitle{},g_fontBold{};
static HBRUSH g_background{},g_header{},g_card{},g_notice{};
static std::wstring g_selectedPath;

static HWND AddText(HWND parent,int id,const wchar_t* text,int x,int y,int w,int h,DWORD style=0){
    return CreateWindowExW(0,L"STATIC",text,WS_CHILD|WS_VISIBLE|SS_LEFT|style,x,y,w,h,parent,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
}
static HWND AddButton(HWND parent,int id,const wchar_t* text,int x,int y,int w,int h,DWORD style=0){
    return CreateWindowExW(0,L"BUTTON",text,WS_CHILD|WS_VISIBLE|WS_TABSTOP|style,x,y,w,h,parent,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),GetModuleHandleW(nullptr),nullptr);
}
static void SetFont(HWND parent,int id,HFONT font){SendMessageW(GetDlgItem(parent,id),WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);}
static void SetStatus(HWND window,const wchar_t* message){SetWindowTextW(GetDlgItem(window,IDC_STATUS),message);}

static LRESULT CALLBACK MainWindowProc(HWND window,UINT message,WPARAM wParam,LPARAM lParam){
    switch(message){
    case WM_CREATE:{
        g_font=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
        g_fontTitle=CreateFontW(-27,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
        g_fontBold=CreateFontW(-16,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");
        AddText(window,IDC_TITLE,L"Intel Hyper-V compatibility patch",34,23,690,38);
        AddText(window,IDC_SUBTITLE,L"For the service error: \"A hypervisor feature is not available to the user\"",36,67,690,26);
        AddText(window,IDC_ERROR,L"TARGET ERROR   0xC035001E",36,105,310,24,SS_CENTER);
        AddText(window,IDC_PICK_LABEL,L"Choose the hyperhv.dll used by the affected application",34,169,690,26);
        HWND path=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL|ES_READONLY,34,204,540,34,window,reinterpret_cast<HMENU>(IDC_PATH),GetModuleHandleW(nullptr),nullptr);
        (void)path;
        AddButton(window,IDC_BROWSE,L"Browse...",587,203,137,36,BS_PUSHBUTTON);
        AddText(window,IDC_PATCH_INFO,L"What this patch changes",34,262,690,26);
        AddText(window,IDC_DESCRIPTION,L"This targets an Intel EPT memory issue associated with 0xC035001E. It redirects EPT page-table allocations and frees to the DLL's pool helpers.",34,294,690,54);
        AddText(window,IDC_BACKUP,L"BACKUP  The selected original is saved with a .bak suffix. The patched DLL is installed as hyperhv.dll. Existing backups are never overwritten.",34,371,690,52);
        AddText(window,IDC_STATUS,L"Select a DLL to begin.",34,455,440,30);
        AddButton(window,IDC_PATCH,L"Patch DLL",514,446,210,48,BS_OWNERDRAW);
        AddText(window,IDC_FOOTER,L"EPT-related cause only: unrelated Hyper-V configuration errors need a different fix.",34,518,690,24);
        SetFont(window,IDC_TITLE,g_fontTitle);SetFont(window,IDC_SUBTITLE,g_font);SetFont(window,IDC_ERROR,g_fontBold);
        SetFont(window,IDC_PICK_LABEL,g_fontBold);SetFont(window,IDC_PATH,g_font);SetFont(window,IDC_BROWSE,g_font);
        SetFont(window,IDC_PATCH_INFO,g_fontBold);SetFont(window,IDC_DESCRIPTION,g_font);SetFont(window,IDC_BACKUP,g_font);SetFont(window,IDC_STATUS,g_font);
        SetFont(window,IDC_PATCH,g_fontBold);SetFont(window,IDC_FOOTER,g_font);
        EnableWindow(GetDlgItem(window,IDC_PATCH),FALSE);
        return 0;
    }
    case WM_ERASEBKGND:{
        HDC dc=reinterpret_cast<HDC>(wParam);RECT r{};GetClientRect(window,&r);FillRect(dc,&r,g_background);
        RECT header{0,0,r.right,148};FillRect(dc,&header,g_header);
        RECT card{24,250,r.right-24,347};FillRect(dc,&card,g_card);
        RECT note{24,360,r.right-24,435};FillRect(dc,&note,g_notice);
        return 1;
    }
    case WM_CTLCOLORSTATIC:{
        HDC dc=reinterpret_cast<HDC>(wParam);HWND control=reinterpret_cast<HWND>(lParam);int id=GetDlgCtrlID(control);
        SetBkMode(dc,TRANSPARENT);
        if(id==IDC_TITLE||id==IDC_SUBTITLE){SetTextColor(dc,RGB(246,249,255));return reinterpret_cast<LRESULT>(g_header);}
        if(id==IDC_ERROR){SetTextColor(dc,RGB(226,239,255));return reinterpret_cast<LRESULT>(g_header);}
        if(id==IDC_BACKUP){SetTextColor(dc,RGB(35,83,70));return reinterpret_cast<LRESULT>(g_notice);}
        if(id==IDC_PATCH_INFO||id==IDC_DESCRIPTION){SetTextColor(dc,RGB(40,52,69));return reinterpret_cast<LRESULT>(g_card);}
        if(id==IDC_STATUS){SetTextColor(dc,RGB(40,52,69));return reinterpret_cast<LRESULT>(g_background);}
        if(id==IDC_FOOTER){SetTextColor(dc,RGB(103,114,129));return reinterpret_cast<LRESULT>(g_background);}
        SetTextColor(dc,RGB(39,51,68));return reinterpret_cast<LRESULT>(g_background);
    }
    case WM_DRAWITEM:{
        auto* item=reinterpret_cast<DRAWITEMSTRUCT*>(lParam);if(item->CtlID==IDC_PATCH){
            COLORREF fill=(item->itemState&ODS_DISABLED)?RGB(165,177,190):RGB(27,105,91);
            HBRUSH brush=CreateSolidBrush(fill);FillRect(item->hDC,&item->rcItem,brush);DeleteObject(brush);
            SetBkMode(item->hDC,TRANSPARENT);SetTextColor(item->hDC,RGB(255,255,255));
            RECT text=item->rcItem;DrawTextW(item->hDC,L"Patch DLL",-1,&text,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            if(item->itemState&ODS_FOCUS)DrawFocusRect(item->hDC,&item->rcItem);return TRUE;
        }break;
    }
    case WM_COMMAND:{
        const int id=LOWORD(wParam);
        if(id==IDC_BROWSE){auto path=PickDll(window);if(path){g_selectedPath=path->wstring();SetWindowTextW(GetDlgItem(window,IDC_PATH),g_selectedPath.c_str());SetStatus(window,L"Ready. The patcher will verify the DLL before changing anything.");EnableWindow(GetDlgItem(window,IDC_PATCH),TRUE);}return 0;}
        if(id==IDC_PATCH){
            if(g_selectedPath.empty())return 0;
            EnableWindow(GetDlgItem(window,IDC_PATCH),FALSE);EnableWindow(GetDlgItem(window,IDC_BROWSE),FALSE);
            SetStatus(window,L"Checking the DLL and preparing a verified patch...");UpdateWindow(window);
            int result=Run({g_selectedPath},true);
            if(result==0)SetStatus(window,L"Finished. See the result message for the backup and installed file paths.");
            else SetStatus(window,L"No patch was installed. See the message for details; your original remains available.");
            EnableWindow(GetDlgItem(window,IDC_BROWSE),TRUE);EnableWindow(GetDlgItem(window,IDC_PATCH),TRUE);return 0;
        }break;
    }
    case WM_DESTROY:
        if(g_font)DeleteObject(g_font);if(g_fontTitle)DeleteObject(g_fontTitle);if(g_fontBold)DeleteObject(g_fontBold);
        if(g_background)DeleteObject(g_background);if(g_header)DeleteObject(g_header);if(g_card)DeleteObject(g_card);if(g_notice)DeleteObject(g_notice);
        PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(window,message,wParam,lParam);
}

static int RunGui(){
    HWND console=GetConsoleWindow();if(console)ShowWindow(console,SW_HIDE);
    g_background=CreateSolidBrush(RGB(246,248,251));g_header=CreateSolidBrush(RGB(27,43,67));
    g_card=CreateSolidBrush(RGB(255,255,255));g_notice=CreateSolidBrush(RGB(229,243,237));
    INITCOMMONCONTROLSEX controls{sizeof(controls),ICC_STANDARD_CLASSES};InitCommonControlsEx(&controls);
    HINSTANCE instance=GetModuleHandleW(nullptr);WNDCLASSEXW wc{};wc.cbSize=sizeof(wc);wc.hInstance=instance;wc.lpfnWndProc=MainWindowProc;
    wc.lpszClassName=L"HyperHvPatcherMainWindow";wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hIcon=LoadIconW(nullptr,IDI_APPLICATION);wc.hbrBackground=g_background;
    if(!RegisterClassExW(&wc)){MessageBoxW(nullptr,L"Could not start the patcher window.",L"HyperHv patcher",MB_OK|MB_ICONERROR);return 1;}
    HWND window=CreateWindowExW(0,wc.lpszClassName,L"HyperHv Intel Hyper-V Patch",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,770,615,nullptr,nullptr,instance,nullptr);
    if(!window)return 1;ShowWindow(window,SW_SHOW);UpdateWindow(window);
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}return static_cast<int>(msg.wParam);
}

int wmain(int argc,wchar_t** argv){
    if(argc==1)return RunGui();
    std::vector<std::wstring> args;for(int i=1;i<argc;i++)args.emplace_back(argv[i]);return Run(args);
}
