// Isolated source-pattern reconstruction. NOT an actual CoreCLR test or an RCE.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma pack(push, 1)
struct HeaderV1 {
    std::uint8_t magic[4];
    std::uint16_t major, minor, sectionCount, relocIndex;
    std::uint32_t cliRva, cliSize, debugRva, debugSize, tableBase;
};
struct Section {std::uint32_t virtualSize, virtualAddress, rawSize, rawOffset;};
struct Block {std::uint32_t rva, size;};
#pragma pack(pop)
static_assert(sizeof(HeaderV1)==32, "webcil header");
static_assert(sizeof(Section)==16, "webcil section");

int main(int argc,char** argv) {
    const bool guarded=argc>1 && std::strcmp(argv[1],"guarded")==0;
    constexpr std::size_t length=96;
    auto* image=static_cast<std::uint8_t*>(std::calloc(length,1));
    if (!image) return 3;
    HeaderV1 h{};
    std::memcpy(h.magic,"WbIL",4);
    h.major=1;h.sectionCount=1;h.relocIndex=1;h.tableBase=1;
    Section s{12,48,12,48};
    Block b{96,10};
    std::uint16_t fixup=0;
    std::memcpy(image,&h,sizeof(h));
    std::memcpy(image+32,&s,sizeof(s));
    std::memcpy(image+48,&b,sizeof(b));
    std::memcpy(image+56,&fixup,sizeof(fixup));
    const auto* sections=reinterpret_cast<const Section*>(image+sizeof(h));
    const auto* block=reinterpret_cast<const Block*>(
        image+sections[h.relocIndex-1].rawOffset);
    const std::size_t target=block->rva+(fixup&0xfff);
    if (guarded && (target>length || sizeof(std::uint32_t)>length-target)) {
        std::puts("MODEL_GUARDED_REJECT=true");
        std::free(image);return 0;
    }
    std::printf("MODEL_ONLY: image=%zu, target=%zu, width=4\n",length,target);
    std::fflush(stdout);
    *reinterpret_cast<std::uint32_t*>(image+target)+=h.tableBase;
    std::free(image);
    return 0;
}
