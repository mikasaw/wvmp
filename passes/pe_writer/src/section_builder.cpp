#include "section_builder.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>

namespace wvmp::passes {
namespace {

u16 rd16(const u8* p) {
    return static_cast<u16>(static_cast<u16>(p[0]) | (static_cast<u16>(p[1]) << 8));
}
u32 rd32(const u8* p) {
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) |
           (static_cast<u32>(p[2]) << 16) | (static_cast<u32>(p[3]) << 24);
}
void wr16(u8* p, u16 v) {
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
}
void wr32(u8* p, u32 v) {
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

u64 align_up(u64 v, u64 a) {
    return a == 0 ? v : ((v + a - 1) / a) * a;
}

[[noreturn]] void fail(const std::string& what) {
    throw std::runtime_error("add_sections: " + what);
}

} // namespace

std::vector<SectionPlacement> add_sections(std::vector<u8>& image,
                                           const std::vector<NewSection>& requests,
                                           u32 section_alignment, u32 file_alignment) {
    if (requests.empty()) return {};
    if (image.size() < 0x40) fail("image too small");
    if (image[0] != 'M' || image[1] != 'Z') fail("no MZ");
    const size_t nt = rd32(&image[0x3C]);
    if (nt + 24 + 64 > image.size()) fail("e_lfanew out of range");
    if (rd32(&image[nt]) != 0x0000'4550) fail("no PE signature");
    if (section_alignment == 0 || file_alignment == 0) fail("zero alignment");

    const u16 num_sections = rd16(&image[nt + 6]);
    const u16 opt_size = rd16(&image[nt + 20]);
    const size_t table = nt + 24 + opt_size;
    if (table + static_cast<size_t>(num_sections) * 40 > image.size())
        fail("section table out of range");

    // 头部可用上限：首个非零 PointerToRawData（原始数据前全是头的地盘）。
    size_t header_limit = image.size();
    u32 size_of_headers = rd32(&image[nt + 24 + 60]); // OptionalHeader.SizeOfHeaders
    if (size_of_headers != 0) header_limit = std::min<size_t>(header_limit, size_of_headers);
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = table + static_cast<size_t>(i) * 40;
        const u32 raw_ptr = rd32(&image[sh + 20]);
        if (raw_ptr != 0) header_limit = std::min<size_t>(header_limit, raw_ptr);
    }
    const size_t new_table_end = table + (static_cast<size_t>(num_sections) + requests.size()) * 40;
    if (new_table_end > header_limit)
        fail("no room in headers for " + std::to_string(requests.size()) + " more entries (" +
             std::to_string(new_table_end) + " > " + std::to_string(header_limit) + ")");

    // 既有节的虚拟/文件末端。
    u64 max_va_end = 0;
    u64 max_raw_end = 0;
    struct Existing {
        u32 va, len;
    };
    std::vector<Existing> existing;
    existing.reserve(num_sections);
    for (u16 i = 0; i < num_sections; ++i) {
        const size_t sh = table + static_cast<size_t>(i) * 40;
        const u32 vsize = rd32(&image[sh + 8]);
        const u32 va = rd32(&image[sh + 12]);
        const u32 rsize = rd32(&image[sh + 16]);
        const u32 rptr = rd32(&image[sh + 20]);
        existing.push_back({va, std::max(vsize, rsize)});
        if (va != 0) max_va_end = std::max<u64>(max_va_end, align_up(u64(va) + std::max(vsize, rsize), section_alignment));
        if (rptr != 0) max_raw_end = std::max<u64>(max_raw_end, u64(rptr) + rsize);
    }
    if (max_raw_end == 0) max_raw_end = align_up(header_limit, file_alignment);
    max_raw_end = std::max<u64>(max_raw_end, align_up(image.size(), file_alignment));

    // —— 阶段 1：先把完整落位表算出来（auto 与 fixed 混排同一次走完）——
    // MIT-414 (G7p2 B.4): 追加节必须与前一节 VA 连续（对齐后 start == prev
    // end）。Windows 加载器拒绝带空洞的节布局（triage §3.3 实测：craft32 既有
    // 节末端 0x5000，.wvmp 落 0x5000 可加载、0x6000 起全拒 WinError 193——
    // pe_loader PE32 bug 把 section_alignment 误读为 0x400000 正是踩此）。
    //
    // CR-08 (MIT-528) 的病灶是"校验一套、写盘另一套"：旧校验段把 fixed 请求
    // 的末端推进进 max_va_end，落位段又拿这个被推过的值当 auto 游标初值 ⇒
    // 审核实测期望 [0x2000,0x3000]、实写 [0x4000,0x3000]（节 RVA 逆序 + 意外
    // VA 空洞）。现以 run_end 为唯一顺序游标：它起于既有节对齐末端，只被"已
    // 落位的这一份表"推进，fixed 请求要么严丝合缝接上它、要么显式失败；校验
    // 与写盘共用 placed，不再存在第二个游标。
    std::vector<SectionPlacement> placed;
    placed.reserve(requests.size());
    u64 run_end = align_up(max_va_end, section_alignment);
    u64 next_raw = align_up(max_raw_end, file_alignment);
    for (const auto& req : requests) {
        if (req.name.size() > 8) fail("section name '" + req.name + "' longer than 8 bytes");
        if (req.data.empty()) fail("section '" + req.name + "' has no data");

        const u64 begin = req.requested_rva != 0 ? req.requested_rva : run_end;
        const u64 end = align_up(begin + req.data.size(), section_alignment);
        if (req.requested_rva != 0 && max_va_end != 0 && begin != run_end)
            fail("requested RVA 0x" + std::to_string(req.requested_rva) +
                 " not contiguous with previous section end 0x" +
                 std::to_string(run_end) +
                 " (section VA gap; Windows loader rejects such images)");
        for (const auto& e : existing) {
            if (e.va == 0) continue;
            const u64 eb = e.va, ee = align_up(u64(e.va) + e.len, section_alignment);
            if (begin < ee && eb < end)
                fail("requested RVA 0x" + std::to_string(begin) + " overlaps existing section");
        }
        // 无既有节时 fixed 请求可浮动（保持旧口径），此时按本批已落位节兜底，
        // 免得两枚浮动请求叠在同一 RVA 上写出静默重叠的节表。
        for (size_t j = 0; j < placed.size(); ++j) {
            const u64 jb = placed[j].rva;
            const u64 je = align_up(jb + requests[j].data.size(), section_alignment);
            if (begin < je && jb < end)
                fail("requested RVA 0x" + std::to_string(begin) +
                     " overlaps a previously placed new section");
        }

        SectionPlacement p;
        p.rva = static_cast<u32>(begin);
        p.file_offset = static_cast<u32>(next_raw);
        p.raw_size = static_cast<u32>(align_up(req.data.size(), file_alignment));
        placed.push_back(p);
        next_raw += p.raw_size;
        run_end = end;
    }

    // —— 阶段 2：对这份表整体断言（写盘前的最后一道，成文的契约）——
    // add_sections 的既有契约在混排下同样成立：与既有节末端连续、表序 RVA
    // 严格单调（stub_link 的固定地址路径按"表序 == 地址序"烘焙 rel32）。
    // 不成立即失败，绝不产出逆序布局。
    u64 chain = align_up(max_va_end, section_alignment);
    for (size_t i = 0; i < placed.size(); ++i) {
        if (max_va_end != 0 && placed[i].rva != chain)
            fail("placement #" + std::to_string(i) + " RVA 0x" + std::to_string(placed[i].rva) +
                 " breaks the contiguous run at 0x" + std::to_string(chain));
        if (i > 0 && placed[i].rva <= placed[i - 1].rva)
            fail("section RVA order not monotonically increasing at #" + std::to_string(i));
        chain = align_up(u64(placed[i].rva) + requests[i].data.size(), section_alignment);
    }

    // —— 阶段 3：修改字节（只用上面这份 placed）——
    // 1) 数据区：文件尾补齐对齐垫片后写入各节数据 + 垫片。
    if (image.size() < max_raw_end)
        image.resize(static_cast<size_t>(max_raw_end), 0);
    for (size_t i = 0; i < requests.size(); ++i) {
        image.resize(placed[i].file_offset, 0);
        image.insert(image.end(), requests[i].data.begin(), requests[i].data.end());
        image.resize(static_cast<size_t>(placed[i].file_offset) + placed[i].raw_size, 0);
    }
    // 2) 节表：追加表项。
    for (size_t i = 0; i < requests.size(); ++i) {
        u8* sh = &image[table + (static_cast<size_t>(num_sections) + i) * 40];
        std::memset(sh, 0, 40);
        std::memcpy(sh, requests[i].name.data(),
                    std::min<size_t>(requests[i].name.size(), 8));
        wr32(sh + 8, static_cast<u32>(requests[i].data.size()));  // VirtualSize
        wr32(sh + 12, placed[i].rva);                              // VirtualAddress
        wr32(sh + 16, placed[i].raw_size);                         // SizeOfRawData
        wr32(sh + 20, placed[i].file_offset);                      // PointerToRawData
        wr32(sh + 36, requests[i].characteristics);                // Characteristics
    }
    // 3) 头部计数与镜像大小（SizeOfImage == 连续链末端，与校验所用同源）。
    wr16(&image[nt + 6], static_cast<u16>(num_sections + requests.size()));
    wr32(&image[nt + 24 + 56], static_cast<u32>(align_up(chain, section_alignment)));
    return placed;
}

} // namespace wvmp::passes
