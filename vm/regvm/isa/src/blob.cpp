#include "wvmp/regvm/isa/blob.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

namespace wvmp::regvm::isa {
namespace {

constexpr char kMagic[4] = {'W', 'V', 'M', 'P'};
constexpr u16 kVersion = 1;

} // namespace

VmBlob make_blob(ir::Arch arch, u32 entry_offset, std::vector<u8> stream) {
    if (stream.size() % 8 != 0)
        throw std::runtime_error("regvm isa: blob stream size must be a multiple of 8");
    if (entry_offset % 8 != 0 || entry_offset > stream.size())
        throw std::runtime_error("regvm isa: entry_offset out of range");
    VmBlob blob;
    std::memcpy(blob.header.magic, kMagic, 4);
    blob.header.version = kVersion;
    blob.header.arch = static_cast<u16>(arch);
    blob.header.entry_offset = entry_offset;
    blob.header.insn_count = static_cast<u32>(stream.size() / 8);
    blob.header.seed = 0;
    blob.header.reserved = 0;
    blob.header.reserved2 = 0;
    blob.header.reserved3 = 0;
    blob.stream = std::move(stream);
    return blob;
}

void write_blob(ByteWriter& w, const VmBlob& blob) {
    w.write_bytes({reinterpret_cast<const u8*>(blob.header.magic), 4});
    w.write_u16(blob.header.version);
    w.write_u16(blob.header.arch);
    w.write_u32(blob.header.entry_offset);
    w.write_u32(blob.header.insn_count);
    w.write_u32(blob.header.seed);
    w.write_u32(blob.header.reserved);
    w.write_u32(blob.header.reserved2);
    w.write_u32(blob.header.reserved3);
    w.write_bytes(blob.stream);
}

VmBlob read_blob(ByteReader& r) {
    if (r.remaining() < sizeof(VmBlobHeader))
        throw std::runtime_error("regvm isa: blob header truncated");
    VmBlob blob;
    for (int i = 0; i < 4; ++i) blob.header.magic[i] = static_cast<char>(r.read_u8());
    if (std::memcmp(blob.header.magic, kMagic, 4) != 0)
        throw std::runtime_error("regvm isa: bad blob magic");
    blob.header.version = r.read_u16();
    if (blob.header.version != kVersion)
        throw std::runtime_error("regvm isa: unsupported blob version " +
                                 std::to_string(blob.header.version));
    blob.header.arch = r.read_u16();
    blob.header.entry_offset = r.read_u32();
    blob.header.insn_count = r.read_u32();
    blob.header.seed = r.read_u32();
    blob.header.reserved = r.read_u32();
    blob.header.reserved2 = r.read_u32();
    blob.header.reserved3 = r.read_u32();
    const size_t bytes = static_cast<size_t>(blob.header.insn_count) * 8;
    if (r.remaining() < bytes)
        throw std::runtime_error("regvm isa: blob truncated (count says " +
                                 std::to_string(bytes) + " bytes, have " +
                                 std::to_string(r.remaining()) + ")");
    blob.stream.assign(r.p + r.off, r.p + r.off + bytes);
    r.skip(bytes);
    return blob;
}

} // namespace wvmp::regvm::isa
