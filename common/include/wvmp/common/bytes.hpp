#pragma once
#include "wvmp/common/types.hpp"
#include <cstddef>
#include <span>
#include <stdexcept>
#include <vector>

namespace wvmp {

// Little-endian bounded reader. Aggregate, so `ByteReader{p, n}` works and
// the cursor (off) is directly observable/adjustable by the caller.
// Any read/skip crossing `n` throws std::out_of_range.
class ByteReader {
public:
    const u8* p = nullptr;
    size_t n = 0;
    size_t off = 0;

    u8 read_u8();
    u16 read_u16();
    u32 read_u32();
    u64 read_u64();
    void skip(size_t bytes); // throws std::out_of_range past the end
    size_t remaining() const { return off <= n ? n - off : 0; }

private:
    void require(size_t bytes) const; // throws std::out_of_range if short
};

// Little-endian writer appending to an external buffer.
class ByteWriter {
public:
    explicit ByteWriter(std::vector<u8>& buf) : buf_(buf) {}

    void write_u8(u8 v);
    void write_u16(u16 v);
    void write_u32(u32 v);
    void write_u64(u64 v);
    void write_bytes(std::span<const u8> bytes);
    void patch_u32(size_t offset, u32 v); // throws std::out_of_range if outside buf
    void patch_u64(size_t offset, u64 v); // throws std::out_of_range if outside buf

private:
    void patch_check(size_t offset, size_t len) const;
    std::vector<u8>& buf_;
};

} // namespace wvmp
