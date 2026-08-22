#include "wvmp/common/bytes.hpp"

namespace wvmp {
namespace {

template <class T>
T load_le(const u8* p) {
    T v = 0;
    for (size_t i = 0; i < sizeof(T); ++i)
        v = static_cast<T>(v | (static_cast<T>(p[i]) << (8 * i)));
    return v;
}

template <class T>
void store_le(u8* p, T v) {
    for (size_t i = 0; i < sizeof(T); ++i)
        p[i] = static_cast<u8>(static_cast<u64>(v >> (8 * i)) & 0xFF);
}

} // namespace

void ByteReader::require(size_t bytes) const {
    if (off > n || bytes > n - off)
        throw std::out_of_range("wvmp::ByteReader: read past end of buffer");
}

u8 ByteReader::read_u8() {
    require(1);
    return p[off++];
}

u16 ByteReader::read_u16() {
    require(2);
    u16 v = load_le<u16>(p + off);
    off += 2;
    return v;
}

u32 ByteReader::read_u32() {
    require(4);
    u32 v = load_le<u32>(p + off);
    off += 4;
    return v;
}

u64 ByteReader::read_u64() {
    require(8);
    u64 v = load_le<u64>(p + off);
    off += 8;
    return v;
}

void ByteReader::skip(size_t bytes) {
    require(bytes);
    off += bytes;
}

void ByteWriter::write_u8(u8 v) {
    buf_.push_back(v);
}

void ByteWriter::write_u16(u16 v) {
    const size_t at = buf_.size();
    buf_.resize(at + 2);
    store_le<u16>(buf_.data() + at, v);
}

void ByteWriter::write_u32(u32 v) {
    const size_t at = buf_.size();
    buf_.resize(at + 4);
    store_le<u32>(buf_.data() + at, v);
}

void ByteWriter::write_u64(u64 v) {
    const size_t at = buf_.size();
    buf_.resize(at + 8);
    store_le<u64>(buf_.data() + at, v);
}

void ByteWriter::write_bytes(std::span<const u8> bytes) {
    buf_.insert(buf_.end(), bytes.begin(), bytes.end());
}

void ByteWriter::patch_check(size_t offset, size_t len) const {
    if (offset > buf_.size() || len > buf_.size() - offset)
        throw std::out_of_range("wvmp::ByteWriter: patch outside buffer");
}

void ByteWriter::patch_u32(size_t offset, u32 v) {
    patch_check(offset, 4);
    store_le<u32>(buf_.data() + offset, v);
}

void ByteWriter::patch_u64(size_t offset, u64 v) {
    patch_check(offset, 8);
    store_le<u64>(buf_.data() + offset, v);
}

} // namespace wvmp
