#pragma once
// pe_writer 内部工具头：产物写出的"唯一临时名 + 原子替换"（CR-09 / MIT-528）
// + 写后读回逐字节校验（MIT-530）。
#include <cstddef>
#include <filesystem>

namespace wvmp::passes {

// 目标产物路径 → 同目录唯一临时文件路径。
// 名字 = <目标文件名> + ".wvmp-tmp-" + <pid> + "-" + <进程内递增序号> + "-" + <16 位随机尾>。
//  - 与目标同目录是硬要求：跨卷改名不是原子操作（Windows 直接失败）；
//  - 唯一后缀消灭旧"固定 .wvmp-tmp 名 ⇒ 同一目标的并发写入共用一份 tmp"。
std::filesystem::path make_temp_output_path(const std::filesystem::path& target);

// 读回 tmp 全文与镜像逐字节比对（MIT-530）。写满≠写对：核长只能挡半写，
// 挡不住"等长错字节"（掉电后文件系统回滚异常一类），只有读回能暴露。
// 失败返回 false 并在 err 里点名首处差异偏移；成功 err 不动。
bool verify_written_image(const std::filesystem::path& tmp,
                          const unsigned char* expect_data,
                          std::size_t expect_size,
                          std::string& err);

// 原子替换 tmp → target（调用方**不得**先删目标）。失败返回 false 并给出 OS
// 错误文本；两种结局都不留半成品：成功 ⇒ 目标即新产物、tmp 消失；失败 ⇒ 旧
// 目标与新 tmp 原地都在，由调用方把两条路径一并报出去。
bool publish_atomic_output(const std::filesystem::path& tmp,
                           const std::filesystem::path& target,
                           std::string& err);

} // namespace wvmp::passes
