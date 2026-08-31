/* MIT-437 (X1a): x86 marker E2E 样本主程序（配合 x86_marker_sample.asm）。
 * 仅调用两个标记区域函数；样本是扫描 fixture（构建期跑一次 rc=0 哨兵，
 * 证明 412 §6 三坑规避成立），非虚拟化交付物。 */
void rgn_one(void);
void rgn_two(void);

int main(void) {
    rgn_one();
    rgn_two();
    return 0;
}
