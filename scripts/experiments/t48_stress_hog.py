"""MIT-495 (T48) 内存压力 hog: 提交并触摸 N GB, 保持驻留使 commit 压力持续。

用法: python t48_stress_hog.py <GB>
生命周期由驱动脚本控制 (进程树 kill)。驻留期每 30s 轻触摸一次防被裁剪。
"""
import sys
import time

gb = int(sys.argv[1])
buf = bytearray(gb << 30)
# 全页触摸: 迫使物理/页面文件提交实化 (零页惰性提交不足以施压)。
page = 4096
for i in range(0, len(buf), page):
    buf[i] = 1
print("hog ready: %d GB committed+touched" % gb, flush=True)
while True:
    time.sleep(30)
    for i in range(0, len(buf), page << 10):
        buf[i] = (buf[i] + 1) & 0xFF
