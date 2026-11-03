#!/usr/bin/env bash
# 重新生成 NTFS 测试夹具。需要 root、ntfs-3g（mkntfs）和可用的 FUSE。
# 产物：sample.ntfs.gz（压缩的 NTFS 镜像）与 sample.expected.tsv（`类型<TAB>逻辑大小<TAB>路径`）。
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
img="$work/sample.img"
mnt="$work/mnt"
mkdir -p "$mnt"
trap 'umount "$mnt" 2>/dev/null || true; rm -rf "$work"' EXIT

truncate -s 32M "$img"
mkntfs -F -Q -q -c 4096 -L fixture "$img" >/dev/null 2>&1
ntfs-3g -o rw "$img" "$mnt"

python3 - "$mnt" <<'PY'
import os, random, sys
root = sys.argv[1]
rnd = random.Random(42)
def w(rel, data):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'wb') as f: f.write(data)
w('docs/readme.txt', b'r' * 100)                       # 常驻数据（存在 MFT 记录里）
w('docs/big.bin', bytes(rnd.getrandbits(8) for _ in range(262144)))
w('docs/sub/deep/a.dat', b'a' * 5000)
os.makedirs(os.path.join(root, 'empty'))
w('unicode/文件.txt', b'u' * 1234)
for i in range(300):                                   # 目录索引会变成非常驻
    w(f'many/f{i:03d}.txt', b'm' * (50 + i))
w('hard/orig.bin', b'h' * 20000)
os.link(os.path.join(root, 'hard/orig.bin'), os.path.join(root, 'hard/link.bin'))
with open(os.path.join(root, 'sparse.bin'), 'wb') as f:  # 10 MiB 稀疏文件，只有两块真实数据
    f.truncate(10 * 1024 * 1024)
    f.seek(0); f.write(b's' * 4096)
    f.seek(5 * 1024 * 1024); f.write(b's' * 4096)
w('UPPER/MiXed.TXT', b'x' * 10)
w('gone.txt', b'g' * 3000)
os.remove(os.path.join(root, 'gone.txt'))              # 已删除：记录空闲，必须被忽略
PY
sync
find "$mnt" -mindepth 1 -printf '%y\t%s\t%P\n' | sort -t$'\t' -k3 > sample.expected.tsv
umount "$mnt"
gzip -9 -c "$img" > sample.ntfs.gz
ls -l sample.ntfs.gz sample.expected.tsv
