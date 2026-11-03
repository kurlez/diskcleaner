//! 用真实 NTFS 镜像（由 ntfs-3g 生成，见 fixtures/make_ntfs_fixture.sh）验证 MFT 扫描。

use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::atomic::AtomicBool;

use diskclean_core::mft::{scan_path, scan_volume, MftError};
use diskclean_core::scanner::Node;

const IMAGE_GZ: &[u8] = include_bytes!("fixtures/sample.ntfs.gz");
const EXPECTED: &str = include_str!("fixtures/sample.expected.tsv");
const CLUSTER: u64 = 4096;

fn image() -> Cursor<Vec<u8>> {
    let mut v = Vec::new();
    flate2::read::GzDecoder::new(IMAGE_GZ)
        .read_to_end(&mut v)
        .unwrap();
    Cursor::new(v)
}

/// 展平成 路径 -> (是目录, 大小)。
fn flatten(node: &Node, prefix: &str, out: &mut BTreeMap<String, (bool, u64)>) {
    for c in &node.children {
        let p = if prefix.is_empty() {
            c.name.clone()
        } else {
            format!("{prefix}/{}", c.name)
        };
        out.insert(p.clone(), (c.is_dir, c.size));
        flatten(c, &p, out);
    }
}

/// 预期条目：路径 -> (是目录, 逻辑大小)。
fn expected() -> BTreeMap<String, (bool, u64)> {
    EXPECTED
        .lines()
        .map(|l| {
            let mut it = l.splitn(3, '\t');
            let (ty, size, path) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
            (path.to_string(), (ty == "d", size.parse().unwrap()))
        })
        .collect()
}

fn scan() -> diskclean_core::scanner::ScanOutcome {
    scan_volume(image(), &AtomicBool::new(false), &mut |_| {}).unwrap()
}

#[test]
fn tree_matches_what_the_filesystem_contains() {
    let out = scan();
    let mut got = BTreeMap::new();
    flatten(&out.root, "", &mut got);
    let exp = expected();

    // 系统元数据文件（$MFT、$Extend 等）是 NTFS 自带的，测试数据里没有。
    let is_system = |p: &str| p.split('/').next().is_some_and(|c| c.starts_with('$'));
    let user: BTreeMap<_, _> = got.iter().filter(|(p, _)| !is_system(p)).collect();

    // 硬链接只应出现一次。
    let hard: Vec<_> = user.keys().filter(|p| p.starts_with("hard/")).collect();
    assert_eq!(hard.len(), 1, "hard link must appear once: {hard:?}");

    for (path, (is_dir, _)) in &exp {
        if path == "hard/orig.bin" || path == "hard/link.bin" {
            continue;
        }
        let (g_dir, _) = *got.get(path).unwrap_or_else(|| panic!("missing {path}"));
        assert_eq!(g_dir, *is_dir, "{path}");
    }
    // 没有多出来的条目（已删除的 gone.txt 必须不在其中）。
    let known: HashSet<_> = exp.keys().cloned().collect();
    for p in user.keys() {
        assert!(known.contains(*p), "unexpected entry {p}");
    }
    assert!(!got.contains_key("gone.txt"));
}

#[test]
fn sizes_are_space_on_disk() {
    let out = scan();
    let mut got = BTreeMap::new();
    flatten(&out.root, "", &mut got);
    let exp = expected();

    for (path, (is_dir, logical)) in &exp {
        if *is_dir || path.starts_with("hard/") || path == "sparse.bin" {
            continue;
        }
        let (_, size) = got[path];
        if *logical <= 500 {
            assert_eq!(
                size, *logical,
                "{path}: small files live inside the MFT record"
            );
        } else {
            assert!(size >= *logical, "{path}: {size} < {logical}");
            assert_eq!(size % CLUSTER, 0, "{path}: must be whole clusters");
            assert!(size < *logical + CLUSTER, "{path}: {size} vs {logical}");
        }
    }
    assert_eq!(got["docs/sub/deep/a.dat"].1, 8192);
    assert_eq!(got["docs/big.bin"].1, 262_144);
    // 10 MiB 稀疏文件只有两个真实簇，占用必须远小于逻辑大小。
    let sparse = got["sparse.bin"].1;
    assert!(
        sparse > 0 && sparse <= 4 * CLUSTER,
        "sparse file uses {sparse} bytes"
    );
}

#[test]
fn directory_totals_add_up() {
    let out = scan();
    let many = out.root.children.iter().find(|c| c.name == "many").unwrap();
    assert_eq!(many.children.len(), 300);
    assert_eq!(many.file_count, 300);
    assert_eq!(many.size, many.children.iter().map(|c| c.size).sum::<u64>());
    // 根的总量 = 各子项之和，且按大小降序排列。
    assert_eq!(
        out.root.size,
        out.root.children.iter().map(|c| c.size).sum::<u64>()
    );
    assert!(out.root.children.windows(2).all(|w| w[0].size >= w[1].size));
    let hard = out.root.children.iter().find(|c| c.name == "hard").unwrap();
    assert_eq!(hard.file_count, 1);
    assert_eq!(hard.size, 20_480, "hard-linked data counted once");
}

#[test]
fn unicode_and_case_are_preserved() {
    let out = scan();
    let mut got = BTreeMap::new();
    flatten(&out.root, "", &mut got);
    assert!(got.contains_key("unicode/文件.txt"));
    assert!(got.contains_key("UPPER/MiXed.TXT"));
}

#[test]
fn subtree_scan_by_path() {
    let out = scan_path(
        image(),
        Path::new(r"c:\DOCS\sub"),
        &AtomicBool::new(false),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out.root.name, "sub");
    assert_eq!(out.root.file_count, 1);
    assert_eq!(out.root.children[0].name, "deep");

    let whole = scan_path(
        image(),
        Path::new(r"C:\"),
        &AtomicBool::new(false),
        &mut |_| {},
    )
    .unwrap();
    assert!(whole.root.children.iter().any(|c| c.name == "docs"));

    let err = scan_path(
        image(),
        Path::new(r"C:\no\such\dir"),
        &AtomicBool::new(false),
        &mut |_| {},
    );
    assert!(matches!(err, Err(MftError::PathNotFound)));
    let rel = scan_path(
        image(),
        Path::new("relative"),
        &AtomicBool::new(false),
        &mut |_| {},
    );
    assert!(matches!(rel, Err(MftError::PathNotFound)));
}

#[test]
fn progress_and_cancellation() {
    let mut calls = 0;
    let mut last = Default::default();
    scan_volume(image(), &AtomicBool::new(false), &mut |p| {
        calls += 1;
        last = *p;
    })
    .unwrap();
    assert!(calls >= 1);
    assert!(last.files >= 310 && last.dirs >= 8, "{last:?}");

    let cancelled = scan_volume(image(), &AtomicBool::new(true), &mut |_| {}).unwrap();
    assert!(cancelled.cancelled);
}
