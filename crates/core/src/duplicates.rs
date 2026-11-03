//! 重复文件查找：按大小 → 前缀哈希 → 全文件哈希逐级筛选，尽量少读磁盘。
//!
//! * 不跟随符号链接/junction，跳过云占位文件（读取会触发下载）。
//! * 硬链接指向同一份数据，删掉其中一个并不会释放空间，所以不算重复。
//! * 只读，不修改任何文件。

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use same_file::Handle;

use crate::scanner::special_reason;

const MAX_DEPTH: usize = 256;
const READ_BUF: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct DupOptions {
    /// 小于该大小的文件忽略（至少为 1，空文件没有意义）。
    pub min_size: u64,
    /// 第二阶段只比较文件开头这么多字节。
    pub partial_bytes: usize,
}

impl Default for DupOptions {
    fn default() -> Self {
        Self {
            min_size: 1024 * 1024,
            partial_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DupFile {
    pub path: PathBuf,
    /// 修改时间（Unix 秒），用于推荐保留哪一份，以及删除前确认文件没变过。
    pub modified: u64,
}

#[derive(Debug, Clone)]
pub struct DupGroup {
    pub size: u64,
    /// 至少两个内容完全相同的文件。
    pub files: Vec<DupFile>,
}

impl DupGroup {
    /// 删到只剩一份能释放的字节数。
    pub fn wasted(&self) -> u64 {
        self.size * (self.files.len() as u64 - 1)
    }

    /// 推荐保留的文件下标：最早修改的；相同则取路径最短、再按字典序。
    pub fn suggested_keep(&self) -> usize {
        self.files
            .iter()
            .enumerate()
            .min_by_key(|(_, f)| (f.modified, f.path.as_os_str().len(), f.path.clone()))
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DupPhase {
    /// 遍历目录收集候选文件。
    Walking,
    /// 对同大小文件比较开头。
    PartialHash,
    /// 对仍然相同的文件做完整哈希。
    FullHash,
}

#[derive(Debug, Clone, Copy)]
pub struct DupProgress {
    pub phase: DupPhase,
    /// 当前阶段已处理的文件数。
    pub done: u64,
    /// 当前阶段预计要处理的文件数（遍历阶段未知，为 0）。
    pub total: u64,
}

#[derive(Debug, Default)]
pub struct DupOutcome {
    /// 按可释放空间从大到小排列。
    pub groups: Vec<DupGroup>,
    pub scanned_files: u64,
    /// 读取失败而被放弃的文件数。
    pub errors: u64,
    pub cancelled: bool,
}

struct Candidate {
    path: PathBuf,
    modified: u64,
}

fn mtime_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// 在 `root` 下查找重复文件。
pub fn find_duplicates(
    root: &Path,
    opts: &DupOptions,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(DupProgress),
) -> io::Result<DupOutcome> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || special_reason(&meta).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root must be a real directory",
        ));
    }
    let min_size = opts.min_size.max(1);
    let mut out = DupOutcome::default();

    // 阶段 1：按大小分组。
    let mut by_size: HashMap<u64, Vec<Candidate>> = HashMap::new();
    let mut seen = 0u64;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            out.cancelled = true;
            return Ok(out);
        }
        let Ok(rd) = fs::read_dir(&dir) else {
            out.errors += 1;
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else {
                out.errors += 1;
                continue;
            };
            if special_reason(&m).is_some() {
                continue;
            }
            if m.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((e.path(), depth + 1));
                }
            } else if m.is_file() {
                out.scanned_files += 1;
                if m.len() >= min_size {
                    by_size.entry(m.len()).or_default().push(Candidate {
                        path: e.path(),
                        modified: mtime_secs(&m),
                    });
                }
            }
            seen += 1;
            if seen.is_multiple_of(2000) {
                on_progress(DupProgress {
                    phase: DupPhase::Walking,
                    done: out.scanned_files,
                    total: 0,
                });
            }
        }
    }
    on_progress(DupProgress {
        phase: DupPhase::Walking,
        done: out.scanned_files,
        total: 0,
    });

    let mut size_groups: Vec<(u64, Vec<Candidate>)> =
        by_size.into_iter().filter(|(_, v)| v.len() > 1).collect();
    // 硬链接合并为一个，只保留第一个路径。
    for (_, files) in &mut size_groups {
        collapse_hard_links(files);
    }
    size_groups.retain(|(_, v)| v.len() > 1);

    // 阶段 2：前缀哈希。
    let total: u64 = size_groups.iter().map(|(_, v)| v.len() as u64).sum();
    let mut done = 0u64;
    let mut partial_groups: Vec<(u64, Vec<Candidate>)> = Vec::new();
    for (size, files) in size_groups {
        let mut by_hash: HashMap<[u8; 32], Vec<Candidate>> = HashMap::new();
        for c in files {
            if cancel.load(Ordering::Relaxed) {
                out.cancelled = true;
                return Ok(out);
            }
            match hash_file(&c.path, Some(opts.partial_bytes), cancel) {
                Ok(Some(h)) => by_hash.entry(h).or_default().push(c),
                Ok(None) => {
                    out.cancelled = true;
                    return Ok(out);
                }
                Err(_) => out.errors += 1,
            }
            done += 1;
            on_progress(DupProgress {
                phase: DupPhase::PartialHash,
                done,
                total,
            });
        }
        partial_groups.extend(
            by_hash
                .into_values()
                .filter(|v| v.len() > 1)
                .map(|v| (size, v)),
        );
    }

    // 阶段 3：完整哈希。文件不超过前缀长度时，前缀哈希就是完整哈希，无需重读。
    let total: u64 = partial_groups.iter().map(|(_, v)| v.len() as u64).sum();
    let mut done = 0u64;
    for (size, files) in partial_groups {
        let mut by_hash: HashMap<[u8; 32], Vec<Candidate>> = HashMap::new();
        for c in files {
            if cancel.load(Ordering::Relaxed) {
                out.cancelled = true;
                return Ok(out);
            }
            let limit = if size <= opts.partial_bytes as u64 {
                Some(opts.partial_bytes)
            } else {
                None
            };
            match hash_file(&c.path, limit, cancel) {
                Ok(Some(h)) => by_hash.entry(h).or_default().push(c),
                Ok(None) => {
                    out.cancelled = true;
                    return Ok(out);
                }
                Err(_) => out.errors += 1,
            }
            done += 1;
            on_progress(DupProgress {
                phase: DupPhase::FullHash,
                done,
                total,
            });
        }
        for (_, v) in by_hash.into_iter().filter(|(_, v)| v.len() > 1) {
            let mut files: Vec<DupFile> = v
                .into_iter()
                .map(|c| DupFile {
                    path: c.path,
                    modified: c.modified,
                })
                .collect();
            files.sort_by(|a, b| a.path.cmp(&b.path));
            out.groups.push(DupGroup { size, files });
        }
    }

    out.groups.sort_by(|a, b| {
        b.wasted()
            .cmp(&a.wasted())
            .then_with(|| a.files[0].path.cmp(&b.files[0].path))
    });
    Ok(out)
}

/// 指向同一份数据的多个路径只留第一个。无法打开的文件保留（后续哈希阶段会如实记录错误）。
fn collapse_hard_links(files: &mut Vec<Candidate>) {
    let mut handles: Vec<Handle> = Vec::new();
    files.retain(|c| match Handle::from_path(&c.path) {
        Ok(h) => {
            if handles.contains(&h) {
                false
            } else {
                handles.push(h);
                true
            }
        }
        Err(_) => true,
    });
}

/// 对文件内容（或前 `limit` 字节）做 blake3。被取消时返回 `Ok(None)`。
fn hash_file(
    path: &Path,
    limit: Option<usize>,
    cancel: &AtomicBool,
) -> io::Result<Option<[u8; 32]>> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; READ_BUF];
    let mut remaining = limit.map(|l| l as u64);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let want = match remaining {
            Some(0) => break,
            Some(r) => buf.len().min(r as usize),
            None => buf.len(),
        };
        let n = f.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        if let Some(r) = remaining.as_mut() {
            *r -= n as u64;
        }
    }
    Ok(Some(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static N: AtomicU64 = AtomicU64::new(0);

    struct Sandbox(PathBuf);
    impl Sandbox {
        fn new() -> Self {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!("dc-dup-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Sandbox(d)
        }
        fn write(&self, rel: &str, data: &[u8]) -> PathBuf {
            let p = self.0.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, data).unwrap();
            p
        }
    }
    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn opts(min: u64) -> DupOptions {
        DupOptions {
            min_size: min,
            partial_bytes: 1024,
        }
    }

    fn run(sb: &Sandbox, o: &DupOptions) -> DupOutcome {
        find_duplicates(&sb.0, o, &AtomicBool::new(false), &mut |_| {}).unwrap()
    }

    fn names(g: &DupGroup, root: &Path) -> Vec<String> {
        g.files
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn finds_identical_files_across_directories() {
        let sb = Sandbox::new();
        sb.write("a/one.bin", &[7u8; 5000]);
        sb.write("b/deep/two.bin", &[7u8; 5000]);
        sb.write("c/three.bin", &[7u8; 5000]);
        sb.write("c/other.bin", &[8u8; 5000]);
        let out = run(&sb, &opts(1));
        assert_eq!(out.groups.len(), 1);
        let g = &out.groups[0];
        assert_eq!(g.size, 5000);
        assert_eq!(
            names(g, &sb.0),
            ["a/one.bin", "b/deep/two.bin", "c/three.bin"]
        );
        assert_eq!(g.wasted(), 10_000);
        assert_eq!(out.scanned_files, 4);
    }

    #[test]
    fn same_size_different_content_is_not_a_duplicate() {
        let sb = Sandbox::new();
        sb.write("x.bin", &[1u8; 4000]);
        sb.write("y.bin", &[2u8; 4000]);
        assert!(run(&sb, &opts(1)).groups.is_empty());
    }

    #[test]
    fn files_that_differ_only_after_the_prefix_are_told_apart() {
        let sb = Sandbox::new();
        let mut a = vec![5u8; 10_000];
        let mut b = a.clone();
        let mut c = a.clone();
        a[9_999] = 1;
        b[9_999] = 2;
        c[9_999] = 1; // 与 a 完全相同
        sb.write("a.bin", &a);
        sb.write("b.bin", &b);
        sb.write("c.bin", &c);
        let out = run(&sb, &opts(1));
        assert_eq!(out.groups.len(), 1, "前缀相同但尾部不同的 b 不应被归入");
        assert_eq!(names(&out.groups[0], &sb.0), ["a.bin", "c.bin"]);
    }

    #[test]
    fn small_files_are_decided_by_the_prefix_hash_alone() {
        let sb = Sandbox::new();
        sb.write("s1", &[9u8; 100]);
        sb.write("s2", &[9u8; 100]);
        let out = run(&sb, &opts(1));
        assert_eq!(out.groups.len(), 1);
    }

    #[test]
    fn min_size_filters_out_small_files_and_empty_files_never_match() {
        let sb = Sandbox::new();
        sb.write("a", &[1u8; 500]);
        sb.write("b", &[1u8; 500]);
        sb.write("e1", b"");
        sb.write("e2", b"");
        assert!(run(&sb, &opts(1000)).groups.is_empty());
        let out = run(&sb, &opts(0));
        assert_eq!(out.groups.len(), 1, "空文件不能成组");
    }

    #[test]
    fn groups_are_ordered_by_reclaimable_space() {
        let sb = Sandbox::new();
        sb.write("small1", &[1u8; 2000]);
        sb.write("small2", &[1u8; 2000]);
        sb.write("big1", &[2u8; 9000]);
        sb.write("big2", &[2u8; 9000]);
        sb.write("big3", &[2u8; 9000]);
        let out = run(&sb, &opts(1));
        assert_eq!(
            out.groups.iter().map(|g| g.wasted()).collect::<Vec<_>>(),
            [18_000, 2_000]
        );
    }

    #[cfg(unix)]
    #[test]
    fn hard_links_and_symlinks_are_not_duplicates() {
        let sb = Sandbox::new();
        let orig = sb.write("orig.bin", &[3u8; 4000]);
        fs::hard_link(&orig, sb.0.join("hard.bin")).unwrap();
        std::os::unix::fs::symlink(&orig, sb.0.join("sym.bin")).unwrap();
        assert!(run(&sb, &opts(1)).groups.is_empty());

        // 再加一份真正独立的副本，应只与其中一个硬链接成组（共两个路径，而不是三个）。
        sb.write("copy.bin", &[3u8; 4000]);
        let out = run(&sb, &opts(1));
        assert_eq!(out.groups.len(), 1);
        assert_eq!(out.groups[0].files.len(), 2);
    }

    #[test]
    fn suggested_keep_prefers_oldest_then_shortest_path() {
        let g = DupGroup {
            size: 1,
            files: vec![
                DupFile {
                    path: "/x/long/name.bin".into(),
                    modified: 100,
                },
                DupFile {
                    path: "/x/a.bin".into(),
                    modified: 50,
                },
                DupFile {
                    path: "/x/b.bin".into(),
                    modified: 50,
                },
            ],
        };
        assert_eq!(g.suggested_keep(), 1);
    }

    #[test]
    fn cancel_stops_early() {
        let sb = Sandbox::new();
        sb.write("a", &[1u8; 3000]);
        sb.write("b", &[1u8; 3000]);
        let out = find_duplicates(&sb.0, &opts(1), &AtomicBool::new(true), &mut |_| {}).unwrap();
        assert!(out.cancelled);
        assert!(out.groups.is_empty());
    }

    #[test]
    fn root_must_be_a_directory_and_progress_is_reported() {
        let sb = Sandbox::new();
        let f = sb.write("f", b"x");
        assert!(find_duplicates(&f, &opts(1), &AtomicBool::new(false), &mut |_| {}).is_err());
        assert!(find_duplicates(
            &sb.0.join("nope"),
            &opts(1),
            &AtomicBool::new(false),
            &mut |_| {}
        )
        .is_err());

        sb.write("a", &[1u8; 3000]);
        sb.write("b", &[1u8; 3000]);
        let mut phases = Vec::new();
        find_duplicates(&sb.0, &opts(1), &AtomicBool::new(false), &mut |p| {
            phases.push(p.phase)
        })
        .unwrap();
        assert!(phases.contains(&DupPhase::Walking));
        assert!(phases.contains(&DupPhase::PartialHash));
        assert!(phases.contains(&DupPhase::FullHash));
    }
}
