//! 目录遍历式扫描器（MFT 快速扫描将在后续里程碑加入，接口保持一致）。
//!
//! * 不跟随符号链接、junction 等重解析点。
//! * Windows 下跳过 OneDrive 等云占位文件，避免触发下载。
//! * 支持取消与进度回调。

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_DEPTH: usize = 512;
const PROGRESS_EVERY: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// 符号链接 / junction / 挂载点。
    ReparsePoint,
    /// 云端占位文件（读取会触发下载）。
    CloudPlaceholder,
    /// 读取失败（权限不足、被占用、路径过深等）。
    Error,
}

#[derive(Debug, Clone)]
pub struct Skipped {
    pub path: PathBuf,
    pub reason: SkipReason,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub is_dir: bool,
    /// 逻辑大小（字节）；目录为其下所有文件之和。
    pub size: u64,
    /// 目录下的文件总数；文件为 1。
    pub file_count: u64,
    /// 按大小降序。
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Progress {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

#[derive(Debug)]
pub struct ScanOutcome {
    pub root: Node,
    pub skipped: Vec<Skipped>,
    pub cancelled: bool,
}

struct Ctx<'a> {
    cancel: &'a AtomicBool,
    on_progress: &'a mut dyn FnMut(&Progress),
    progress: Progress,
    skipped: Vec<Skipped>,
    since_report: u64,
}

impl Ctx<'_> {
    fn tick(&mut self) {
        self.since_report += 1;
        if self.since_report >= PROGRESS_EVERY {
            self.since_report = 0;
            (self.on_progress)(&self.progress);
        }
    }

    fn skip(&mut self, path: PathBuf, reason: SkipReason, detail: Option<String>) {
        self.skipped.push(Skipped {
            path,
            reason,
            detail,
        });
    }
}

pub fn special_reason(meta: &Metadata) -> Option<SkipReason> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const REPARSE_POINT: u32 = 0x0400;
        const RECALL_ON_OPEN: u32 = 0x0004_0000;
        const RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        let attrs = meta.file_attributes();
        // 云占位文件通常也带重解析点标志，需先判断。
        if attrs & (RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0 {
            return Some(SkipReason::CloudPlaceholder);
        }
        if attrs & REPARSE_POINT != 0 {
            return Some(SkipReason::ReparsePoint);
        }
    }
    if meta.file_type().is_symlink() {
        return Some(SkipReason::ReparsePoint);
    }
    None
}

/// 扫描 `root`。`root` 必须是目录。
pub fn scan(
    root: &Path,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
) -> io::Result<ScanOutcome> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || special_reason(&meta).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan root must be a real directory",
        ));
    }
    let mut ctx = Ctx {
        cancel,
        on_progress,
        progress: Progress::default(),
        skipped: Vec::new(),
        since_report: 0,
    };
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    let node = walk(root, name, 0, &mut ctx);
    (ctx.on_progress)(&ctx.progress);
    Ok(ScanOutcome {
        root: node,
        skipped: ctx.skipped,
        cancelled: cancel.load(Ordering::Relaxed),
    })
}

fn walk(path: &Path, name: String, depth: usize, ctx: &mut Ctx) -> Node {
    let mut node = Node {
        name,
        is_dir: true,
        size: 0,
        file_count: 0,
        children: Vec::new(),
    };
    ctx.progress.dirs += 1;

    if depth >= MAX_DEPTH {
        ctx.skip(
            path.to_path_buf(),
            SkipReason::Error,
            Some("directory nesting too deep".into()),
        );
        return node;
    }
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            ctx.skip(path.to_path_buf(), SkipReason::Error, Some(e.to_string()));
            return node;
        }
    };

    for entry in entries {
        if ctx.cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                ctx.skip(path.to_path_buf(), SkipReason::Error, Some(e.to_string()));
                continue;
            }
        };
        let child_path = entry.path();
        // DirEntry::metadata 不跟随符号链接。
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                ctx.skip(child_path, SkipReason::Error, Some(e.to_string()));
                continue;
            }
        };
        if let Some(reason) = special_reason(&meta) {
            ctx.skip(child_path, reason, None);
            continue;
        }
        let child_name = entry.file_name().to_string_lossy().into_owned();
        ctx.tick();
        if meta.is_dir() {
            let child = walk(&child_path, child_name, depth + 1, ctx);
            node.size += child.size;
            node.file_count += child.file_count;
            node.children.push(child);
        } else {
            ctx.progress.files += 1;
            ctx.progress.bytes += meta.len();
            node.size += meta.len();
            node.file_count += 1;
            node.children.push(Node {
                name: child_name,
                is_dir: false,
                size: meta.len(),
                file_count: 1,
                children: Vec::new(),
            });
        }
    }
    node.children
        .sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    node
}

/// 取最大的 `n` 个文件（含完整路径），按大小降序。
pub fn top_files(root_path: &Path, root: &Node, n: usize) -> Vec<(PathBuf, u64)> {
    if n == 0 {
        return Vec::new();
    }
    let mut heap: BinaryHeap<Reverse<(u64, PathBuf)>> = BinaryHeap::new();
    collect(root_path, root, n, &mut heap);
    let mut v: Vec<_> = heap.into_iter().map(|Reverse((s, p))| (p, s)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

fn collect(path: &Path, node: &Node, n: usize, heap: &mut BinaryHeap<Reverse<(u64, PathBuf)>>) {
    for child in &node.children {
        let p = path.join(&child.name);
        if child.is_dir {
            collect(&p, child, n, heap);
        } else if heap.len() < n {
            heap.push(Reverse((child.size, p)));
        } else if heap
            .peek()
            .is_some_and(|Reverse((min, _))| child.size > *min)
        {
            heap.pop();
            heap.push(Reverse((child.size, p)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tmpdir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("diskclean-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(p: &Path, bytes: usize) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, vec![0u8; bytes]).unwrap();
    }

    fn run(root: &Path) -> ScanOutcome {
        scan(root, &AtomicBool::new(false), &mut |_| {}).unwrap()
    }

    #[test]
    fn sums_sizes_and_sorts_descending() {
        let d = tmpdir();
        write(&d.join("a.bin"), 100);
        write(&d.join("sub/b.bin"), 300);
        write(&d.join("sub/deep/c.bin"), 50);
        let out = run(&d);
        assert_eq!(out.root.size, 450);
        assert_eq!(out.root.file_count, 3);
        assert_eq!(out.root.children[0].name, "sub");
        assert_eq!(out.root.children[0].size, 350);
        assert!(out.skipped.is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn top_files_returns_largest_with_paths() {
        let d = tmpdir();
        write(&d.join("a"), 10);
        write(&d.join("x/b"), 30);
        write(&d.join("x/y/c"), 20);
        let out = run(&d);
        let top = top_files(&d, &out.root, 2);
        assert_eq!(top, vec![(d.join("x/b"), 30), (d.join("x/y/c"), 20)]);
        assert!(top_files(&d, &out.root, 0).is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn does_not_follow_symlinks() {
        let d = tmpdir();
        let outside = tmpdir();
        write(&outside.join("big"), 10_000);
        write(&d.join("real"), 5);
        std::os::unix::fs::symlink(&outside, d.join("link")).unwrap();
        let out = run(&d);
        assert_eq!(out.root.size, 5);
        assert_eq!(out.skipped.len(), 1);
        assert_eq!(out.skipped[0].reason, SkipReason::ReparsePoint);
        fs::remove_dir_all(&d).unwrap();
        fs::remove_dir_all(&outside).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_dir_is_reported_not_fatal() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir();
        write(&d.join("ok"), 7);
        write(&d.join("locked/f"), 99);
        fs::set_permissions(d.join("locked"), fs::Permissions::from_mode(0o000)).unwrap();
        // root 用户不受权限位限制，此时无法构造该场景。
        if fs::read_dir(d.join("locked")).is_err() {
            let out = run(&d);
            assert_eq!(out.root.size, 7);
            assert!(out.skipped.iter().any(|s| s.reason == SkipReason::Error));
        }
        fs::set_permissions(d.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cancel_stops_scan() {
        let d = tmpdir();
        write(&d.join("a"), 1);
        let cancel = AtomicBool::new(true);
        let out = scan(&d, &cancel, &mut |_| {}).unwrap();
        assert!(out.cancelled);
        assert_eq!(out.root.size, 0);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn root_must_be_directory() {
        let d = tmpdir();
        write(&d.join("f"), 1);
        assert!(scan(&d.join("f"), &AtomicBool::new(false), &mut |_| {}).is_err());
        assert!(scan(&d.join("missing"), &AtomicBool::new(false), &mut |_| {}).is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
