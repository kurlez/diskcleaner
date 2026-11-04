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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use rayon::prelude::*;

pub use crate::cloud::Excluded;

const MAX_DEPTH: usize = 512;
/// 并行遍历的线程数：瓶颈是文件系统等待而不是 CPU，所以可以多于核数。
const SCAN_THREADS: usize = 16;
const WORKER_STACK: usize = 32 * 1024 * 1024;
const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

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
    /// 因为是云端/同步目录或用户自定义跳过而没有分析的目录。
    pub excluded: Vec<Excluded>,
    pub cancelled: bool,
}

/// 决定一个目录是否跳过：返回原因（`Some`）表示跳过。
pub type DirFilter<'a> = &'a (dyn Fn(&Path) -> Option<String> + Sync);

/// 各工作线程共享的扫描状态；计数用原子量，进度由调用线程定时读取。
struct Shared<'a> {
    filter: Option<DirFilter<'a>>,
    cancel: &'a AtomicBool,
    files: AtomicU64,
    dirs: AtomicU64,
    bytes: AtomicU64,
    skipped: Mutex<Vec<Skipped>>,
    excluded: Mutex<Vec<Excluded>>,
}

impl Shared<'_> {
    fn snapshot(&self) -> Progress {
        Progress {
            files: self.files.load(Ordering::Relaxed),
            dirs: self.dirs.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }

    fn skip(&self, path: PathBuf, reason: SkipReason, detail: Option<String>) {
        self.skipped.lock().unwrap().push(Skipped {
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
    scan_filtered(root, cancel, on_progress, None)
}

/// 与 [`scan`] 相同，但 `filter` 返回 `Some` 的目录会被整个跳过（不进入、不统计），并记录在 `excluded` 里。
pub fn scan_filtered(
    root: &Path,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
    filter: Option<DirFilter>,
) -> io::Result<ScanOutcome> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() || special_reason(&meta).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "scan root must be a real directory",
        ));
    }
    let shared = Shared {
        filter,
        cancel,
        files: AtomicU64::new(0),
        dirs: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        skipped: Mutex::new(Vec::new()),
        excluded: Mutex::new(Vec::new()),
    };
    let name = root
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(SCAN_THREADS)
        .stack_size(WORKER_STACK)
        .build()
        .map_err(io::Error::other)?;
    let node = std::thread::scope(|scope| {
        let worker = scope.spawn(|| pool.install(|| walk(root, name, 0, &shared)));
        while !worker.is_finished() {
            std::thread::sleep(PROGRESS_INTERVAL);
            on_progress(&shared.snapshot());
        }
        worker.join()
    })
    .map_err(|_| io::Error::other("scan worker panicked"))?;
    on_progress(&shared.snapshot());
    let mut skipped = shared.skipped.into_inner().unwrap();
    let mut excluded = shared.excluded.into_inner().unwrap();
    // 并行遍历的发现顺序不固定，排序后结果才可复现。
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    excluded.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ScanOutcome {
        root: node,
        skipped,
        excluded,
        cancelled: cancel.load(Ordering::Relaxed),
    })
}

fn walk(path: &Path, name: String, depth: usize, sh: &Shared) -> Node {
    let mut node = Node {
        name,
        is_dir: true,
        size: 0,
        file_count: 0,
        children: Vec::new(),
    };
    sh.dirs.fetch_add(1, Ordering::Relaxed);

    if depth >= MAX_DEPTH {
        sh.skip(
            path.to_path_buf(),
            SkipReason::Error,
            Some("directory nesting too deep".into()),
        );
        return node;
    }
    let entries = match fs::read_dir(path) {
        Ok(e) => e,
        Err(e) => {
            sh.skip(path.to_path_buf(), SkipReason::Error, Some(e.to_string()));
            return node;
        }
    };

    let mut subdirs: Vec<(PathBuf, String)> = Vec::new();
    for entry in entries {
        if sh.cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                sh.skip(path.to_path_buf(), SkipReason::Error, Some(e.to_string()));
                continue;
            }
        };
        let child_path = entry.path();
        // DirEntry::metadata 不跟随符号链接。
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                sh.skip(child_path, SkipReason::Error, Some(e.to_string()));
                continue;
            }
        };
        if let Some(reason) = special_reason(&meta) {
            sh.skip(child_path, reason, None);
            continue;
        }
        let child_name = entry.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            if let Some(reason) = sh.filter.and_then(|f| f(&child_path)) {
                sh.excluded.lock().unwrap().push(Excluded {
                    path: child_path,
                    reason,
                    size: 0,
                });
                continue;
            }
            subdirs.push((child_path, child_name));
        } else {
            sh.files.fetch_add(1, Ordering::Relaxed);
            sh.bytes.fetch_add(meta.len(), Ordering::Relaxed);
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
    // 子目录交给线程池并行处理（工作窃取，深浅不一的目录树也能均衡）。
    let dirs: Vec<Node> = subdirs
        .into_par_iter()
        .map(|(p, n)| walk(&p, n, depth + 1, sh))
        .collect();
    for child in dirs {
        node.size += child.size;
        node.file_count += child.file_count;
        node.children.push(child);
    }
    node.children
        .sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
    node
}

/// 去掉小于 `min_size` 的文件和目录节点（它们的大小仍计入上级，只是不再单独列出），
/// 返回被去掉的节点数。小目录整棵子树一起去掉，所以界面与内存里只剩大头。
pub fn prune_small(node: &mut Node, min_size: u64) -> usize {
    if min_size == 0 {
        return 0;
    }
    let before = node.children.len();
    node.children.retain(|c| c.size >= min_size);
    let mut removed = before - node.children.len();
    for c in &mut node.children {
        removed += prune_small(c, min_size);
    }
    removed
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

/// 事后剪掉被排除的目录（用于 MFT 扫描：它一次读出整个卷，没有"遍历时跳过"的机会）。
/// 被剪掉的目录的大小会从所有上级扣除，并记录在返回值里。
pub fn prune_excluded(root: &mut Node, root_path: &Path, filter: DirFilter) -> Vec<Excluded> {
    fn walk(node: &mut Node, path: &Path, filter: DirFilter, out: &mut Vec<Excluded>) {
        let mut removed = (0u64, 0u64);
        let mut keep = Vec::with_capacity(node.children.len());
        for mut child in std::mem::take(&mut node.children) {
            let cp = path.join(&child.name);
            if child.is_dir {
                if let Some(reason) = filter(&cp) {
                    removed.0 += child.size;
                    removed.1 += child.file_count;
                    out.push(Excluded {
                        path: cp,
                        reason,
                        size: child.size,
                    });
                    continue;
                }
                let before = (child.size, child.file_count);
                walk(&mut child, &cp, filter, out);
                removed.0 += before.0 - child.size;
                removed.1 += before.1 - child.file_count;
            }
            keep.push(child);
        }
        node.children = keep;
        node.size = node.size.saturating_sub(removed.0);
        node.file_count = node.file_count.saturating_sub(removed.1);
    }
    let mut out = Vec::new();
    walk(root, root_path, filter, &mut out);
    out
}

// ---------- 就地更新扫描树 ----------
//
// 清理、迁移之后，已有的扫描结果会过期。与其让用户重新扫描整个磁盘，
// 不如直接在内存里的树上删掉/替换对应的节点，并同步修正所有上级目录的大小和排序。

fn same_name(a: &str, b: &str) -> bool {
    a == b || a.to_lowercase() == b.to_lowercase()
}

fn resort(node: &mut Node) {
    node.children
        .sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
}

/// 把 `path` 拆成相对扫描根 `root_path` 的目录名序列（不区分大小写、兼容 `\` 与 `/`）。
/// 路径就是根本身时返回空序列；不在根之内返回 `None`。
pub fn parts_below(root_path: &Path, path: &Path) -> Option<Vec<String>> {
    let comps = |p: &Path| -> Vec<String> {
        p.to_string_lossy()
            .replace('\\', "/")
            .split('/')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect()
    };
    let (r, p) = (comps(root_path), comps(path));
    if p.len() < r.len() || !r.iter().zip(&p).all(|(a, b)| same_name(a, b)) {
        return None;
    }
    Some(p[r.len()..].to_vec())
}

/// 删除 `parts` 指向的节点，并从沿途所有上级扣除它的大小与文件数。返回被删节点的 (大小, 文件数)。
pub fn remove_path(node: &mut Node, parts: &[String]) -> Option<(u64, u64)> {
    let (first, rest) = parts.split_first()?;
    let idx = node
        .children
        .iter()
        .position(|c| same_name(&c.name, first))?;
    let removed = if rest.is_empty() {
        let c = node.children.remove(idx);
        (c.size, c.file_count)
    } else {
        remove_path(&mut node.children[idx], rest)?
    };
    node.size = node.size.saturating_sub(removed.0);
    node.file_count = node.file_count.saturating_sub(removed.1);
    resort(node);
    Some(removed)
}

/// 用 `new` 替换 `parts` 指向的节点（不存在则插入），并按大小差修正所有上级。
/// 中间的目录必须已存在，否则返回 `false` 且树保持不变。
pub fn replace_path(node: &mut Node, parts: &[String], mut new: Node) -> bool {
    let Some((first, rest)) = parts.split_first() else {
        return false;
    };
    let idx = node.children.iter().position(|c| same_name(&c.name, first));
    if rest.is_empty() {
        let (old_size, old_files) = match idx {
            Some(i) => {
                new.name = node.children[i].name.clone();
                let o = (node.children[i].size, node.children[i].file_count);
                node.children[i] = new.clone();
                o
            }
            None => {
                new.name = first.clone();
                node.children.push(new.clone());
                (0, 0)
            }
        };
        node.size = node.size.saturating_sub(old_size) + new.size;
        node.file_count = node.file_count.saturating_sub(old_files) + new.file_count;
        resort(node);
        return true;
    }
    let Some(i) = idx else { return false };
    let (before_size, before_files) = (node.children[i].size, node.children[i].file_count);
    if !replace_path(&mut node.children[i], rest, new) {
        return false;
    }
    let (after_size, after_files) = (node.children[i].size, node.children[i].file_count);
    node.size = node.size.saturating_sub(before_size) + after_size;
    node.file_count = node.file_count.saturating_sub(before_files) + after_files;
    resort(node);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ----- 就地更新 -----

    fn n(name: &str, size: u64, children: Vec<Node>) -> Node {
        let is_dir = !children.is_empty() || size == 0;
        Node {
            name: name.into(),
            is_dir,
            size: if children.is_empty() {
                size
            } else {
                children.iter().map(|c| c.size).sum()
            },
            file_count: if children.is_empty() {
                u64::from(!is_dir)
            } else {
                children.iter().map(|c| c.file_count).sum()
            },
            children,
        }
    }

    fn sample() -> Node {
        let mut root = n(
            "root",
            0,
            vec![
                n(
                    "Users",
                    0,
                    vec![
                        n(
                            "alice",
                            0,
                            vec![n("big.bin", 500, vec![]), n("small.txt", 5, vec![])],
                        ),
                        n("bob", 0, vec![n("b.dat", 100, vec![])]),
                    ],
                ),
                n("pagefile.sys", 300, vec![]),
            ],
        );
        root.children.iter_mut().for_each(|_| {});
        resort(&mut root);
        root
    }

    fn p(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn splits_paths_below_the_scan_root_ignoring_case_and_separator_style() {
        let root = Path::new("C:\\Users");
        assert_eq!(
            parts_below(root, Path::new("c:/users/Alice/x.bin")),
            Some(p(&["Alice", "x.bin"]))
        );
        assert_eq!(parts_below(root, Path::new("C:\\USERS")), Some(vec![]));
        assert_eq!(parts_below(root, Path::new("C:\\Usersx\\a")), None);
        assert_eq!(parts_below(root, Path::new("D:\\Users\\a")), None);
        // 中文与表情符号的名字原样保留。
        assert_eq!(
            parts_below(Path::new("D:\\"), Path::new("D:\\项目\\报告📄.docx")),
            Some(p(&["项目", "报告📄.docx"]))
        );
    }

    #[test]
    fn removing_a_node_updates_every_ancestor_and_the_sort_order() {
        let mut t = sample();
        assert_eq!(t.size, 905);
        let removed = remove_path(&mut t, &p(&["users", "ALICE", "big.bin"])).unwrap();
        assert_eq!(removed, (500, 1));
        assert_eq!(t.size, 405);
        assert_eq!(t.file_count, 3);
        let users = t.children.iter().find(|c| c.name == "Users").unwrap();
        assert_eq!(users.size, 105);
        // 缩小之后 Users 不再是最大的，排序要跟着变。
        assert_eq!(t.children[0].name, "pagefile.sys");
        assert!(remove_path(&mut t, &p(&["Users", "ghost"])).is_none());
        assert!(remove_path(&mut t, &[]).is_none());
        assert_eq!(t.size, 405, "找不到时树不变");
    }

    #[test]
    fn removing_a_whole_directory_subtracts_its_total() {
        let mut t = sample();
        assert_eq!(remove_path(&mut t, &p(&["Users", "alice"])), Some((505, 2)));
        assert_eq!(t.size, 400);
        assert_eq!(
            t.children
                .iter()
                .find(|c| c.name == "Users")
                .unwrap()
                .children
                .len(),
            1
        );
    }

    #[test]
    fn replacing_a_subtree_adjusts_sizes_by_the_difference() {
        let mut t = sample();
        let fresh = n("whatever", 0, vec![n("only.bin", 40, vec![])]);
        assert!(replace_path(&mut t, &p(&["Users", "alice"]), fresh));
        let alice = &t
            .children
            .iter()
            .find(|c| c.name == "Users")
            .unwrap()
            .children
            .iter()
            .find(|c| c.name == "alice")
            .unwrap();
        assert_eq!((alice.size, alice.file_count), (40, 1));
        assert_eq!(t.size, 440, "905 - 505 + 40");
        assert!(
            replace_path(
                &mut t,
                &p(&["Users", "carol"]),
                n("x", 0, vec![n("c.bin", 10, vec![])])
            ),
            "不存在时插入"
        );
        assert_eq!(t.size, 450);
        assert!(
            !replace_path(&mut t, &p(&["Nope", "x"]), n("x", 1, vec![])),
            "中间目录不存在时失败"
        );
        assert_eq!(t.size, 450);
    }

    // ----- 排除目录 -----

    fn cloud_filter(p: &Path) -> Option<String> {
        crate::cloud::provider_of_name(&p.file_name()?.to_string_lossy()).map(str::to_string)
    }

    #[test]
    fn filtered_scan_skips_excluded_directories_entirely() {
        let d = tmpdir();
        write(&d.join("real/a.bin"), 100);
        write(&d.join("Google Drive/huge.bin"), 9_999);
        write(&d.join("real/OneDrive - Work/doc.bin"), 777);
        write(&d.join("real/keep/b.bin"), 5);
        let out = scan_filtered(
            &d,
            &AtomicBool::new(false),
            &mut |_| {},
            Some(&cloud_filter),
        )
        .unwrap();
        assert_eq!(out.root.size, 105, "云目录里的内容不能计入");
        assert_eq!(
            out.root
                .children
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            ["real"]
        );
        let mut ex: Vec<_> = out
            .excluded
            .iter()
            .map(|e| {
                (
                    e.path.file_name().unwrap().to_string_lossy().into_owned(),
                    e.reason.clone(),
                )
            })
            .collect();
        ex.sort();
        assert_eq!(
            ex,
            [
                ("Google Drive".into(), "Google Drive".into()),
                ("OneDrive - Work".into(), "OneDrive".into())
            ]
        );
        // 不带过滤器时行为与之前完全一致。
        let all = scan(&d, &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(all.root.size, 105 + 9_999 + 777);
        assert!(all.excluded.is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pruning_a_finished_tree_matches_a_filtered_scan() {
        let d = tmpdir();
        write(&d.join("real/a.bin"), 100);
        write(&d.join("Dropbox/x/huge.bin"), 5_000);
        write(&d.join("real/Dropbox (Personal)/y.bin"), 300);
        write(&d.join("other.bin"), 7);
        let mut tree = scan(&d, &AtomicBool::new(false), &mut |_| {}).unwrap().root;
        let pruned = prune_excluded(&mut tree, &d, &cloud_filter);
        let filtered = scan_filtered(
            &d,
            &AtomicBool::new(false),
            &mut |_| {},
            Some(&cloud_filter),
        )
        .unwrap();
        assert_eq!(
            (tree.size, tree.file_count),
            (filtered.root.size, filtered.root.file_count)
        );
        assert_eq!(tree.size, 107);
        let real = tree.children.iter().find(|c| c.name == "real").unwrap();
        assert_eq!(
            (real.size, real.file_count),
            (100, 1),
            "上级目录的大小一起扣除"
        );
        let mut sizes: Vec<u64> = pruned.iter().map(|e| e.size).collect();
        sizes.sort();
        assert_eq!(sizes, [300, 5_000], "记录下被排除目录原来的大小");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn pruning_with_nothing_to_exclude_changes_nothing() {
        let d = tmpdir();
        write(&d.join("a/b.bin"), 10);
        let mut tree = scan(&d, &AtomicBool::new(false), &mut |_| {}).unwrap().root;
        assert!(prune_excluded(&mut tree, &d, &cloud_filter).is_empty());
        assert_eq!(tree.size, 10);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn parallel_walk_totals_match_a_wide_and_deep_tree() {
        let base = std::env::temp_dir().join(format!("dc-par-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (mut files, mut bytes) = (0u64, 0u64);
        for a in 0..12 {
            for b in 0..12 {
                let d = base.join(format!("a{a}/b{b}/c/d"));
                fs::create_dir_all(&d).unwrap();
                for f in 0..5 {
                    let n = (a * 100 + b * 10 + f + 1) as usize;
                    fs::write(d.join(format!("f{f}.bin")), vec![1u8; n]).unwrap();
                    files += 1;
                    bytes += n as u64;
                }
            }
        }
        let mut reports = 0;
        let out = scan(&base, &AtomicBool::new(false), &mut |_| reports += 1).unwrap();
        assert_eq!(out.root.file_count, files);
        assert_eq!(out.root.size, bytes);
        assert!(reports >= 1, "final progress is always reported");
        // 每一层都按大小降序，结果与线程调度无关。
        fn sorted(n: &Node) -> bool {
            n.children.windows(2).all(|w| w[0].size >= w[1].size) && n.children.iter().all(sorted)
        }
        assert!(sorted(&out.root));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn small_items_are_pruned_but_still_counted_in_their_parents() {
        let f = |n: &str, size: u64| Node {
            name: n.into(),
            is_dir: false,
            size,
            file_count: 1,
            children: vec![],
        };
        let small_dir = Node {
            name: "sd".into(),
            is_dir: true,
            size: 300,
            file_count: 2,
            children: vec![f("x", 100), f("y", 200)],
        };
        let mut root = Node {
            name: "r".into(),
            is_dir: true,
            size: 5000 + 300 + 10,
            file_count: 4,
            children: vec![f("big", 5000), small_dir, f("tiny", 10)],
        };
        assert_eq!(prune_small(&mut root, 1000), 2);
        assert_eq!(root.children.len(), 1);
        assert_eq!(root.children[0].name, "big");
        assert_eq!(root.size, 5310, "上级大小不变");
        assert_eq!(prune_small(&mut root, 0), 0);
    }
}
