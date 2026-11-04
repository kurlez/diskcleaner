//! 通过解析 NTFS 的 $MFT 快速扫描整个卷（需要管理员权限才能打开原始卷）。
//!
//! 相比逐目录遍历，这里只做顺序读取，1TB 级的卷通常在几十秒内完成。
//!
//! 与遍历扫描器的差异（均为有意为之）：
//! * 大小是**占用空间**（数据流实际分配的簇，稀疏部分不计），而不是逻辑大小。
//!   这样 OneDrive 的"仅在线"文件、稀疏文件不会虚增占用。
//! * 只统计未命名数据流；备用数据流不计入。
//! * 硬链接只在第一个路径下出现一次，大小只算一次。
//! * 目录自身的索引（`$INDEX_ALLOCATION`）不计入。
//!
//! 读取是在线进行的，扫描期间被修改的文件可能出现轻微不一致，这对"分析占用"可以接受。
//! 解析只依赖 `Read + Seek`，因此可以在任何平台上用磁盘镜像做测试。

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use ntfs::attribute_value::NtfsAttributeValue;
use ntfs::structured_values::{NtfsFileName, NtfsFileNamespace};
use ntfs::{Ntfs, NtfsAttributeType, NtfsFile, NtfsFileFlags};

use crate::scanner::{Node, Progress, ScanOutcome};

/// 原始卷读取必须按扇区对齐；4096 同时满足 512e 与 4Kn 磁盘。
const ALIGN: u64 = 4096;
/// 每次预读 1 MiB，把大量零散的 1 KiB 记录读取合并成顺序 I/O。
const BLOCK: usize = 1 << 20;
const MAX_DEPTH: usize = 512;
const ROOT_RECORD: u64 = 5;
const PROGRESS_EVERY: u64 = 20_000;

#[derive(Debug)]
pub enum MftError {
    /// 不是 NTFS，或引导扇区无法识别（FAT、exFAT、ReFS 等）。
    NotNtfs(String),
    /// I/O 错误（含权限不足）。
    Io(io::Error),
    /// MFT 结构异常。
    Corrupt(String),
    /// 请求的子路径在卷中不存在。
    PathNotFound,
}

impl fmt::Display for MftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MftError::NotNtfs(m) => write!(f, "not an NTFS volume: {m}"),
            MftError::Io(e) => write!(f, "I/O error: {e}"),
            MftError::Corrupt(m) => write!(f, "corrupt MFT: {m}"),
            MftError::PathNotFound => write!(f, "path not found on the volume"),
        }
    }
}

impl std::error::Error for MftError {}

impl From<io::Error> for MftError {
    fn from(e: io::Error) -> Self {
        MftError::Io(e)
    }
}

fn ntfs_err(e: ntfs::NtfsError) -> MftError {
    MftError::Corrupt(e.to_string())
}

// ---------- 对齐的块缓存读取器 ----------

/// 只在 4096 字节边界上、以 1 MiB 为单位读取底层流，并在内存中缓存当前块。
struct BlockReader<R: Read + Seek> {
    inner: R,
    pos: u64,
    block_start: u64,
    buf: Vec<u8>,
    valid: usize,
}

impl<R: Read + Seek> BlockReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            pos: 0,
            block_start: 0,
            buf: vec![0; BLOCK],
            valid: 0,
        }
    }

    fn fill(&mut self, pos: u64) -> io::Result<()> {
        let start = pos / ALIGN * ALIGN;
        self.inner.seek(SeekFrom::Start(start))?;
        let mut total = 0;
        while total < BLOCK {
            let n = self.inner.read(&mut self.buf[total..])?;
            if n == 0 {
                break;
            }
            total += n;
        }
        self.block_start = start;
        self.valid = total;
        Ok(())
    }
}

impl<R: Read + Seek> Read for BlockReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let in_cache = self.valid > 0
            && self.pos >= self.block_start
            && self.pos < self.block_start + self.valid as u64;
        if !in_cache {
            self.fill(self.pos)?;
            if self.pos < self.block_start || self.pos >= self.block_start + self.valid as u64 {
                return Ok(0); // 超出卷末尾
            }
        }
        let off = (self.pos - self.block_start) as usize;
        let n = out.len().min(self.valid - off);
        out[..n].copy_from_slice(&self.buf[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for BlockReader<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let new = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            // 原始卷句柄通常不支持从末尾定位。
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "seek from end is not supported",
                ))
            }
        };
        self.pos = new.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad seek"))?;
        Ok(self.pos)
    }
}

// ---------- 路径处理 ----------

/// 把 `C:\Users\a`、`c:/users/a`、`\\?\C:\Users\a` 拆成盘符和目录名序列。
/// 不是以盘符开头的绝对路径（相对路径、UNC）返回 `None`。
pub fn split_drive_path(path: &str) -> Option<(char, Vec<String>)> {
    let s = path.replace('/', "\\");
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s);
    let mut chars = s.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    if chars.next() != Some(':') {
        return None;
    }
    let rest = &s[2..];
    if !rest.is_empty() && !rest.starts_with('\\') {
        return None; // "C:foo" 是相对路径
    }
    let comps = rest
        .split('\\')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_string)
        .collect();
    Some((letter.to_ascii_uppercase(), comps))
}

/// 在 `root` 下按名称（不区分大小写）逐级取出子树。
pub fn take_subtree(root: Node, comps: &[String]) -> Option<Node> {
    let mut node = root;
    for c in comps {
        let lc = c.to_lowercase();
        let idx = node
            .children
            .iter()
            .position(|n| n.is_dir && n.name.to_lowercase() == lc)?;
        node = node.children.swap_remove(idx);
    }
    Some(node)
}

// ---------- 打开卷（仅 Windows） ----------

/// 打开 `\\.\X:`，需要管理员权限。
#[cfg(windows)]
pub fn open_volume(letter: char) -> io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4; // READ | WRITE | DELETE
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .open(format!(r"\\.\{letter}:"))
}

// ---------- 扫描 ----------

struct Entry {
    parent: u64,
    name: Box<str>,
    is_dir: bool,
    size: u64,
}

/// 扫描 `path` 所在的整个卷，然后截取 `path` 对应的子树。
/// `volume` 是已经打开的原始卷（或磁盘镜像）。
pub fn scan_path<R: Read + Seek>(
    volume: R,
    path: &Path,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
) -> Result<ScanOutcome, MftError> {
    let (_, comps) = path
        .to_str()
        .and_then(split_drive_path)
        .ok_or(MftError::PathNotFound)?;
    let mut out = scan_volume(volume, cancel, on_progress)?;
    out.root = take_subtree(out.root, &comps).ok_or(MftError::PathNotFound)?;
    out.root.name = comps
        .last()
        .cloned()
        .unwrap_or_else(|| path.to_string_lossy().into_owned());
    Ok(out)
}

/// 解析整个卷的 MFT，返回以根目录为根的目录树（根的名字为空）。
pub fn scan_volume<R: Read + Seek>(
    volume: R,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(&Progress),
) -> Result<ScanOutcome, MftError> {
    let mut fs = BlockReader::new(volume);
    let ntfs = Ntfs::new(&mut fs).map_err(|e| MftError::NotNtfs(e.to_string()))?;

    let mft = ntfs.file(&mut fs, 0).map_err(ntfs_err)?;
    let mft_len = mft
        .data(&mut fs, "")
        .ok_or_else(|| MftError::Corrupt("$MFT has no data stream".into()))?
        .map_err(ntfs_err)?
        .to_attribute()
        .map_err(ntfs_err)?
        .value_length();
    let record_size = u64::from(ntfs.file_record_size());
    let count = mft_len / record_size.max(1);

    let mut entries: Vec<Option<Entry>> = Vec::new();
    entries.resize_with(count as usize, || None);
    let mut progress = Progress::default();
    let mut cancelled = false;

    for n in 0..count {
        if n % 1024 == 0 && cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        // 无法解析的记录（空闲、损坏）直接跳过。
        let Ok(file) = ntfs.file(&mut fs, n) else {
            continue;
        };
        if let Some(entry) = read_entry(&file, &mut fs) {
            if entry.is_dir {
                progress.dirs += 1;
            } else {
                progress.files += 1;
                progress.bytes += entry.size;
            }
            entries[n as usize] = Some(entry);
        }
        if n % PROGRESS_EVERY == 0 {
            on_progress(&progress);
        }
    }
    on_progress(&progress);

    let root = build_tree(&entries);
    Ok(ScanOutcome {
        root,
        skipped: Vec::new(),
        excluded: Vec::new(),
        cancelled,
    })
}

/// 读取一条 MFT 记录，得到它在目录树里的位置与大小。
/// 空闲记录、扩展记录、没有可用文件名的记录返回 `None`。
fn read_entry<R: Read + Seek>(file: &NtfsFile, fs: &mut R) -> Option<Entry> {
    if !file.flags().contains(NtfsFileFlags::IN_USE) {
        return None;
    }

    // 基本记录一定含 $STANDARD_INFORMATION；扩展记录（属性溢出的部分）没有。
    let mut is_base = false;
    let mut name: Option<(u64, Box<str>)> = None;
    for attr in file.attributes_raw() {
        let Ok(attr) = attr else { continue };
        match attr.ty() {
            Ok(NtfsAttributeType::StandardInformation) => is_base = true,
            Ok(NtfsAttributeType::FileName) => {
                let Ok(fname) = attr.structured_value::<_, NtfsFileName>(fs) else {
                    continue;
                };
                // 跳过纯 DOS 8.3 短名；硬链接只取第一个有效名字。
                if fname.namespace() == NtfsFileNamespace::Dos || name.is_some() {
                    continue;
                }
                let parent = fname.parent_directory_reference().file_record_number();
                name = Some((parent, fname.name().to_string_lossy().into_boxed_str()));
            }
            _ => {}
        }
    }
    if !is_base {
        return None;
    }
    let (parent, name) = name?;
    let is_dir = file.is_directory();
    let size = if is_dir { 0 } else { size_on_disk(file, fs) };
    Some(Entry {
        parent,
        name,
        is_dir,
        size,
    })
}

/// 未命名数据流在磁盘上实际占用的字节数。
fn size_on_disk<R: Read + Seek>(file: &NtfsFile, fs: &mut R) -> u64 {
    let Some(Ok(item)) = file.data(fs, "") else {
        return 0;
    };
    let Ok(attr) = item.to_attribute() else {
        return 0;
    };
    match attr.value(fs) {
        Ok(NtfsAttributeValue::Resident(v)) => v.len(),
        // 稀疏段没有真实位置，不占磁盘空间。
        Ok(NtfsAttributeValue::NonResident(v)) => v
            .data_runs()
            .filter_map(Result::ok)
            .filter(|r| r.data_position().value().is_some())
            .map(|r| r.allocated_size())
            .sum(),
        Ok(other) => other.len(),
        Err(_) => attr.value_length(),
    }
}

/// 由 (记录号 → 条目) 重建目录树。父目录找不到的孤儿记录被忽略。
fn build_tree(entries: &[Option<Entry>]) -> Node {
    // 按父目录排序后，每个目录的子项是一段连续区间，用二分定位，避免为每个目录单独分配 Vec。
    let mut by_parent: Vec<(u64, u64)> = entries
        .iter()
        .enumerate()
        .filter_map(|(rec, e)| {
            let e = e.as_ref()?;
            // 根目录的父目录是它自己，必须排除。
            (rec as u64 != ROOT_RECORD).then_some((e.parent, rec as u64))
        })
        .collect();
    by_parent.sort_unstable();

    let mut root = Node {
        name: String::new(),
        is_dir: true,
        size: 0,
        file_count: 0,
        children: Vec::new(),
    };
    fill_children(&mut root, ROOT_RECORD, entries, &by_parent, 0);
    root
}

fn fill_children(
    node: &mut Node,
    dir_record: u64,
    entries: &[Option<Entry>],
    by_parent: &[(u64, u64)],
    depth: usize,
) {
    if depth >= MAX_DEPTH {
        return;
    }
    let start = by_parent.partition_point(|&(p, _)| p < dir_record);
    let end = by_parent.partition_point(|&(p, _)| p <= dir_record);
    for &(_, rec) in &by_parent[start..end] {
        let Some(e) = entries.get(rec as usize).and_then(Option::as_ref) else {
            continue;
        };
        let mut child = Node {
            name: e.name.to_string(),
            is_dir: e.is_dir,
            size: e.size,
            file_count: u64::from(!e.is_dir),
            children: Vec::new(),
        };
        if e.is_dir {
            fill_children(&mut child, rec, entries, by_parent, depth + 1);
        }
        node.size += child.size;
        node.file_count += child.file_count;
        node.children.push(child);
    }
    node.children
        .sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn splits_drive_paths() {
        assert_eq!(split_drive_path(r"C:\"), Some(('C', vec![])));
        assert_eq!(split_drive_path("c:"), Some(('C', vec![])));
        assert_eq!(
            split_drive_path(r"c:/Users\alice/"),
            Some(('C', vec!["Users".into(), "alice".into()]))
        );
        assert_eq!(
            split_drive_path(r"\\?\D:\Data"),
            Some(('D', vec!["Data".into()]))
        );
        assert_eq!(split_drive_path("C:foo"), None);
        assert_eq!(split_drive_path(r"\\server\share"), None);
        assert_eq!(split_drive_path("/home/user"), None);
        assert_eq!(split_drive_path(""), None);
    }

    fn node(name: &str, is_dir: bool, size: u64, children: Vec<Node>) -> Node {
        Node {
            name: name.into(),
            is_dir,
            size,
            file_count: u64::from(!is_dir),
            children,
        }
    }

    #[test]
    fn takes_subtree_case_insensitively() {
        let tree = node(
            "",
            true,
            0,
            vec![node(
                "Users",
                true,
                0,
                vec![node(
                    "Alice",
                    true,
                    0,
                    vec![node("a.txt", false, 5, vec![])],
                )],
            )],
        );
        let sub = take_subtree(tree.clone(), &["users".into(), "ALICE".into()]).unwrap();
        assert_eq!(sub.name, "Alice");
        assert!(take_subtree(tree.clone(), &["nope".into()]).is_none());
        // 文件不能当作目录往下走
        assert!(take_subtree(tree, &["Users".into(), "Alice".into(), "a.txt".into()]).is_none());
    }

    #[test]
    fn block_reader_serves_unaligned_reads_from_aligned_io() {
        // 记录底层每次读写的位置，确认都落在 4096 边界上。
        struct Spy {
            inner: Cursor<Vec<u8>>,
            starts: Vec<u64>,
        }
        impl Read for Spy {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.inner.read(b)
            }
        }
        impl Seek for Spy {
            fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
                if let SeekFrom::Start(s) = p {
                    self.starts.push(s);
                }
                self.inner.seek(p)
            }
        }
        let data: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
        let mut r = BlockReader::new(Spy {
            inner: Cursor::new(data.clone()),
            starts: vec![],
        });
        for &(pos, len) in &[
            (5u64, 17usize),
            (4095, 10),
            (1_500_000, 300),
            (2_999_990, 50),
        ] {
            r.seek(SeekFrom::Start(pos)).unwrap();
            let mut buf = vec![0u8; len];
            let mut got = 0;
            while got < len {
                let n = r.read(&mut buf[got..]).unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            let end = (pos as usize + len).min(data.len());
            assert_eq!(&buf[..got], &data[pos as usize..end], "pos {pos}");
        }
        assert!(
            r.inner.starts.iter().all(|s| s % ALIGN == 0),
            "{:?}",
            r.inner.starts
        );
        // 读到末尾之后返回 0，而不是报错
        r.seek(SeekFrom::Start(10_000_000)).unwrap();
        assert_eq!(r.read(&mut [0u8; 8]).unwrap(), 0);
        assert!(r.seek(SeekFrom::End(0)).is_err());
    }

    #[test]
    fn non_ntfs_input_is_reported_as_such() {
        let junk = Cursor::new(vec![0u8; 1 << 16]);
        let err = scan_volume(junk, &AtomicBool::new(false), &mut |_| {}).unwrap_err();
        assert!(matches!(err, MftError::NotNtfs(_)), "{err}");
    }
}
