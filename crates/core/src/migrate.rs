//! 把一个目录迁移到另一个盘，并在原位置留下 junction，使原路径继续可用。
//!
//! **安全模型：先复制、校验，再切换；任何一步失败都回滚到原样，原目录始终完好。**
//!
//! 1. 预检：源目录、目标位置、空间、是否含链接、是否会嵌套……
//! 2. 复制到目标，并逐项校验（路径与大小）。
//! 3. 把原目录**改名**为 `<名>.dc-old-<id>`（目录被占用时这一步会失败——这是最可靠的占用检测）。
//! 4. 在原路径创建 junction 指向目标，验证能读。
//! 5. 一切正常才删除旧目录；删除不全时保留并告知，迁移仍算成功。
//!
//! 每一步之前先把状态写入清单（write-ahead），中途崩溃后 [`recover`] 能识别并恢复。
//! 复制、建链接、读取卷信息都通过接口注入，因此整套流程可以在任何平台上用真实目录测试。

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::safety::SafetyPolicy;
use crate::scanner::special_reason;
use crate::sysaction::CommandRunner;
use crate::uninstall::format_timestamp;

// ====================================================================
// 卷信息
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// 卷的挂载点（如 `C:\`）。两个路径的挂载点相同就是同一个卷。
    pub mount: PathBuf,
    /// 卷标（如 `Data`、`Google Drive`）。
    pub label: String,
    pub fs: String,
    pub free: u64,
    pub total: u64,
    pub removable: bool,
    /// 网络驱动器：junction 不能指向网络位置。
    pub remote: bool,
}

pub trait Volumes: Send + Sync {
    fn volume_of(&self, path: &Path) -> Option<VolumeInfo>;
}

fn norm_mount(p: &Path) -> String {
    p.to_string_lossy()
        .replace('/', "\\")
        .to_lowercase()
        .trim_end_matches('\\')
        .to_string()
}

/// 通过 `sysinfo` 读取真实卷信息：取挂载点最长的前缀匹配。
pub struct SysVolumes;

impl Volumes for SysVolumes {
    fn volume_of(&self, path: &Path) -> Option<VolumeInfo> {
        let disks = sysinfo::Disks::new_with_refreshed_list().ok()?;
        let target = norm_mount(path);
        let mut best: Option<(usize, VolumeInfo)> = None;
        for d in disks.iter() {
            let mount = d.mount_point();
            let m = norm_mount(mount);
            let matches = target == m
                || target.starts_with(&format!("{m}\\"))
                || (m.is_empty() && target.starts_with('/'));
            let len = if m.is_empty() { 0 } else { m.len() };
            if matches && best.as_ref().is_none_or(|(l, _)| len >= *l) {
                best = Some((
                    len,
                    VolumeInfo {
                        mount: mount.to_path_buf(),
                        label: d.name().to_string_lossy().into_owned(),
                        fs: d.file_system().to_string_lossy().into_owned(),
                        free: d.available_space(),
                        total: d.total_space(),
                        removable: d.is_removable(),
                        remote: is_remote(mount),
                    },
                ));
            }
        }
        best.map(|(_, v)| v)
    }
}

#[cfg(windows)]
fn is_remote(mount: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    const DRIVE_REMOTE: u32 = 4;
    let wide: Vec<u16> = mount
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` 以 NUL 结尾，调用期间一直有效。
    unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(wide.as_ptr()) == DRIVE_REMOTE }
}

#[cfg(not(windows))]
fn is_remote(_mount: &Path) -> bool {
    false
}

// ====================================================================
// 复制
// ====================================================================

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyStats {
    pub files: u64,
    pub bytes: u64,
}

pub trait Copier: Send + Sync {
    /// 把 `src` 整个目录树复制到 `dst`（`dst` 已存在且为空，或不存在）。
    /// `on_bytes` 报告累计已复制的字节数；`cancel` 被置位时尽快返回 `Interrupted`。
    fn copy_tree(
        &self,
        src: &Path,
        dst: &Path,
        cancel: &AtomicBool,
        on_bytes: &mut dyn FnMut(u64),
    ) -> io::Result<CopyStats>;
}

fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "cancelled")
}

/// 纯 Rust 复制：保留内容、修改时间和只读属性；**不保留 ACL/所有者**，所以只用于测试和兜底。
pub struct StdCopier;

impl Copier for StdCopier {
    fn copy_tree(
        &self,
        src: &Path,
        dst: &Path,
        cancel: &AtomicBool,
        on_bytes: &mut dyn FnMut(u64),
    ) -> io::Result<CopyStats> {
        fn walk(
            src: &Path,
            dst: &Path,
            cancel: &AtomicBool,
            stats: &mut CopyStats,
            on_bytes: &mut dyn FnMut(u64),
        ) -> io::Result<()> {
            fs::create_dir_all(dst)?;
            for e in fs::read_dir(src)? {
                if cancel.load(Ordering::Relaxed) {
                    return Err(interrupted());
                }
                let e = e?;
                let (from, to) = (e.path(), dst.join(e.file_name()));
                let meta = fs::symlink_metadata(&from)?;
                if special_reason(&meta).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unexpected link: {}", from.display()),
                    ));
                }
                if meta.is_dir() {
                    walk(&from, &to, cancel, stats, on_bytes)?;
                } else {
                    let n = fs::copy(&from, &to)?;
                    if let Ok(mtime) = meta.modified() {
                        let _ = fs::File::options()
                            .write(true)
                            .open(&to)
                            .and_then(|f| f.set_modified(mtime));
                    }
                    stats.files += 1;
                    stats.bytes += n;
                    on_bytes(stats.bytes);
                }
            }
            Ok(())
        }
        let mut stats = CopyStats::default();
        walk(src, dst, cancel, &mut stats, on_bytes)?;
        Ok(stats)
    }
}

/// robocopy 的命令行参数：保留数据、属性、时间、ACL 与所有者；不跟随 junction；静默输出。
pub fn robocopy_args(src: &Path, dst: &Path) -> Vec<String> {
    vec![
        src.to_string_lossy().into_owned(),
        dst.to_string_lossy().into_owned(),
        "/E".into(),
        "/COPY:DATSO".into(),
        "/DCOPY:DAT".into(),
        "/R:2".into(),
        "/W:1".into(),
        "/XJ".into(),
        "/MT:8".into(),
        "/NFL".into(),
        "/NDL".into(),
        "/NJH".into(),
        "/NJS".into(),
        "/NP".into(),
    ]
}

/// robocopy 的退出码是位掩码：0–7 表示成功（含"有文件被复制"、"有多余文件"等），8 及以上是失败。
pub fn robocopy_exit_ok(code: i32) -> bool {
    (0..8).contains(&code)
}

/// 用 Windows 自带的 robocopy 复制，能保留 ACL、所有者、备用数据流。
pub struct RobocopyCopier;

fn dir_bytes(p: &Path) -> u64 {
    crate::plan::measure_path(p).map(|s| s.size).unwrap_or(0)
}

impl Copier for RobocopyCopier {
    fn copy_tree(
        &self,
        src: &Path,
        dst: &Path,
        cancel: &AtomicBool,
        on_bytes: &mut dyn FnMut(u64),
    ) -> io::Result<CopyStats> {
        let mut cmd = std::process::Command::new("robocopy.exe");
        cmd.args(robocopy_args(src, dst))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        let mut child = cmd.spawn()?;
        let mut last_sample = Instant::now();
        let mut sample_cost = Duration::ZERO;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(interrupted());
            }
            // 复制大小用抽样统计目标目录得到；抽样间隔随统计耗时拉长，避免拖慢复制。
            if last_sample.elapsed() >= Duration::from_secs(2).max(sample_cost * 10) {
                let t = Instant::now();
                on_bytes(dir_bytes(dst));
                sample_cost = t.elapsed();
                last_sample = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(200));
        };
        let code = status.code().unwrap_or(-1);
        if !robocopy_exit_ok(code) {
            return Err(io::Error::other(format!(
                "robocopy failed with exit code {code}"
            )));
        }
        let size = crate::plan::measure_path(dst).map_err(|e| io::Error::other(e.to_string()))?;
        on_bytes(size.size);
        Ok(CopyStats {
            files: size.files,
            bytes: size.size,
        })
    }
}

// ====================================================================
// 链接（junction）
// ====================================================================

pub trait LinkMaker: Send + Sync {
    /// 在 `link`（必须不存在）创建指向 `target` 的 junction。
    fn make_junction(&self, link: &Path, target: &Path) -> io::Result<()>;
    /// 只删除链接本身，不碰它指向的内容。
    fn remove_link(&self, link: &Path) -> io::Result<()>;
    fn link_target(&self, link: &Path) -> Option<PathBuf>;
}

/// 路径里不能含这些字符：它们会被命令解释器当作语法处理。
fn shell_safe(p: &Path) -> bool {
    !p.to_string_lossy().chars().any(|c| {
        matches!(
            c,
            '"' | '%' | '\r' | '\n' | '\0' | '^' | '&' | '|' | '<' | '>'
        )
    })
}

/// 通过 `mklink /J` 创建 junction。
pub struct MklinkJunction<'a>(pub &'a dyn CommandRunner);

impl LinkMaker for MklinkJunction<'_> {
    fn make_junction(&self, link: &Path, target: &Path) -> io::Result<()> {
        if !shell_safe(link) || !shell_safe(target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains characters that are not allowed",
            ));
        }
        let out = self.0.run_shell(&format!(
            "mklink /J \"{}\" \"{}\"",
            link.display(),
            target.display()
        ))?;
        if out.code == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "mklink failed ({}): {} {}",
                out.code,
                out.stdout.trim(),
                out.stderr.trim()
            )))
        }
    }

    fn remove_link(&self, link: &Path) -> io::Result<()> {
        remove_link(link)
    }

    fn link_target(&self, link: &Path) -> Option<PathBuf> {
        fs::read_link(link).ok()
    }
}

/// 删除链接本身。`remove_dir` 对 junction / 目录符号链接只删链接；非 Windows 上符号链接用 `remove_file`。
pub fn remove_link(link: &Path) -> io::Result<()> {
    match fs::remove_dir(link) {
        Ok(()) => Ok(()),
        Err(_) => fs::remove_file(link),
    }
}

/// 比较两个路径是否指向同一处（忽略大小写、斜杠方向、`\\?\` 与 `\??\` 前缀）。
pub fn same_path(a: &Path, b: &Path) -> bool {
    let n = |p: &Path| {
        let s = p.to_string_lossy().replace('/', "\\");
        let s = s
            .strip_prefix(r"\\?\")
            .or_else(|| s.strip_prefix(r"\??\"))
            .unwrap_or(&s)
            .to_string();
        s.trim_end_matches('\\').to_lowercase()
    };
    n(a) == n(b)
}

// ====================================================================
// 目录改名
// ====================================================================

/// 目录改名。把它抽出来是因为"改名失败"是检测目录被占用的最可靠信号，需要能在测试里模拟。
pub trait DirMover: Send + Sync {
    fn rename_dir(&self, from: &Path, to: &Path) -> io::Result<()>;
}

pub struct StdMover;

impl DirMover for StdMover {
    fn rename_dir(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }
}

// ====================================================================
// 清单（迁移记录）
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// 正在复制（原目录未动）。
    Copying,
    /// 正在切换（改名、建链接）。
    Switching,
    Done,
    /// 正在还原到原位置。
    Restoring,
    /// 失败或被中断；原目录完好（或已回滚）。
    Failed,
    /// 已还原，不再是迁移状态。
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub id: String,
    pub source: String,
    pub target: String,
    /// 切换时原目录被改成的名字（成功删除后为空）。
    pub old_path: Option<String>,
    pub size: u64,
    pub files: u64,
    pub created: u64,
    pub status: Status,
    /// 补充说明：失败原因、旧目录没删干净等。
    pub note: Option<String>,
    /// 目标目录是不是我们创建的（回滚时据此决定是删整个目录还是只清空内容）。
    #[serde(default)]
    pub target_created: bool,
}

/// 清单文件（JSON），写入时先写临时文件再改名。
pub struct ManifestStore {
    path: PathBuf,
    records: Mutex<Vec<MigrationRecord>>,
}

impl ManifestStore {
    /// 读取清单；文件不存在或损坏时从空开始（损坏的清单不应让程序打不开）。
    pub fn open(path: PathBuf) -> Self {
        let records = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self {
            path,
            records: Mutex::new(records),
        }
    }

    pub fn list(&self) -> Vec<MigrationRecord> {
        self.records.lock().unwrap().clone()
    }

    pub fn get(&self, id: &str) -> Option<MigrationRecord> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// 新增或更新，并立即落盘。落盘失败会返回错误——此时不应继续做破坏性操作。
    pub fn upsert(&self, rec: &MigrationRecord) -> io::Result<()> {
        let mut g = self.records.lock().unwrap();
        match g.iter_mut().find(|r| r.id == rec.id) {
            Some(x) => *x = rec.clone(),
            None => g.push(rec.clone()),
        }
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(&*g).map_err(io::Error::other)?,
        )?;
        fs::rename(&tmp, &self.path)
    }
}

// ====================================================================
// 安全策略
// ====================================================================

/// 迁移用的安全策略：决定**哪些目录可以被搬走**（搬走后原位置会被删除/替换）。
///
/// * 系统目录（Windows、回收站、系统卷信息……）整体禁止；
/// * `Program Files`、`ProgramData`、用户目录、`AppData`、`Local`、`Roaming`、文档/桌面/下载等
///   **这些目录本身**禁止，但它们里面的子目录允许（迁移 `AppData\Local\Docker` 正是典型用途）；
/// * 其中系统自带的子目录（`Microsoft`、`Packages`、`WindowsApps`、`Common Files` 等）重新保护。
pub fn migration_policy(
    dirs: &crate::safety::KnownDirs,
) -> Result<SafetyPolicy, crate::safety::Denied> {
    use crate::safety::PathStyle;
    let mut p = SafetyPolicy::empty(PathStyle::Windows);
    p.protect(&dirs.system_root)?;
    let drive = dirs.system_root.get(..2).unwrap_or("C:").to_string();
    for special in [
        "System Volume Information",
        "$Recycle.Bin",
        "Recovery",
        "Boot",
        "Windows.old",
    ] {
        p.protect(&format!("{drive}\\{special}"))?;
    }
    let profile = dirs.user_profile.trim_end_matches('\\').to_string();
    let mut open_roots: Vec<String> = vec![
        dirs.program_files.clone(),
        dirs.program_files_x86.clone(),
        dirs.program_data.clone(),
        profile.clone(),
    ];
    for sub in [
        "AppData",
        r"AppData\Local",
        r"AppData\Roaming",
        r"AppData\LocalLow",
        "Documents",
        "Desktop",
        "Downloads",
        "Pictures",
        "Videos",
        "Music",
        "OneDrive",
    ] {
        open_roots.push(format!("{profile}\\{sub}"));
    }
    for r in &open_roots {
        p.protect(r)?;
        p.allow_root(r)?;
    }
    let mut system_children: Vec<String> = Vec::new();
    for pf in [&dirs.program_files, &dirs.program_files_x86] {
        for n in [
            "WindowsApps",
            "Common Files",
            "Windows Defender",
            "Windows NT",
            "Windows Mail",
            "Internet Explorer",
            "ModifiableWindowsApps",
        ] {
            system_children.push(format!("{pf}\\{n}"));
        }
    }
    system_children.push(format!("{}\\Microsoft", dirs.program_data));
    system_children.push(format!("{}\\Package Cache", dirs.program_data));
    for base in [r"AppData\Local", r"AppData\Roaming"] {
        system_children.push(format!("{profile}\\{base}\\Microsoft"));
    }
    system_children.push(format!("{profile}\\AppData\\Local\\Packages"));
    system_children.push(format!("{profile}\\AppData\\Local\\Temp"));
    for c in system_children {
        p.protect(&c)?;
    }
    Ok(p)
}

// ====================================================================
// 预检
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub severity: Severity,
    pub code: &'static str,
    pub detail: Option<String>,
}

impl Issue {
    fn err(code: &'static str, detail: impl Into<Option<String>>) -> Self {
        Self {
            severity: Severity::Error,
            code,
            detail: detail.into(),
        }
    }
    fn warn(code: &'static str, detail: impl Into<Option<String>>) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Preflight {
    pub size: u64,
    pub files: u64,
    pub issues: Vec<Issue>,
    pub source_volume: Option<String>,
    pub target_volume: Option<String>,
    pub target_free: Option<u64>,
}

impl Preflight {
    pub fn can_proceed(&self) -> bool {
        !self.issues.iter().any(|i| i.severity == Severity::Error)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PreflightOptions {
    /// 程序安装根目录（`Program Files` 等）。迁移其中的程序时给出提示。
    pub program_dirs: Vec<PathBuf>,
    /// 云同步目录的识别规则。云同步目录不能迁移：搬走会破坏同步。
    pub cloud: crate::cloud::CloudRules,
}

#[derive(Debug, Default)]
struct Survey {
    size: u64,
    files: u64,
    links: Vec<String>,
    link_count: u64,
    cloud: u64,
}

fn survey(dir: &Path) -> Survey {
    let mut s = Survey::default();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            match special_reason(&m) {
                Some(crate::scanner::SkipReason::CloudPlaceholder) => s.cloud += 1,
                Some(_) => {
                    s.link_count += 1;
                    if s.links.len() < 5 {
                        s.links.push(
                            e.path()
                                .strip_prefix(dir)
                                .unwrap_or(&e.path())
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                }
                None if m.is_dir() => stack.push(e.path()),
                None => {
                    s.size += m.len();
                    s.files += 1;
                }
            }
        }
    }
    s
}

fn starts_with_ci(a: &Path, b: &Path) -> bool {
    let (a, b) = (norm_mount(a), norm_mount(b));
    a == b || a.starts_with(&format!("{b}\\"))
}

fn is_empty_dir(p: &Path) -> bool {
    fs::read_dir(p)
        .map(|mut r| r.next().is_none())
        .unwrap_or(false)
}

/// 迁移前的全部检查。只读，不改动任何东西。
pub fn preflight(
    src: &Path,
    dst: &Path,
    vols: &dyn Volumes,
    policy: &SafetyPolicy,
    existing: &[MigrationRecord],
    opts: &PreflightOptions,
) -> Preflight {
    let mut p = Preflight::default();

    for (path, which) in [(src, "source"), (dst, "target")] {
        let s = path.to_string_lossy();
        if !path.is_absolute() && !s.starts_with('/') && !s.chars().nth(1).is_some_and(|c| c == ':')
            || !shell_safe(path)
        {
            p.issues.push(Issue::err("invalid_path", which.to_string()));
        }
    }
    if p.issues.iter().any(|i| i.code == "invalid_path") {
        return p;
    }

    // ---- 源 ----
    match fs::symlink_metadata(src) {
        Err(_) => p.issues.push(Issue::err("source_missing", None)),
        Ok(m) if special_reason(&m).is_some() => {
            let migrated = existing
                .iter()
                .any(|r| r.status == Status::Done && same_path(Path::new(&r.source), src));
            p.issues.push(Issue::err(
                if migrated {
                    "already_migrated"
                } else {
                    "source_is_link"
                },
                None,
            ));
        }
        Ok(m) if !m.is_dir() => p.issues.push(Issue::err("source_not_dir", None)),
        Ok(_) => {}
    }
    if let Err(d) = policy.check_delete(&src.to_string_lossy()) {
        p.issues.push(Issue::err("source_protected", d.to_string()));
    }
    if let Some(provider) = opts.cloud.location_excluded(src) {
        p.issues.push(Issue::err("cloud_location", provider));
    }
    if let Err(d) = policy.check_delete(&dst.to_string_lossy()) {
        p.issues.push(Issue::err("target_protected", d.to_string()));
    }
    if starts_with_ci(dst, src) {
        p.issues.push(Issue::err("target_inside_source", None));
    }
    if starts_with_ci(src, dst) {
        p.issues.push(Issue::err("source_inside_target", None));
    }
    if existing.iter().any(|r| {
        matches!(
            r.status,
            Status::Copying | Status::Switching | Status::Restoring
        ) && same_path(Path::new(&r.source), src)
    }) {
        p.issues.push(Issue::err("migration_in_progress", None));
    }

    // ---- 卷 ----
    let sv = vols.volume_of(src);
    let tv = vols.volume_of(dst);
    p.source_volume = sv.as_ref().map(|v| v.mount.to_string_lossy().into_owned());
    p.target_volume = tv.as_ref().map(|v| v.mount.to_string_lossy().into_owned());
    p.target_free = tv.as_ref().map(|v| v.free);
    match (&sv, &tv) {
        (Some(s), Some(t)) => {
            if norm_mount(&s.mount) == norm_mount(&t.mount) {
                p.issues.push(Issue::err("same_volume", None));
            }
            if t.remote {
                p.issues.push(Issue::err("target_remote", None));
            }
            if t.removable {
                p.issues.push(Issue::err("target_removable", None));
            }
            // junction 要求源所在卷是 NTFS（或 ReFS）。读不到文件系统名时不阻止。
            let fs_name = s.fs.to_lowercase();
            if !fs_name.is_empty() && fs_name != "ntfs" && fs_name != "refs" {
                p.issues
                    .push(Issue::err("source_fs_unsupported", s.fs.clone()));
            }
        }
        _ => p.issues.push(Issue::err("volume_unknown", None)),
    }

    // ---- 目标是否已存在 ----
    if dst.exists() && !(dst.is_dir() && is_empty_dir(dst)) {
        p.issues.push(Issue::err("target_exists_nonempty", None));
    }

    // ---- 内容 ----
    if src.is_dir() && fs::symlink_metadata(src).is_ok_and(|m| special_reason(&m).is_none()) {
        let sv = survey(src);
        p.size = sv.size;
        p.files = sv.files;
        if sv.link_count > 0 {
            p.issues.push(Issue::err(
                "contains_links",
                format!("{} ({})", sv.link_count, sv.links.join(", ")),
            ));
        }
        if sv.cloud > 0 {
            p.issues
                .push(Issue::err("contains_cloud", sv.cloud.to_string()));
        }
        if let Some(t) = &tv {
            let need = p.size + (p.size / 20).max(100 * 1024 * 1024);
            if t.free < need {
                p.issues
                    .push(Issue::err("not_enough_space", format!("{need}/{}", t.free)));
            }
        }
        if p.size > 20 * 1024 * 1024 * 1024 {
            p.issues.push(Issue::warn("large", None));
        }
    }
    if opts.program_dirs.iter().any(|d| starts_with_ci(src, d)) {
        p.issues.push(Issue::warn("program_dir", None));
    }
    p
}

// ====================================================================
// 迁移
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Copying,
    Verifying,
    Switching,
    Cleaning,
}

#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub stage: Stage,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug)]
pub enum MigrateError {
    /// 预检没通过。
    Preflight(Vec<Issue>),
    Cancelled,
    CopyFailed(String),
    VerifyFailed(String),
    /// 原目录无法改名——通常是有进程占用。原目录完好。
    InUse(String),
    LinkFailed(String),
    /// 不能写清单：为保证出问题时能恢复，拒绝继续。
    Manifest(String),
    /// 还原时的前提不满足。
    NotRestorable(String),
}

impl fmt::Display for MigrateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Preflight(_) => write!(f, "preflight failed"),
            MigrateError::Cancelled => write!(f, "cancelled"),
            MigrateError::CopyFailed(m) => write!(f, "copy failed: {m}"),
            MigrateError::VerifyFailed(m) => write!(f, "verification failed: {m}"),
            MigrateError::InUse(m) => write!(f, "the folder is in use: {m}"),
            MigrateError::LinkFailed(m) => write!(f, "could not create the junction: {m}"),
            MigrateError::Manifest(m) => write!(f, "could not write the migration journal: {m}"),
            MigrateError::NotRestorable(m) => write!(f, "cannot restore: {m}"),
        }
    }
}

impl std::error::Error for MigrateError {}

pub struct Deps<'a> {
    pub copier: &'a dyn Copier,
    pub mover: &'a dyn DirMover,
    pub links: &'a dyn LinkMaker,
    pub volumes: &'a dyn Volumes,
    pub store: &'a ManifestStore,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn new_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!(
        "{}-{:03}",
        format_timestamp(now),
        COUNTER.fetch_add(1, Ordering::Relaxed) % 1000
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// 目录树清单：相对路径 → (是否目录, 大小)。
pub fn manifest_of(root: &Path) -> io::Result<BTreeMap<String, (bool, u64)>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (bool, u64)>) -> io::Result<()> {
        for e in fs::read_dir(dir)? {
            let e = e?;
            let m = fs::symlink_metadata(e.path())?;
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if m.is_dir() {
                out.insert(rel, (true, 0));
                walk(root, &e.path(), out)?;
            } else {
                out.insert(rel, (false, m.len()));
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}

/// 校验两棵树完全一致（相同的路径、类型和大小），不一致时给出前几处差异。
pub fn verify_equal(a: &Path, b: &Path) -> Result<(), String> {
    let (ma, mb) = (
        manifest_of(a).map_err(|e| e.to_string())?,
        manifest_of(b).map_err(|e| e.to_string())?,
    );
    let mut diffs: Vec<String> = Vec::new();
    for (k, v) in &ma {
        match mb.get(k) {
            None => diffs.push(format!("missing: {k}")),
            Some(w) if w != v => diffs.push(format!("differs: {k}")),
            _ => {}
        }
    }
    for k in mb.keys() {
        if !ma.contains_key(k) {
            diffs.push(format!("extra: {k}"));
        }
    }
    if diffs.is_empty() {
        Ok(())
    } else {
        let n = diffs.len();
        diffs.truncate(5);
        Err(format!("{n} differences, e.g. {}", diffs.join("; ")))
    }
}

/// 回滚时清理我们创建的目标：目录是我们建的就整个删除，否则只清空它的内容。
fn cleanup_target(dst: &Path, created: bool) {
    if created {
        let _ = fs::remove_dir_all(dst);
    } else if let Ok(rd) = fs::read_dir(dst) {
        for e in rd.flatten() {
            let p = e.path();
            let _ = if p.is_dir() {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
            };
        }
    }
}

fn save(store: &ManifestStore, rec: &MigrationRecord) -> Result<(), MigrateError> {
    store
        .upsert(rec)
        .map_err(|e| MigrateError::Manifest(e.to_string()))
}

fn fail(store: &ManifestStore, rec: &mut MigrationRecord, note: String) {
    rec.status = Status::Failed;
    rec.note = Some(note);
    let _ = store.upsert(rec);
}

/// 执行迁移。`on_progress` 报告阶段与字节进度。
pub fn migrate(
    src: &Path,
    dst: &Path,
    deps: &Deps,
    policy: &SafetyPolicy,
    opts: &PreflightOptions,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<MigrationRecord, MigrateError> {
    let existing = deps.store.list();
    let pre = preflight(src, dst, deps.volumes, policy, &existing, opts);
    if !pre.can_proceed() {
        return Err(MigrateError::Preflight(pre.issues));
    }

    let id = new_id();
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dir".into());
    let old = src.with_file_name(format!("{name}.dc-old-{id}"));
    let target_created = !dst.exists();
    let mut rec = MigrationRecord {
        id,
        source: src.to_string_lossy().into_owned(),
        target: dst.to_string_lossy().into_owned(),
        old_path: None,
        size: pre.size,
        files: pre.files,
        created: now_secs(),
        status: Status::Copying,
        note: None,
        target_created,
    };
    save(deps.store, &rec)?; // write-ahead：动手之前先记下

    // ---- 1. 复制 ----
    on_progress(Progress {
        stage: Stage::Copying,
        done: 0,
        total: pre.size,
    });
    let copied = deps.copier.copy_tree(src, dst, cancel, &mut |b| {
        on_progress(Progress {
            stage: Stage::Copying,
            done: b,
            total: pre.size,
        })
    });
    if let Err(e) = copied {
        cleanup_target(dst, target_created);
        let cancelled = e.kind() == io::ErrorKind::Interrupted;
        fail(
            deps.store,
            &mut rec,
            if cancelled {
                "cancelled".into()
            } else {
                e.to_string()
            },
        );
        return Err(if cancelled {
            MigrateError::Cancelled
        } else {
            MigrateError::CopyFailed(e.to_string())
        });
    }

    // ---- 2. 校验 ----
    on_progress(Progress {
        stage: Stage::Verifying,
        done: 0,
        total: 1,
    });
    if let Err(m) = verify_equal(src, dst) {
        cleanup_target(dst, target_created);
        fail(deps.store, &mut rec, m.clone());
        return Err(MigrateError::VerifyFailed(m));
    }
    if cancel.load(Ordering::Relaxed) {
        cleanup_target(dst, target_created);
        fail(deps.store, &mut rec, "cancelled".into());
        return Err(MigrateError::Cancelled);
    }

    // ---- 3. 切换：改名 → 建 junction → 验证 ----
    on_progress(Progress {
        stage: Stage::Switching,
        done: 0,
        total: 1,
    });
    rec.status = Status::Switching;
    rec.old_path = Some(old.to_string_lossy().into_owned());
    if let Err(e) = save(deps.store, &rec) {
        cleanup_target(dst, target_created);
        return Err(e);
    }
    if let Err(e) = deps.mover.rename_dir(src, &old) {
        // 原目录没动：回滚目标即可。
        cleanup_target(dst, target_created);
        rec.old_path = None;
        fail(deps.store, &mut rec, format!("rename failed: {e}"));
        return Err(MigrateError::InUse(e.to_string()));
    }
    if let Err(e) = deps.links.make_junction(src, dst) {
        let restored = deps.mover.rename_dir(&old, src).is_ok();
        cleanup_target(dst, target_created);
        fail(
            deps.store,
            &mut rec,
            if restored {
                format!("junction failed: {e}")
            } else {
                format!("junction failed and the original is at {}", old.display())
            },
        );
        return Err(MigrateError::LinkFailed(e.to_string()));
    }
    let link_ok = fs::read_dir(src).is_ok()
        && deps
            .links
            .link_target(src)
            .is_some_and(|t| same_path(&t, dst));
    if !link_ok {
        let _ = deps.links.remove_link(src);
        let restored = deps.mover.rename_dir(&old, src).is_ok();
        cleanup_target(dst, target_created);
        fail(
            deps.store,
            &mut rec,
            if restored {
                "junction verification failed".into()
            } else {
                format!(
                    "junction verification failed; the original is at {}",
                    old.display()
                )
            },
        );
        return Err(MigrateError::LinkFailed(
            "junction verification failed".into(),
        ));
    }

    // ---- 4. 清理旧目录 ----
    on_progress(Progress {
        stage: Stage::Cleaning,
        done: 0,
        total: 1,
    });
    rec.status = Status::Done;
    match fs::remove_dir_all(&old) {
        Ok(()) => rec.old_path = None,
        Err(e) => rec.note = Some(format!("the old folder could not be fully deleted: {e}")),
    }
    save(deps.store, &rec)?;
    Ok(rec)
}

/// 把迁移过的目录还原到原位置：删除链接 → 复制回来 → 校验 → 删除目标。
/// 任何一步失败都会恢复链接，目标数据保持不动。
pub fn restore(
    rec: &MigrationRecord,
    deps: &Deps,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(Progress),
) -> Result<MigrationRecord, MigrateError> {
    let (src, dst) = (PathBuf::from(&rec.source), PathBuf::from(&rec.target));
    let not = |m: &str| MigrateError::NotRestorable(m.to_string());
    if rec.status != Status::Done {
        return Err(not("not in the done state"));
    }
    if !fs::symlink_metadata(&src).is_ok_and(|m| special_reason(&m).is_some())
        || !deps
            .links
            .link_target(&src)
            .is_some_and(|t| same_path(&t, &dst))
    {
        return Err(not(
            "the original path is no longer a junction to the migrated folder",
        ));
    }
    if !dst.is_dir() {
        return Err(not("the migrated folder is missing"));
    }
    // 还原需要原来那个卷有足够空间。
    let size = survey(&dst).size;
    if let Some(v) = deps.volumes.volume_of(&src) {
        if v.free < size + (size / 20).max(100 * 1024 * 1024) {
            return Err(not("not enough free space on the original drive"));
        }
    }

    let mut rec = rec.clone();
    rec.status = Status::Restoring;
    save(deps.store, &rec)?;

    let back_to_done = |rec: &mut MigrationRecord, note: String| {
        rec.status = Status::Done;
        rec.note = Some(note);
        let _ = deps.store.upsert(rec);
    };

    if let Err(e) = deps.links.remove_link(&src) {
        back_to_done(&mut rec, format!("restore failed: {e}"));
        return Err(MigrateError::InUse(e.to_string()));
    }
    on_progress(Progress {
        stage: Stage::Copying,
        done: 0,
        total: size,
    });
    let copied = deps.copier.copy_tree(&dst, &src, cancel, &mut |b| {
        on_progress(Progress {
            stage: Stage::Copying,
            done: b,
            total: size,
        })
    });
    let verified = copied
        .as_ref()
        .map_err(|e| e.to_string())
        .and_then(|_| verify_equal(&dst, &src));
    if let Err(m) = verified {
        // 回退：删掉不完整的副本，把链接放回去。
        let _ = fs::remove_dir_all(&src);
        let relinked = deps.links.make_junction(&src, &dst);
        back_to_done(&mut rec, match relinked {
            Ok(()) => format!("restore failed: {m}"),
            Err(e) => format!("restore failed ({m}) and the junction could not be recreated: {e}; your data is at {}", dst.display()),
        });
        return Err(
            if copied
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::Interrupted)
            {
                MigrateError::Cancelled
            } else {
                MigrateError::CopyFailed(m)
            },
        );
    }
    on_progress(Progress {
        stage: Stage::Cleaning,
        done: 0,
        total: 1,
    });
    rec.status = Status::Restored;
    rec.note = fs::remove_dir_all(&dst)
        .err()
        .map(|e| format!("the migrated copy could not be fully deleted: {e}"));
    if rec.note.is_none() && rec.target_created {
        // 目标是我们创建的：顺手删掉空的父目录链不做，避免误删用户目录。
    }
    save(deps.store, &rec)?;
    Ok(rec)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// 无需处理。
    Nothing,
    /// 已回滚到迁移前的状态。
    RolledBack(String),
    /// 迁移其实已经完成，补记为完成。
    Completed(String),
    /// 无法自动判断，需要人工查看。
    NeedsAttention(String),
}

/// 崩溃或被强制关闭后，根据磁盘上的实际状态修复一条处于中间状态的记录。
pub fn recover(rec: &MigrationRecord, deps: &Deps) -> Recovery {
    let (src, dst) = (PathBuf::from(&rec.source), PathBuf::from(&rec.target));
    let old = rec.old_path.as_deref().map(PathBuf::from);
    let src_is_link = fs::symlink_metadata(&src).is_ok_and(|m| special_reason(&m).is_some());
    let src_is_dir =
        fs::symlink_metadata(&src).is_ok_and(|m| m.is_dir() && special_reason(&m).is_none());
    let mut r = rec.clone();
    let mut finish = |status: Status, note: String| {
        r.status = status;
        r.note = Some(note);
        let _ = deps.store.upsert(&r);
    };
    match rec.status {
        Status::Done | Status::Failed | Status::Restored => Recovery::Nothing,
        Status::Copying => {
            // 复制阶段原目录没动过：丢掉不完整的目标即可。
            if src_is_dir {
                cleanup_target(&dst, rec.target_created);
                finish(
                    Status::Failed,
                    "interrupted while copying; the original folder is untouched".into(),
                );
                Recovery::RolledBack("copy".into())
            } else {
                finish(
                    Status::Failed,
                    "interrupted while copying, but the original path is not a folder".into(),
                );
                Recovery::NeedsAttention("source".into())
            }
        }
        Status::Switching => {
            if src_is_link
                && deps
                    .links
                    .link_target(&src)
                    .is_some_and(|t| same_path(&t, &dst))
                && dst.is_dir()
            {
                finish(
                    Status::Done,
                    "recovered after an interruption; the old folder may still need to be deleted"
                        .into(),
                );
                Recovery::Completed("junction exists".into())
            } else if !src.exists() && old.as_ref().is_some_and(|o| o.is_dir()) {
                let o = old.unwrap();
                match deps.mover.rename_dir(&o, &src) {
                    Ok(()) => {
                        cleanup_target(&dst, rec.target_created);
                        finish(
                            Status::Failed,
                            "interrupted while switching; the original folder was put back".into(),
                        );
                        Recovery::RolledBack("switch".into())
                    }
                    Err(e) => {
                        finish(
                            Status::Failed,
                            format!("could not put the original back from {}: {e}", o.display()),
                        );
                        Recovery::NeedsAttention(o.to_string_lossy().into_owned())
                    }
                }
            } else {
                finish(
                    Status::Failed,
                    "interrupted while switching; please check the folders manually".into(),
                );
                Recovery::NeedsAttention("switch".into())
            }
        }
        Status::Restoring => {
            if src_is_link && dst.is_dir() {
                finish(
                    Status::Done,
                    "restore was interrupted before it started; still migrated".into(),
                );
                Recovery::RolledBack("restore".into())
            } else if dst.is_dir() {
                // 还原中途中断：丢掉不完整的副本，重新建链接，数据仍在目标。
                let _ = fs::remove_dir_all(&src);
                match deps.links.make_junction(&src, &dst) {
                    Ok(()) => {
                        finish(
                            Status::Done,
                            "restore was interrupted; the junction was recreated".into(),
                        );
                        Recovery::RolledBack("restore".into())
                    }
                    Err(e) => {
                        finish(
                            Status::Failed,
                            format!(
                                "could not recreate the junction: {e}; your data is at {}",
                                dst.display()
                            ),
                        );
                        Recovery::NeedsAttention(dst.to_string_lossy().into_owned())
                    }
                }
            } else {
                finish(
                    Status::Failed,
                    "restore was interrupted and the migrated folder is missing".into(),
                );
                Recovery::NeedsAttention("target".into())
            }
        }
    }
}

/// 写一行迁移日志（JSON Lines），与清理日志放在同一个文件。
pub fn journal_line(journal: &mut dyn Write, rec: &MigrationRecord, event: &str) {
    let _ = writeln!(
        journal,
        "{}",
        serde_json::json!({
            "op": "migration",
            "ts": now_secs(),
            "event": event,
            "id": rec.id,
            "source": rec.source,
            "target": rec.target,
            "status": rec.status,
        })
    );
    let _ = journal.flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety::PathStyle;
    use crate::sysaction::CmdOutput;

    static N: AtomicU64 = AtomicU64::new(0);

    struct Sb {
        base: PathBuf,
    }

    impl Sb {
        fn new() -> Self {
            let n = N.fetch_add(1, Ordering::Relaxed);
            let raw = std::env::temp_dir().join(format!("dc-mig-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&raw);
            fs::create_dir_all(&raw).unwrap();
            Sb {
                base: fs::canonicalize(raw).unwrap(),
            }
        }
        fn p(&self, rel: &str) -> PathBuf {
            self.base.join(rel)
        }
        fn write(&self, rel: &str, n: usize) {
            let p = self.p(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, vec![7u8; n]).unwrap();
        }
        fn policy(&self) -> SafetyPolicy {
            let mut p = SafetyPolicy::empty(PathStyle::Posix);
            p.protect(&self.p("Windows").to_string_lossy()).unwrap();
            p
        }
        fn store(&self) -> ManifestStore {
            ManifestStore::open(self.p("meta/migrations.json"))
        }
    }

    impl Drop for Sb {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    /// 两个"卷"：`C`（沙箱里的 C 目录）与 `D`，各有自己的空闲空间。
    struct FakeVols {
        c: PathBuf,
        d: PathBuf,
        d_free: u64,
        d_removable: bool,
        d_remote: bool,
        c_fs: &'static str,
    }

    impl FakeVols {
        fn new(sb: &Sb) -> Self {
            FakeVols {
                c: sb.p("C"),
                d: sb.p("D"),
                d_free: 10 * 1024 * 1024 * 1024,
                d_removable: false,
                d_remote: false,
                c_fs: "NTFS",
            }
        }
    }

    impl Volumes for FakeVols {
        fn volume_of(&self, path: &Path) -> Option<VolumeInfo> {
            let mk = |mount: &Path, fs: &str, free, removable, remote| VolumeInfo {
                mount: mount.to_path_buf(),
                label: String::new(),
                fs: fs.into(),
                free,
                total: free * 2,
                removable,
                remote,
            };
            if path.starts_with(&self.c) {
                Some(mk(&self.c, self.c_fs, 1 << 40, false, false))
            } else if path.starts_with(&self.d) {
                Some(mk(
                    &self.d,
                    "NTFS",
                    self.d_free,
                    self.d_removable,
                    self.d_remote,
                ))
            } else {
                None
            }
        }
    }

    /// 用符号链接代替 junction（语义一致：路径透明地指向另一处）。
    struct TestLinks {
        fail_make: AtomicBool,
        calls: Mutex<Vec<String>>,
    }

    impl TestLinks {
        fn new() -> Self {
            Self {
                fail_make: AtomicBool::new(false),
                calls: Mutex::default(),
            }
        }
    }

    impl LinkMaker for TestLinks {
        fn make_junction(&self, link: &Path, target: &Path) -> io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("make {}", link.display()));
            if self.fail_make.load(Ordering::Relaxed) {
                return Err(io::Error::other("mklink failed"));
            }
            #[cfg(unix)]
            return std::os::unix::fs::symlink(target, link);
            #[cfg(not(unix))]
            {
                let _ = target;
                Err(io::Error::other("unsupported"))
            }
        }
        fn remove_link(&self, link: &Path) -> io::Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove {}", link.display()));
            remove_link(link)
        }
        fn link_target(&self, link: &Path) -> Option<PathBuf> {
            fs::read_link(link).ok()
        }
    }

    /// 复制到一半就失败的复制器（模拟磁盘写满、被杀毒软件拦截等）。
    struct FlakyCopier;
    impl Copier for FlakyCopier {
        fn copy_tree(
            &self,
            src: &Path,
            dst: &Path,
            _c: &AtomicBool,
            _b: &mut dyn FnMut(u64),
        ) -> io::Result<CopyStats> {
            fs::create_dir_all(dst)?;
            let first = fs::read_dir(src)?.flatten().find(|e| e.path().is_file());
            if let Some(f) = first {
                fs::copy(f.path(), dst.join(f.file_name()))?;
            }
            Err(io::Error::other("disk full"))
        }
    }

    /// 复制时悄悄漏掉一个文件（模拟校验要抓的错误）。
    struct LossyCopier;
    impl Copier for LossyCopier {
        fn copy_tree(
            &self,
            src: &Path,
            dst: &Path,
            c: &AtomicBool,
            b: &mut dyn FnMut(u64),
        ) -> io::Result<CopyStats> {
            let s = StdCopier.copy_tree(src, dst, c, b)?;
            if let Some(f) = fs::read_dir(dst)?.flatten().find(|e| e.path().is_file()) {
                fs::remove_file(f.path())?;
            }
            Ok(s)
        }
    }

    struct Env<'a> {
        copier: &'a dyn Copier,
        mover: &'a dyn DirMover,
        links: &'a TestLinks,
        vols: &'a FakeVols,
        store: &'a ManifestStore,
    }

    impl Env<'_> {
        fn deps(&self) -> Deps<'_> {
            Deps {
                copier: self.copier,
                mover: self.mover,
                links: self.links,
                volumes: self.vols,
                store: self.store,
            }
        }
    }

    fn setup() -> (Sb, TestLinks) {
        let sb = Sb::new();
        fs::create_dir_all(sb.p("C")).unwrap();
        fs::create_dir_all(sb.p("D")).unwrap();
        sb.write("C/App/main.bin", 4000);
        sb.write("C/App/data/a.dat", 300);
        sb.write("C/App/data/deep/b.dat", 20);
        fs::create_dir_all(sb.p("C/App/empty")).unwrap();
        (sb, TestLinks::new())
    }

    fn run(env: &Env, sb: &Sb, src: &str, dst: &str) -> Result<MigrationRecord, MigrateError> {
        migrate(
            &sb.p(src),
            &sb.p(dst),
            &env.deps(),
            &sb.policy(),
            &PreflightOptions::default(),
            &AtomicBool::new(false),
            &mut |_| {},
        )
    }

    fn codes(p: &Preflight) -> Vec<&'static str> {
        p.issues.iter().map(|i| i.code).collect()
    }

    // ----- 纯函数 -----

    #[test]
    fn robocopy_arguments_preserve_acls_and_skip_junctions() {
        let a = robocopy_args(
            Path::new(r"C:\Users\a\Docker"),
            Path::new(r"D:\Migrated\Docker"),
        );
        assert_eq!(&a[..2], [r"C:\Users\a\Docker", r"D:\Migrated\Docker"]);
        for flag in ["/E", "/COPY:DATSO", "/DCOPY:DAT", "/XJ", "/R:2", "/W:1"] {
            assert!(a.contains(&flag.to_string()), "{flag}");
        }
        assert!(
            !a.iter()
                .any(|x| x == "/MIR" || x == "/PURGE" || x == "/MOVE"),
            "绝不能带会删除源文件或多余文件的参数"
        );
    }

    #[test]
    fn robocopy_exit_codes_follow_the_bitmask_convention() {
        for ok in 0..8 {
            assert!(robocopy_exit_ok(ok), "{ok}");
        }
        for bad in [8, 9, 16, -1] {
            assert!(!robocopy_exit_ok(bad), "{bad}");
        }
    }

    #[test]
    fn path_comparison_ignores_case_separators_and_prefixes() {
        assert!(same_path(
            Path::new(r"D:\Migrated\Foo"),
            Path::new(r"\\?\d:\migrated\foo\")
        ));
        assert!(same_path(Path::new(r"\??\D:\Foo"), Path::new("D:/Foo")));
        assert!(!same_path(Path::new(r"D:\Foo"), Path::new(r"D:\Foobar")));
    }

    #[test]
    fn junction_commands_reject_shell_metacharacters() {
        struct Spy(Mutex<Vec<String>>);
        impl CommandRunner for Spy {
            fn run(&self, _: &str, _: &[&str]) -> io::Result<CmdOutput> {
                Ok(CmdOutput::default())
            }
            fn run_shell(&self, l: &str) -> io::Result<CmdOutput> {
                self.0.lock().unwrap().push(l.into());
                Ok(CmdOutput::default())
            }
        }
        let spy = Spy(Mutex::default());
        let m = MklinkJunction(&spy);
        m.make_junction(
            Path::new(r"C:\Users\a\Docker"),
            Path::new(r"D:\Migrated\Docker"),
        )
        .unwrap();
        assert_eq!(
            spy.0.lock().unwrap()[0],
            r#"mklink /J "C:\Users\a\Docker" "D:\Migrated\Docker""#
        );
        for bad in [
            r#"C:\x" & calc & ""#,
            r"C:\%USERPROFILE%\x",
            "C:\\x\ny",
            r"C:\a^b",
            r"C:\a|b",
        ] {
            assert!(
                m.make_junction(Path::new(bad), Path::new(r"D:\t")).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(spy.0.lock().unwrap().len(), 1, "非法路径不能到达命令解释器");
    }

    // ----- 预检 -----

    #[test]
    fn a_normal_migration_passes_preflight() {
        let (sb, _) = setup();
        let vols = FakeVols::new(&sb);
        let p = preflight(
            &sb.p("C/App"),
            &sb.p("D/Migrated/App"),
            &vols,
            &sb.policy(),
            &[],
            &PreflightOptions::default(),
        );
        assert!(p.can_proceed(), "{:?}", p.issues);
        assert_eq!((p.size, p.files), (4320, 3));
        assert_eq!(p.target_free, Some(10 * 1024 * 1024 * 1024));
    }

    #[test]
    fn preflight_catches_every_blocking_condition() {
        let (sb, _) = setup();
        let mut vols = FakeVols::new(&sb);
        let pol = sb.policy();
        let o = PreflightOptions::default();
        let pf = |s: &str, d: &str, v: &FakeVols, ex: &[MigrationRecord]| {
            preflight(&sb.p(s), &sb.p(d), v, &pol, ex, &o)
        };

        assert!(codes(&pf("C/Missing", "D/x", &vols, &[])).contains(&"source_missing"));
        sb.write("C/file.txt", 1);
        assert!(codes(&pf("C/file.txt", "D/x", &vols, &[])).contains(&"source_not_dir"));
        assert!(codes(&pf("C/App", "C/Other", &vols, &[])).contains(&"same_volume"));
        assert!(codes(&pf("C/App", "C/App/inside", &vols, &[])).contains(&"target_inside_source"));
        assert!(codes(&pf("C/App/data", "C/App", &vols, &[])).contains(&"source_inside_target"));
        assert!(codes(&pf("Windows/System32", "D/x", &vols, &[])).contains(&"source_protected"));
        assert!(codes(&pf("C/App", "Windows/x", &vols, &[])).contains(&"target_protected"));

        sb.write("D/taken/f", 1);
        assert!(codes(&pf("C/App", "D/taken", &vols, &[])).contains(&"target_exists_nonempty"));
        fs::create_dir_all(sb.p("D/empty-ok")).unwrap();
        assert!(
            pf("C/App", "D/empty-ok", &vols, &[]).can_proceed(),
            "已存在的空目录可以作为目标"
        );

        vols.d_free = 1000;
        assert!(codes(&pf("C/App", "D/x", &vols, &[])).contains(&"not_enough_space"));
        vols.d_free = 1 << 40;
        vols.d_removable = true;
        assert!(codes(&pf("C/App", "D/x", &vols, &[])).contains(&"target_removable"));
        vols.d_removable = false;
        vols.d_remote = true;
        assert!(codes(&pf("C/App", "D/x", &vols, &[])).contains(&"target_remote"));
        vols.d_remote = false;
        vols.c_fs = "exFAT";
        assert!(codes(&pf("C/App", "D/x", &vols, &[])).contains(&"source_fs_unsupported"));
        vols.c_fs = "NTFS";
        assert!(codes(&pf("C/App", "/unknown/place", &vols, &[])).contains(&"volume_unknown"));
        assert!(codes(&preflight(
            Path::new("relative"),
            &sb.p("D/x"),
            &vols,
            &pol,
            &[],
            &o
        ))
        .contains(&"invalid_path"));
        assert!(codes(&preflight(
            &sb.p("C/App"),
            Path::new("/d/%USERPROFILE%/x"),
            &vols,
            &pol,
            &[],
            &o
        ))
        .contains(&"invalid_path"));
    }

    #[cfg(unix)]
    #[test]
    fn links_inside_the_source_block_the_migration() {
        let (sb, _) = setup();
        std::os::unix::fs::symlink(sb.p("C/App/main.bin"), sb.p("C/App/data/shortcut")).unwrap();
        let p = preflight(
            &sb.p("C/App"),
            &sb.p("D/x"),
            &FakeVols::new(&sb),
            &sb.policy(),
            &[],
            &PreflightOptions::default(),
        );
        let issue = p
            .issues
            .iter()
            .find(|i| i.code == "contains_links")
            .unwrap();
        assert!(issue.detail.as_ref().unwrap().contains("shortcut"));
        assert_eq!(p.files, 3, "链接不计入大小");
    }

    #[cfg(unix)]
    #[test]
    fn already_migrated_directories_are_recognized() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        run(&env, &sb, "C/App", "D/App").unwrap();
        let p = preflight(
            &sb.p("C/App"),
            &sb.p("D/App2"),
            &vols,
            &sb.policy(),
            &store.list(),
            &PreflightOptions::default(),
        );
        assert!(codes(&p).contains(&"already_migrated"));
    }

    #[test]
    fn program_directories_and_huge_sources_only_warn() {
        let (sb, _) = setup();
        let o = PreflightOptions {
            program_dirs: vec![sb.p("C")],
            ..PreflightOptions::default()
        };
        let p = preflight(
            &sb.p("C/App"),
            &sb.p("D/x"),
            &FakeVols::new(&sb),
            &sb.policy(),
            &[],
            &o,
        );
        assert!(p.can_proceed());
        assert!(p
            .issues
            .iter()
            .any(|i| i.code == "program_dir" && i.severity == Severity::Warning));
    }

    // ----- 迁移 -----

    #[cfg(unix)]
    #[test]
    fn migrates_copies_verifies_links_and_removes_the_old_folder() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let mut stages = Vec::new();
        let rec = migrate(
            &sb.p("C/App"),
            &sb.p("D/Migrated/App"),
            &env.deps(),
            &sb.policy(),
            &PreflightOptions::default(),
            &AtomicBool::new(false),
            &mut |p| {
                if stages.last() != Some(&p.stage) {
                    stages.push(p.stage);
                }
            },
        )
        .unwrap();

        assert_eq!(
            stages,
            [
                Stage::Copying,
                Stage::Verifying,
                Stage::Switching,
                Stage::Cleaning
            ]
        );
        assert_eq!(rec.status, Status::Done);
        assert_eq!((rec.size, rec.files), (4320, 3));
        // 原路径现在是链接，内容经由链接可读，且真实数据在 D 上。
        assert!(fs::symlink_metadata(sb.p("C/App"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(sb.p("C/App/data/deep/b.dat")).unwrap().len(), 20);
        assert_eq!(
            fs::read(sb.p("D/Migrated/App/main.bin")).unwrap().len(),
            4000
        );
        assert!(sb.p("D/Migrated/App/empty").is_dir(), "空目录也要迁移");
        // 旧目录已删除，清单记录为完成。
        assert!(rec.old_path.is_none());
        assert!(!fs::read_dir(sb.p("C"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("dc-old")));
        assert_eq!(store.list()[0].status, Status::Done);
        assert!(sb.p("meta/migrations.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn mtimes_survive_the_copy() {
        let (sb, links) = setup();
        let old = SystemTime::now() - Duration::from_secs(86_400 * 400);
        fs::File::options()
            .write(true)
            .open(sb.p("C/App/main.bin"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        run(
            &Env {
                copier: &StdCopier,
                mover: &StdMover,
                links: &links,
                vols: &vols,
                store: &store,
            },
            &sb,
            "C/App",
            "D/App",
        )
        .unwrap();
        let got = fs::metadata(sb.p("D/App/main.bin"))
            .unwrap()
            .modified()
            .unwrap();
        let diff = got.duration_since(old).unwrap_or_else(|e| e.duration());
        assert!(diff < Duration::from_secs(2));
    }

    #[test]
    fn a_failed_preflight_changes_nothing() {
        let (sb, links) = setup();
        let store = sb.store();
        let mut vols = FakeVols::new(&sb);
        vols.d_free = 10;
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        match run(&env, &sb, "C/App", "D/App") {
            Err(MigrateError::Preflight(issues)) => {
                assert!(issues.iter().any(|i| i.code == "not_enough_space"))
            }
            other => panic!("{other:?}"),
        }
        assert!(sb.p("C/App/main.bin").exists());
        assert!(!sb.p("D/App").exists());
        assert!(store.list().is_empty(), "预检失败不应留下清单记录");
    }

    #[test]
    fn copy_failure_rolls_back_and_leaves_the_original_untouched() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &FlakyCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        assert!(
            matches!(run(&env, &sb, "C/App", "D/Migrated/App"), Err(MigrateError::CopyFailed(m)) if m.contains("disk full"))
        );
        assert!(
            sb.p("C/App/main.bin").exists()
                && !fs::symlink_metadata(sb.p("C/App"))
                    .unwrap()
                    .file_type()
                    .is_symlink()
        );
        assert!(!sb.p("D/Migrated/App").exists(), "不完整的目标必须被清掉");
        assert_eq!(store.list()[0].status, Status::Failed);
        assert!(links.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn verification_catches_a_silently_missing_file_before_anything_is_switched() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &LossyCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        assert!(
            matches!(run(&env, &sb, "C/App", "D/App"), Err(MigrateError::VerifyFailed(m)) if m.contains("missing"))
        );
        assert!(sb.p("C/App/main.bin").exists() && sb.p("C/App/data/a.dat").exists());
        assert!(!sb.p("D/App").exists());
        assert!(
            links.calls.lock().unwrap().is_empty(),
            "校验失败时不能碰原目录"
        );
    }

    #[test]
    fn cancelling_during_the_copy_rolls_back() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let cancel = AtomicBool::new(false);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let r = migrate(
            &sb.p("C/App"),
            &sb.p("D/App"),
            &env.deps(),
            &sb.policy(),
            &PreflightOptions::default(),
            &cancel,
            &mut |p| {
                if p.stage == Stage::Copying && p.done > 0 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
        );
        assert!(matches!(r, Err(MigrateError::Cancelled)));
        assert!(sb.p("C/App/main.bin").exists());
        assert!(!sb.p("D/App").exists());
    }

    /// 模拟目录被进程占用：改名时返回"拒绝访问"（Windows 上就是共享冲突）。
    struct LockedMover;
    impl DirMover for LockedMover {
        fn rename_dir(&self, _from: &Path, _to: &Path) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Access is denied. (os error 5)",
            ))
        }
    }

    #[test]
    fn a_locked_folder_that_cannot_be_renamed_is_reported_as_in_use_and_rolled_back() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &LockedMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let r = run(&env, &sb, "C/App", "D/Migrated/App");
        assert!(
            matches!(&r, Err(MigrateError::InUse(m)) if m.contains("Access is denied")),
            "{r:?}"
        );
        assert!(sb.p("C/App/main.bin").exists(), "原目录完好");
        assert!(!sb.p("D/Migrated/App").exists(), "已复制的目标要清掉");
        assert!(
            links.calls.lock().unwrap().is_empty(),
            "改名失败时不能创建链接"
        );
        let rec = &store.list()[0];
        assert_eq!(rec.status, Status::Failed);
        assert!(rec.old_path.is_none());
        // 解除占用后可以直接重试。
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        #[cfg(unix)]
        {
            run(&env, &sb, "C/App", "D/Migrated/App").unwrap();
            assert!(sb.p("D/Migrated/App/main.bin").exists());
        }
        #[cfg(not(unix))]
        let _ = env;
    }

    /// 切换时改名成功、但把原目录放回去时失败：不能谎称已回滚，要告诉用户旧目录在哪。
    #[cfg(unix)]
    #[test]
    fn if_the_original_cannot_be_put_back_the_note_says_where_it_is() {
        struct OneWayMover(AtomicBool);
        impl DirMover for OneWayMover {
            fn rename_dir(&self, from: &Path, to: &Path) -> io::Result<()> {
                if self.0.swap(true, Ordering::Relaxed) {
                    return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
                }
                fs::rename(from, to)
            }
        }
        let (sb, links) = setup();
        links.fail_make.store(true, Ordering::Relaxed);
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let mover = OneWayMover(AtomicBool::new(false));
        let env = Env {
            copier: &StdCopier,
            mover: &mover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        assert!(matches!(
            run(&env, &sb, "C/App", "D/App"),
            Err(MigrateError::LinkFailed(_))
        ));
        let note = store.list()[0].note.clone().unwrap();
        assert!(note.contains("dc-old"), "{note}");
        assert!(fs::read_dir(sb.p("C"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("dc-old")));
    }

    #[cfg(unix)]
    #[test]
    fn junction_failure_puts_the_original_back() {
        let (sb, links) = setup();
        links.fail_make.store(true, Ordering::Relaxed);
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        assert!(matches!(
            run(&env, &sb, "C/App", "D/App"),
            Err(MigrateError::LinkFailed(_))
        ));
        assert!(sb.p("C/App/main.bin").exists(), "原目录必须原样放回");
        assert!(!fs::symlink_metadata(sb.p("C/App"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!sb.p("D/App").exists());
        assert!(!fs::read_dir(sb.p("C"))
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("dc-old")));
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_empty_target_directory_is_kept_but_emptied_on_rollback() {
        let (sb, links) = setup();
        fs::create_dir_all(sb.p("D/pre-made")).unwrap();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &FlakyCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let _ = run(&env, &sb, "C/App", "D/pre-made");
        assert!(sb.p("D/pre-made").is_dir(), "不是我们创建的目录不能删");
        assert!(is_empty_dir(&sb.p("D/pre-made")));
    }

    // ----- 还原 -----

    #[cfg(unix)]
    #[test]
    fn restore_brings_the_data_back_and_removes_the_migrated_copy() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let rec = run(&env, &sb, "C/App", "D/Migrated/App").unwrap();
        let back = restore(&rec, &env.deps(), &AtomicBool::new(false), &mut |_| {}).unwrap();
        assert_eq!(back.status, Status::Restored);
        let m = fs::symlink_metadata(sb.p("C/App")).unwrap();
        assert!(
            m.is_dir() && !m.file_type().is_symlink(),
            "原路径应是真实目录"
        );
        assert_eq!(fs::read(sb.p("C/App/main.bin")).unwrap().len(), 4000);
        assert!(!sb.p("D/Migrated/App").exists());
        assert_eq!(store.get(&rec.id).unwrap().status, Status::Restored);
    }

    #[cfg(unix)]
    #[test]
    fn restore_failure_recreates_the_junction_and_keeps_the_data() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let rec = run(
            &Env {
                copier: &StdCopier,
                mover: &StdMover,
                links: &links,
                vols: &vols,
                store: &store,
            },
            &sb,
            "C/App",
            "D/App",
        )
        .unwrap();
        let env = Env {
            copier: &FlakyCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        assert!(restore(&rec, &env.deps(), &AtomicBool::new(false), &mut |_| {}).is_err());
        assert!(
            fs::symlink_metadata(sb.p("C/App"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "链接要放回去"
        );
        assert_eq!(
            fs::read(sb.p("C/App/main.bin")).unwrap().len(),
            4000,
            "数据仍可通过原路径访问"
        );
        assert_eq!(store.get(&rec.id).unwrap().status, Status::Done);
    }

    #[cfg(unix)]
    #[test]
    fn restore_is_refused_when_its_preconditions_do_not_hold() {
        let (sb, links) = setup();
        let store = sb.store();
        let vols = FakeVols::new(&sb);
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let rec = run(&env, &sb, "C/App", "D/App").unwrap();
        let go =
            |r: &MigrationRecord| restore(r, &env.deps(), &AtomicBool::new(false), &mut |_| {});
        assert!(matches!(
            go(&MigrationRecord {
                status: Status::Failed,
                ..rec.clone()
            }),
            Err(MigrateError::NotRestorable(_))
        ));
        // 链接被用户手动换成了别的东西。
        remove_link(&sb.p("C/App")).unwrap();
        fs::create_dir_all(sb.p("C/App")).unwrap();
        assert!(matches!(go(&rec), Err(MigrateError::NotRestorable(_))));
        assert!(sb.p("D/App/main.bin").exists(), "拒绝还原时不能动数据");
    }

    // ----- 崩溃恢复 -----

    fn rec_in(sb: &Sb, status: Status, old: Option<&str>) -> MigrationRecord {
        MigrationRecord {
            id: "t-1".into(),
            source: sb.p("C/App").to_string_lossy().into(),
            target: sb.p("D/App").to_string_lossy().into(),
            old_path: old.map(|o| sb.p(o).to_string_lossy().into()),
            size: 1,
            files: 1,
            created: 0,
            status,
            note: None,
            target_created: true,
        }
    }

    #[test]
    fn recovery_discards_a_partial_copy() {
        let (sb, links) = setup();
        sb.write("D/App/partial.bin", 5);
        let (store, vols) = (sb.store(), FakeVols::new(&sb));
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let r = recover(&rec_in(&sb, Status::Copying, None), &env.deps());
        assert_eq!(r, Recovery::RolledBack("copy".into()));
        assert!(!sb.p("D/App").exists());
        assert!(sb.p("C/App/main.bin").exists());
    }

    #[test]
    fn recovery_puts_the_original_back_when_interrupted_after_the_rename() {
        let (sb, links) = setup();
        fs::rename(sb.p("C/App"), sb.p("C/App.dc-old-t-1")).unwrap();
        fs::create_dir_all(sb.p("D/App")).unwrap();
        let (store, vols) = (sb.store(), FakeVols::new(&sb));
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let r = recover(
            &rec_in(&sb, Status::Switching, Some("C/App.dc-old-t-1")),
            &env.deps(),
        );
        assert_eq!(r, Recovery::RolledBack("switch".into()));
        assert!(sb.p("C/App/main.bin").exists());
        assert!(!sb.p("D/App").exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_completes_a_migration_whose_junction_already_exists() {
        let (sb, links) = setup();
        StdCopier
            .copy_tree(
                &sb.p("C/App"),
                &sb.p("D/App"),
                &AtomicBool::new(false),
                &mut |_| {},
            )
            .unwrap();
        fs::rename(sb.p("C/App"), sb.p("C/App.dc-old-t-1")).unwrap();
        std::os::unix::fs::symlink(sb.p("D/App"), sb.p("C/App")).unwrap();
        let (store, vols) = (sb.store(), FakeVols::new(&sb));
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        let r = recover(
            &rec_in(&sb, Status::Switching, Some("C/App.dc-old-t-1")),
            &env.deps(),
        );
        assert_eq!(r, Recovery::Completed("junction exists".into()));
        assert_eq!(store.get("t-1").unwrap().status, Status::Done);
        assert!(
            sb.p("C/App.dc-old-t-1").exists(),
            "旧目录留给用户确认后再删"
        );
    }

    #[test]
    fn recovery_ignores_finished_records_and_flags_confusing_states() {
        let (sb, links) = setup();
        let (store, vols) = (sb.store(), FakeVols::new(&sb));
        let env = Env {
            copier: &StdCopier,
            mover: &StdMover,
            links: &links,
            vols: &vols,
            store: &store,
        };
        for s in [Status::Done, Status::Failed, Status::Restored] {
            assert_eq!(
                recover(&rec_in(&sb, s, None), &env.deps()),
                Recovery::Nothing
            );
        }
        // 切换中断，但既没有链接也找不到旧目录：不猜，交给人工。
        fs::remove_dir_all(sb.p("C/App")).unwrap();
        assert!(matches!(
            recover(&rec_in(&sb, Status::Switching, Some("C/gone")), &env.deps()),
            Recovery::NeedsAttention(_)
        ));
    }

    #[test]
    fn cloud_sync_folders_cannot_be_moved() {
        let (sb, _) = setup();
        fs::create_dir_all(sb.p("C/Google Drive/Projects")).unwrap();
        sb.write("C/Google Drive/Projects/a.bin", 10);
        sb.write("C/OneDrive - Work/b.bin", 10);
        let vols = FakeVols::new(&sb);
        for src in [
            "C/Google Drive",
            "C/Google Drive/Projects",
            "C/OneDrive - Work",
        ] {
            let p = preflight(
                &sb.p(src),
                &sb.p("D/x"),
                &vols,
                &sb.policy(),
                &[],
                &PreflightOptions::default(),
            );
            let issue = p
                .issues
                .iter()
                .find(|i| i.code == "cloud_location")
                .unwrap_or_else(|| panic!("{src}: {:?}", p.issues));
            assert!(issue.detail.is_some());
            assert!(!p.can_proceed());
        }
        let normal = preflight(
            &sb.p("C/App"),
            &sb.p("D/x"),
            &vols,
            &sb.policy(),
            &[],
            &PreflightOptions::default(),
        );
        assert!(!codes(&normal).contains(&"cloud_location"));
    }

    // ----- 安全策略 -----

    #[test]
    fn migration_policy_allows_app_data_subfolders_but_not_system_or_user_roots() {
        let p = migration_policy(&crate::safety::KnownDirs::typical("alice")).unwrap();
        for ok in [
            r"C:\Users\alice\AppData\Local\Docker",
            r"C:\Users\alice\AppData\Roaming\Claude\vm_bundles",
            r"C:\Users\alice\Documents\BigProject",
            r"C:\Users\alice\Games",
            r"C:\Program Files\Foo",
            r"C:\Program Files (x86)\Bar",
            r"C:\ProgramData\Foo",
            r"D:\Anything\Else",
        ] {
            assert!(p.check_delete(ok).is_ok(), "{ok}");
        }
        for bad in [
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Users",
            r"C:\Users\alice",
            r"C:\Users\alice\AppData",
            r"C:\Users\alice\AppData\Local",
            r"C:\Users\alice\AppData\Roaming",
            r"C:\Users\alice\AppData\Local\Microsoft",
            r"C:\Users\alice\AppData\Local\Packages\X",
            r"C:\Users\alice\Documents",
            r"C:\Users\alice\Desktop",
            r"C:\Program Files",
            r"C:\Program Files\WindowsApps",
            r"C:\Program Files\Common Files",
            r"C:\ProgramData",
            r"C:\ProgramData\Microsoft",
            r"C:\$Recycle.Bin",
            r"C:\",
            r"C:\Users\alice\.ssh",
        ] {
            assert!(p.check_delete(bad).is_err(), "{bad}");
        }
    }

    // ----- 清单文件 -----

    #[test]
    fn the_manifest_persists_updates_and_survives_corruption() {
        let sb = Sb::new();
        let path = sb.p("meta/migrations.json");
        let store = ManifestStore::open(path.clone());
        assert!(store.list().is_empty());
        let mut r = rec_in(&sb, Status::Copying, None);
        store.upsert(&r).unwrap();
        r.status = Status::Done;
        store.upsert(&r).unwrap();
        let reopened = ManifestStore::open(path.clone());
        assert_eq!(reopened.list().len(), 1);
        assert_eq!(reopened.get("t-1").unwrap().status, Status::Done);
        fs::write(&path, "{ not json").unwrap();
        assert!(ManifestStore::open(path).list().is_empty());
    }

    #[test]
    fn verify_reports_missing_extra_and_changed_entries() {
        let sb = Sb::new();
        sb.write("a/x", 1);
        sb.write("a/y", 2);
        sb.write("b/x", 1);
        sb.write("b/y", 3);
        sb.write("b/z", 1);
        let e = verify_equal(&sb.p("a"), &sb.p("b")).unwrap_err();
        assert!(e.contains("differs: y") && e.contains("extra: z"), "{e}");
        assert!(verify_equal(&sb.p("a"), &sb.p("a")).is_ok());
    }

    #[test]
    fn migration_journal_lines_are_json() {
        let sb = Sb::new();
        let mut buf: Vec<u8> = Vec::new();
        journal_line(&mut buf, &rec_in(&sb, Status::Done, None), "done");
        let v: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().trim()).unwrap();
        assert_eq!(
            (v["op"].as_str(), v["event"].as_str(), v["status"].as_str()),
            (Some("migration"), Some("done"), Some("done"))
        );
    }
}
