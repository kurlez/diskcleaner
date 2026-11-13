//! 与 Tauri 无关的应用服务层：持有扫描结果和清理计划，向界面提供可序列化的 DTO。
//!
//! 安全要点：界面**只能**提交规则 ID；真正要删除的路径始终来自后端保存的计划，
//! 前端无法注入任意路径。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use diskclean_core::cleaner::{execute_with, ExecOptions, Report, Status};
use diskclean_core::cloud::{self, CloudRules};
use diskclean_core::duplicates::{self, DupGroup, DupOptions, DupOutcome, DupPhase};
use diskclean_core::migrate::{
    self, Copier, Deps, DirMover, LinkMaker, ManifestStore, MigrateError, MigrationRecord,
    Preflight, PreflightOptions, Recovery, Severity, Stage, Volumes,
};
use diskclean_core::plan::{build_plan, Candidate, Plan, PlanSkipReason};
use diskclean_core::procs::{
    self, Blocker, BlockerKind, BlockerReport, OpenFileFinder, ProcessSource, Protection,
    RelatedReason, StopStatus, StopTiming,
};
use diskclean_core::registry::{Hive, NoRegistry, Registry};
use diskclean_core::rules::{Disposal, Env, Risk, Rule};
use diskclean_core::safety::SafetyPolicy;
use diskclean_core::scanner::{self, Node, Progress, ScanOutcome};
use diskclean_core::sysaction::{self, CommandRunner, ScServices, SystemRunner};
use diskclean_core::uninstall::{
    self, AppSource, Confidence, DeleteCtx, DeleteError, FsRoots, InstalledApp, Leftover,
    LeftoverScan, Reason, RegStatus, Target, UninstallError,
};
use serde::Serialize;

const MAX_CHILDREN: usize = 1000;
const TOP_FILES: usize = 50;
const MAX_PLAN_ITEMS: usize = 300;
const MAX_PROBLEMS: usize = 200;

/// 返回给界面的错误：`code` 供界面翻译，`detail` 是附带的原始信息。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }
    pub fn with(code: &'static str, detail: impl ToString) -> Self {
        Self {
            code,
            detail: Some(detail.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, ApiError>;

/// 去掉 `\\?\` 前缀，仅用于展示。
pub fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

// ---------- DTO ----------

#[derive(Debug, Serialize)]
pub struct DriveDto {
    pub mount: String,
    pub name: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
    /// 云端虚拟盘或网络驱动器的服务名（如 `Google Drive`、`Network`）；普通磁盘为空。
    pub cloud: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExcludedDto {
    pub path: String,
    /// 服务名（如 `OneDrive`）或 `custom`。
    pub reason: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct FileDto {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    /// `mft`（NTFS 快速扫描，大小为占用空间）或 `walk`（逐目录遍历，大小为逻辑大小）。
    pub method: &'static str,
    /// 想用快速扫描却回退到遍历时的原因代码（`access_denied`、`not_ntfs` 等）。
    pub fallback: Option<&'static str>,
    pub root: String,
    pub total_size: u64,
    pub file_count: u64,
    pub skipped: usize,
    /// 没有参与分析的云端/同步目录与自定义跳过的目录。
    pub excluded: Vec<ExcludedDto>,
    pub cancelled: bool,
    /// 本次扫描的耗时（毫秒）。
    pub elapsed_ms: u64,
    /// 小于该大小的项目没有单独列出（0 表示全部列出）。
    pub min_size: u64,
    pub top_files: Vec<FileDto>,
}

#[derive(Debug, Serialize)]
pub struct ChildDto {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub file_count: u64,
}

#[derive(Debug, Serialize)]
pub struct ChildrenDto {
    pub items: Vec<ChildDto>,
    /// 因数量上限而未返回的子项个数。
    pub hidden: usize,
    /// 这个目录下因小于"最小显示大小"而没有单独列出的项目：总大小与文件数。
    pub small_size: u64,
    pub small_files: u64,
}

#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub risk: Risk,
    pub default_selected: bool,
    pub disposal: Disposal,
}

#[derive(Debug, Serialize)]
pub struct RuleTotal {
    pub rule_id: String,
    pub size: u64,
    pub files: u64,
}

#[derive(Debug, Serialize)]
pub struct SkipCount {
    pub reason: &'static str,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct PlanItemDto {
    pub rule_id: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Serialize)]
pub struct PlanSummary {
    pub by_rule: Vec<RuleTotal>,
    pub total_size: u64,
    pub total_files: u64,
    pub item_count: usize,
    pub skipped: Vec<SkipCount>,
    /// 按大小降序的前若干项，仅供预览。
    pub items: Vec<PlanItemDto>,
    pub cancelled: bool,
}

#[derive(Debug, Serialize)]
pub struct Problem {
    pub rule_id: String,
    pub path: String,
    /// `failed` 或 `refused`。
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ReportDto {
    pub dry_run: bool,
    pub freed_bytes: u64,
    pub recycled_bytes: u64,
    pub deleted: usize,
    pub recycled: usize,
    pub would_delete: usize,
    pub failed: usize,
    pub refused: usize,
    pub cancelled: bool,
    pub problems: Vec<Problem>,
    /// 停止/恢复 Windows 服务时遇到的问题。
    pub service_errors: Vec<String>,
    pub journal_path: String,
}

#[derive(Debug, Serialize)]
pub struct DupFileDto {
    pub path: String,
    pub modified: u64,
}

#[derive(Debug, Serialize)]
pub struct DupGroupDto {
    /// 在后端保存的结果里的序号；删除时前端只回传序号，不回传路径。
    pub id: usize,
    pub size: u64,
    pub wasted: u64,
    /// 推荐保留的文件下标。
    pub keep: usize,
    pub files: Vec<DupFileDto>,
}

#[derive(Debug, Serialize)]
pub struct DupSummary {
    pub groups: Vec<DupGroupDto>,
    /// 因数量上限未返回的组数。
    pub hidden_groups: usize,
    pub total_wasted: u64,
    pub scanned_files: u64,
    pub errors: u64,
    pub excluded: Vec<ExcludedDto>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct DupProgressDto {
    /// `walking` / `partial` / `full`
    pub phase: &'static str,
    pub done: u64,
    pub total: u64,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct DupSelection {
    pub group: usize,
    pub file: usize,
    /// 界面看到的该文件的路径。给出时必须与后端保存的一致：别处的清理可能已经让序号错位，
    /// 不一致就拒绝，而不是删到别的文件。
    #[serde(default)]
    pub path: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct SysActionDto {
    pub id: &'static str,
    pub risk: Risk,
    /// 预计释放的字节数；无法估算时为空。
    pub estimate: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct SysResultDto {
    pub id: &'static str,
    /// 系统盘可用空间的变化（执行前后），无法获取时为空。
    pub free_before: Option<u64>,
    pub free_after: Option<u64>,
    pub output: String,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct ProgressDto {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct CleanProgressDto {
    pub done: usize,
    pub total: usize,
}

#[derive(Clone, Copy)]
pub struct ExecRequest {
    pub dry_run: bool,
    pub recycle: bool,
}

// ---------- 应用卸载 DTO ----------

#[derive(Debug, Serialize)]
pub struct AppDto {
    /// 在后端保存的列表里的序号；之后的操作只传这个序号。
    pub id: usize,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    /// `YYYY-MM-DD`；登记里没有或格式不对时为空。
    pub install_date: Option<String>,
    pub size_kb: Option<u64>,
    pub install_location: Option<String>,
    /// `desktop`、`store` 或 `bundle`（macOS 的 `.app`）。
    pub kind: &'static str,
    /// 有可用的卸载命令（Store 应用总是可以）。没有时只能"强制删除"。
    pub can_uninstall: bool,
    /// 将要运行的卸载命令，供用户在确认前查看。
    pub uninstall_command: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UninstallRunDto {
    pub exit_code: i32,
    pub still_registered: bool,
}

#[derive(Debug, Serialize)]
pub struct LeftoverDto {
    pub id: usize,
    /// `folder` / `file` / `reg_key` / `reg_value`
    pub kind: &'static str,
    /// 文件路径，或带根的注册表路径（如 `HKLM\SOFTWARE\Foo`）。
    pub path: String,
    pub value_name: Option<String>,
    pub confidence: &'static str,
    pub reason: &'static str,
    pub size: u64,
    pub files: u64,
    /// 高置信度的默认勾选。
    pub default_selected: bool,
}

#[derive(Debug, Serialize)]
pub struct LeftoversDto {
    pub items: Vec<LeftoverDto>,
    pub still_registered: bool,
    pub install_dir: Option<String>,
    pub total_size: u64,
}

#[derive(Debug, Serialize)]
pub struct RegResultDto {
    pub path: String,
    pub value_name: Option<String>,
    /// `deleted` / `missing` / `refused` / `failed`
    pub status: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LeftoverReportDto {
    pub registry: Vec<RegResultDto>,
    pub files: ReportDto,
    /// 注册表备份文件，可双击导入恢复。
    pub backup_file: Option<String>,
}

// ---------- 候选清单 DTO ----------

#[derive(Debug, Serialize)]
pub struct CandResolved {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub files: u64,
    /// 磁盘上是否还存在（扫描之后可能已被删除）。
    pub exists: bool,
    /// 是链接/junction/云占位文件：这类项不会被处理。
    pub is_link: bool,
}

// ---------- 目录迁移 DTO ----------

#[derive(Debug, Serialize)]
pub struct IssueDto {
    /// `error` 会阻止迁移；`warning` 只是提示。
    pub severity: &'static str,
    pub code: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PreflightDto {
    pub size: u64,
    pub files: u64,
    pub issues: Vec<IssueDto>,
    pub can_proceed: bool,
    pub source_volume: Option<String>,
    pub target_volume: Option<String>,
    pub target_free: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct RelatedDto {
    pub pid: u32,
    pub name: String,
    /// `descendant` / `same_folder`
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct BlockerDto {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    /// `image` / `current_dir` / `open_file` / `service`
    pub kinds: Vec<&'static str>,
    pub service: Option<String>,
    /// `this_app` / `critical` / `explorer` / `service_host`；有值时不允许停止。
    pub protection: Option<&'static str>,
    pub related: Vec<RelatedDto>,
}

#[derive(Debug, Serialize)]
pub struct BlockersDto {
    pub blockers: Vec<BlockerDto>,
    pub rm_error: Option<String>,
    pub files_checked: usize,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct StopResultDto {
    pub pid: u32,
    pub name: String,
    /// `exited` / `forced` / `service_stopped` / `already_gone` / `still_running` / `refused` / `failed`
    pub status: &'static str,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MigrationDto {
    pub id: String,
    pub source: String,
    pub target: String,
    pub size: u64,
    pub files: u64,
    pub created: u64,
    /// `copying` / `switching` / `done` / `restoring` / `failed` / `restored`
    pub status: &'static str,
    pub note: Option<String>,
    pub old_path: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct MigProgressDto {
    /// `copying` / `verifying` / `switching` / `cleaning`
    pub stage: &'static str,
    pub done: u64,
    pub total: u64,
}

/// 目录迁移所需的外部能力（生产环境与测试各自提供）。
pub struct MigrateParts {
    pub procs: Arc<dyn ProcessSource>,
    pub rm: Arc<dyn OpenFileFinder>,
    pub volumes: Arc<dyn Volumes>,
    pub copier: Arc<dyn Copier>,
    pub mover: Arc<dyn DirMover>,
    pub links: Arc<dyn LinkMaker>,
    pub policy_factory: Arc<PolicyFactory>,
    pub manifest_path: PathBuf,
    pub program_dirs: Vec<PathBuf>,
    pub system_dirs: Vec<PathBuf>,
    /// macOS：符号链接代替 junction、路径不经命令解释器等（见 `PreflightOptions::unix_links`）。
    pub unix_links: bool,
    pub self_pid: u32,
    /// 停止进程时的等待时间（生产环境用默认值，测试用极短值）。
    pub stop_timing: StopTiming,
}

struct MigState {
    parts: MigrateParts,
    store: ManifestStore,
    blockers: Mutex<Option<(PathBuf, BlockerReport)>>,
    cancel: AtomicBool,
}

// ---------- Service ----------

pub type PolicyFactory = dyn Fn(&[String]) -> Result<SafetyPolicy> + Send + Sync;

/// 快速扫描器：成功返回目录树，失败返回 (原因代码, 详情) 让服务层回退到遍历。
pub type FastScanFn = dyn Fn(
        &Path,
        &AtomicBool,
        &mut dyn FnMut(&Progress),
    ) -> std::result::Result<ScanOutcome, (&'static str, String)>
    + Send
    + Sync;

struct ScanState {
    root_path: PathBuf,
    root: Node,
    method: &'static str,
    fallback: Option<&'static str>,
    skipped: usize,
    excluded: Vec<scanner::Excluded>,
    elapsed_ms: u64,
    min_size: u64,
}

pub struct Service {
    rules: Vec<Rule>,
    env: Env,
    policy_factory: Arc<PolicyFactory>,
    /// 用户亲自选中文件时使用的策略（如删除重复文件）。
    selected_policy_factory: Arc<PolicyFactory>,
    runner: Arc<dyn CommandRunner>,
    fast_scan: Option<Box<FastScanFn>>,
    scan: Mutex<Option<ScanState>>,
    plan: Mutex<Option<Plan>>,
    dup: Mutex<Option<DupOutcome>>,
    scan_cancel: Arc<AtomicBool>,
    clean_cancel: Arc<AtomicBool>,
    dup_cancel: Arc<AtomicBool>,
    registry: Arc<dyn Registry>,
    leftover_policy_factory: Arc<PolicyFactory>,
    fs_roots: FsRoots,
    apps: Mutex<Vec<InstalledApp>>,
    leftovers: Mutex<Option<LeftoverState>>,
    mig: Option<MigState>,
    /// macOS：应用管理的配置（家目录、应用目录、移入废纸篓的方式）。
    mac: Option<MacConfig>,
}

/// 把一个路径移入废纸篓的函数。
pub type TrashFn = dyn Fn(&Path) -> std::io::Result<()> + Send + Sync;

/// macOS 应用管理所需的外部能力。
pub struct MacConfig {
    pub home: String,
    pub app_roots: Vec<PathBuf>,
    /// 把应用包移入废纸篓（生产环境用 `trash` crate，测试注入假实现）。
    pub trash: Arc<TrashFn>,
}

struct LeftoverState {
    app_name: String,
    scan: LeftoverScan,
    policy: SafetyPolicy,
}

impl Service {
    pub fn new(
        rules: Vec<Rule>,
        env: Env,
        policy_factory: Box<PolicyFactory>,
        fast_scan: Option<Box<FastScanFn>>,
    ) -> Self {
        let policy_factory: Arc<PolicyFactory> = Arc::from(policy_factory);
        let policy_factory_for_leftovers = policy_factory.clone();
        Self {
            rules,
            env,
            selected_policy_factory: policy_factory.clone(),
            policy_factory,
            runner: Arc::new(SystemRunner),
            fast_scan,
            scan: Mutex::new(None),
            plan: Mutex::new(None),
            dup: Mutex::new(None),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            clean_cancel: Arc::new(AtomicBool::new(false)),
            dup_cancel: Arc::new(AtomicBool::new(false)),
            registry: Arc::new(NoRegistry),
            leftover_policy_factory: policy_factory_for_leftovers,
            fs_roots: FsRoots::default(),
            apps: Mutex::new(Vec::new()),
            leftovers: Mutex::new(None),
            mig: None,
            mac: None,
        }
    }

    /// 启用 macOS 的应用管理（枚举 `.app`、移入废纸篓、`~/Library` 残留）。
    pub fn with_mac(mut self, mac: MacConfig) -> Self {
        self.mac = Some(mac);
        self
    }

    /// 注入目录迁移所需的外部能力，并读取迁移清单。
    pub fn with_migrate(mut self, parts: MigrateParts) -> Self {
        let store = ManifestStore::open(parts.manifest_path.clone());
        self.mig = Some(MigState {
            parts,
            store,
            blockers: Mutex::new(None),
            cancel: AtomicBool::new(false),
        });
        self
    }

    /// 注入注册表、残留文件的安全策略与扫描位置（生产环境与测试各自提供）。
    pub fn with_uninstall(
        mut self,
        registry: Arc<dyn Registry>,
        leftover_policy_factory: Box<PolicyFactory>,
        fs_roots: FsRoots,
    ) -> Self {
        self.registry = registry;
        self.leftover_policy_factory = Arc::from(leftover_policy_factory);
        self.fs_roots = fs_roots;
        self
    }

    /// 替换外部命令执行器与"用户选中文件"策略（生产环境与测试各自注入）。
    pub fn with_system(
        mut self,
        runner: Arc<dyn CommandRunner>,
        selected_policy_factory: Box<PolicyFactory>,
    ) -> Self {
        self.runner = runner;
        self.selected_policy_factory = Arc::from(selected_policy_factory);
        self
    }

    pub fn drives(&self) -> Vec<DriveDto> {
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let mut v: Vec<DriveDto> = disks
            .list()
            .iter()
            .filter(|d| d.total_space() > 0)
            .filter(|d| !is_hidden_mount(d.mount_point()))
            .map(|d| DriveDto {
                mount: display_path(d.mount_point()),
                name: d.name().to_string_lossy().into_owned(),
                fs: d.file_system().to_string_lossy().into_owned(),
                total: d.total_space(),
                free: d.available_space(),
                cloud: cloud::provider_of_label(&d.name().to_string_lossy())
                    .map(str::to_string)
                    .or_else(|| {
                        self.mig.as_ref().and_then(|m| {
                            cloud::drive_provider(m.parts.volumes.as_ref(), d.mount_point())
                        })
                    }),
            })
            .collect();
        v.sort_by(|a, b| a.mount.cmp(&b.mount));
        v
    }

    // ----- 扫描 -----

    #[cfg_attr(not(test), allow(dead_code))]
    /// 默认规则（排除云端/同步目录）的扫描。
    pub fn scan(
        &self,
        path: &str,
        on_progress: &mut dyn FnMut(ProgressDto),
    ) -> Result<ScanSummary> {
        self.scan_with(path, 0, &self.default_cloud_rules(), on_progress)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// 没有设置时的默认规则：排除云端/同步目录，不跳过任何自定义路径。
    pub fn default_cloud_rules(&self) -> CloudRules {
        CloudRules::new(false, &[], &self.env)
    }

    /// 路径所在的位置是否应当排除（云端虚拟盘、网络驱动器，或位于云同步/自定义跳过的目录里）。
    fn excluded_location(&self, path: &Path, rules: &CloudRules) -> Option<String> {
        if let Some(r) = rules.location_excluded(path) {
            return Some(r);
        }
        // 云盘/网络驱动器整盘排除；设置里选择"分析云端"时才放开（自定义跳过路径仍然生效，上面已处理）。
        let m = self.mig.as_ref()?;
        if !rules_allow_cloud(rules) {
            return cloud::drive_provider(m.parts.volumes.as_ref(), path);
        }
        None
    }

    pub fn scan_with(
        &self,
        path: &str,
        min_size: u64,
        rules: &CloudRules,
        on_progress: &mut dyn FnMut(ProgressDto),
    ) -> Result<ScanSummary> {
        let root_path = PathBuf::from(path);
        if path.trim().is_empty() || !root_path.is_dir() {
            return Err(ApiError::with("invalid_path", path));
        }
        if let Some(provider) = self.excluded_location(&root_path, rules) {
            return Err(ApiError::with("cloud_location", provider));
        }
        self.scan_cancel.store(false, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let filter = |p: &Path| rules.excluded_dir(p);

        let mut method = "walk";
        let mut fallback = None;
        let mut fast = None;
        if let Some(f) = &self.fast_scan {
            match f(&root_path, &self.scan_cancel, &mut |p: &Progress| {
                on_progress(ProgressDto {
                    files: p.files,
                    dirs: p.dirs,
                    bytes: p.bytes,
                });
            }) {
                Ok(mut out) => {
                    method = "mft";
                    // MFT 一次读出整个卷，没有"遍历时跳过"的机会：事后把被排除的目录剪掉。
                    out.excluded = scanner::prune_excluded(&mut out.root, &root_path, &filter);
                    fast = Some(out);
                }
                Err((code, _detail)) => fallback = Some(code),
            }
        }
        let mut out = match fast {
            Some(out) => out,
            None => scanner::scan_filtered(
                &root_path,
                &self.scan_cancel,
                &mut |p: &Progress| {
                    on_progress(ProgressDto {
                        files: p.files,
                        dirs: p.dirs,
                        bytes: p.bytes,
                    });
                },
                Some(&filter),
            )
            .map_err(|e| ApiError::with("scan_failed", e))?,
        };

        // 只列出大头：小文件/小目录的大小仍计入上级，但不再单独保留。
        scanner::prune_small(&mut out.root, min_size);
        let state = ScanState {
            root_path,
            root: out.root,
            method,
            fallback,
            skipped: out.skipped.len(),
            excluded: out.excluded,
            elapsed_ms: started.elapsed().as_millis() as u64,
            min_size,
        };
        let summary = summarize(&state, out.cancelled);
        *self.scan.lock().unwrap() = Some(state);
        Ok(summary)
    }

    /// 当前保存的扫描结果的摘要。清理或迁移之后，界面用它直接刷新，不需要重新扫描。
    pub fn scan_current(&self) -> Result<ScanSummary> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        Ok(summarize(state, false))
    }

    /// 这些路径已被删除或搬走：从扫描树和重复文件结果里去掉，并同步修正上级目录的大小。
    pub(crate) fn prune(&self, paths: &[PathBuf]) {
        if paths.is_empty() {
            return;
        }
        if let Some(state) = self.scan.lock().unwrap().as_mut() {
            for p in paths {
                if let Some(parts) = scanner::parts_below(&state.root_path, p) {
                    if !parts.is_empty() {
                        scanner::remove_path(&mut state.root, &parts);
                    }
                }
            }
        }
        if let Some(out) = self.dup.lock().unwrap().as_mut() {
            let gone: std::collections::HashSet<String> = paths
                .iter()
                .map(|p| p.to_string_lossy().to_lowercase())
                .collect();
            for g in &mut out.groups {
                g.files
                    .retain(|f| !gone.contains(&f.path.to_string_lossy().to_lowercase()));
            }
            out.groups.retain(|g| g.files.len() > 1);
        }
    }

    /// 某个目录的内容变了（比如刚还原回来）：重新遍历它，并把结果接回扫描树。
    pub(crate) fn graft(&self, path: &Path) {
        let Ok(out) = scanner::scan(path, &AtomicBool::new(false), &mut |_| {}) else {
            return;
        };
        if let Some(state) = self.scan.lock().unwrap().as_mut() {
            if let Some(parts) = scanner::parts_below(&state.root_path, path) {
                if !parts.is_empty() {
                    scanner::replace_path(&mut state.root, &parts, out.root);
                }
            }
        }
    }

    pub fn cancel_scan(&self) {
        self.scan_cancel.store(true, Ordering::Relaxed);
    }

    /// `parts` 是从扫描根开始的目录名序列；空序列表示根本身。
    pub fn children(&self, parts: &[String]) -> Result<ChildrenDto> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut node = &state.root;
        for part in parts {
            node = node
                .children
                .iter()
                .find(|c| c.is_dir && &c.name == part)
                .ok_or_else(|| ApiError::with("invalid_path", part))?;
        }
        let items = node
            .children
            .iter()
            .take(MAX_CHILDREN)
            .map(|c| ChildDto {
                name: c.name.clone(),
                size: c.size,
                is_dir: c.is_dir,
                file_count: c.file_count,
            })
            .collect();
        Ok(ChildrenDto {
            items,
            hidden: node.children.len().saturating_sub(MAX_CHILDREN),
            small_size: node
                .size
                .saturating_sub(node.children.iter().map(|c| c.size).sum()),
            small_files: node
                .file_count
                .saturating_sub(node.children.iter().map(|c| c.file_count).sum()),
        })
    }

    /// 把"根 + 目录名序列"还原成真实路径，供"在资源管理器中显示"使用。
    /// 只接受扫描结果中确实存在的路径。
    pub fn resolve_in_scan(&self, parts: &[String]) -> Result<PathBuf> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut node = &state.root;
        let mut path = state.root_path.clone();
        for part in parts {
            node = node
                .children
                .iter()
                .find(|c| &c.name == part)
                .ok_or_else(|| ApiError::with("invalid_path", part))?;
            path.push(part);
        }
        Ok(path)
    }

    // ----- 规则 / 计划 / 执行 -----

    pub fn rules(&self) -> Vec<RuleDto> {
        self.rules
            .iter()
            .map(|r| RuleDto {
                id: r.id.clone(),
                risk: r.risk,
                default_selected: r.default_selected,
                disposal: r.disposal,
            })
            .collect()
    }

    pub fn validate_exclusion(&self, path: &str) -> Result<()> {
        if path.trim().is_empty() {
            return Err(ApiError::with("invalid_exclusion", path));
        }
        (self.policy_factory)(&[path.to_string()]).map(|_| ())
    }

    pub fn build_plan(&self, rule_ids: &[String], exclusions: &[String]) -> Result<PlanSummary> {
        for id in rule_ids {
            if !self.rules.iter().any(|r| &r.id == id) {
                return Err(ApiError::with("unknown_rule", id));
            }
        }
        let policy = (self.policy_factory)(exclusions)?;
        let ids: Vec<&str> = rule_ids.iter().map(String::as_str).collect();
        let cancel = AtomicBool::new(false);
        let plan = build_plan(
            &self.rules,
            &ids,
            &self.env,
            &policy,
            SystemTime::now(),
            &cancel,
        );

        let mut items: Vec<_> = plan.items.iter().collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.size));
        let summary = PlanSummary {
            by_rule: plan
                .by_rule()
                .into_iter()
                .map(|(rule_id, size, files)| RuleTotal {
                    rule_id,
                    size,
                    files,
                })
                .collect(),
            total_size: plan.total_size(),
            total_files: plan.total_files(),
            item_count: plan.items.len(),
            skipped: skip_counts(&plan),
            items: items
                .into_iter()
                .take(MAX_PLAN_ITEMS)
                .map(|c| PlanItemDto {
                    rule_id: c.rule_id.clone(),
                    path: display_path(&c.path),
                    size: c.size,
                    is_dir: c.is_dir,
                })
                .collect(),
            cancelled: plan.cancelled,
        };
        *self.plan.lock().unwrap() = Some(plan);
        Ok(summary)
    }

    pub fn discard_plan(&self) {
        *self.plan.lock().unwrap() = None;
    }

    pub fn cancel_clean(&self) {
        self.clean_cancel.store(true, Ordering::Relaxed);
    }

    /// 执行当前保存的计划。计划一经取出即作废（无论成败），要再清理必须重新分析。
    pub fn execute(
        &self,
        req: ExecRequest,
        journal_path: &Path,
        on_progress: &mut dyn FnMut(CleanProgressDto),
    ) -> Result<ReportDto> {
        let plan = self
            .plan
            .lock()
            .unwrap()
            .take()
            .ok_or(ApiError::new("no_plan"))?;
        self.clean_cancel.store(false, Ordering::Relaxed);
        let mut journal = open_journal(journal_path)?;
        let opts = ExecOptions {
            dry_run: req.dry_run,
            override_disposal: req.recycle.then_some(Disposal::Recycle),
        };
        let services = ScServices::new(self.runner.as_ref());
        let report = execute_with(
            &plan,
            opts,
            Some(&mut journal as &mut dyn Write),
            Some(&services),
            &self.clean_cancel,
            &mut |done, total| on_progress(CleanProgressDto { done, total }),
        );
        self.prune(&removed_paths(&report));
        Ok(report_dto(&report, req.dry_run, journal_path))
    }

    // ----- 重复文件 -----

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn dup_scan(
        &self,
        path: &str,
        min_size: u64,
        on_progress: &mut dyn FnMut(DupProgressDto),
    ) -> Result<DupSummary> {
        self.dup_scan_with(path, min_size, &self.default_cloud_rules(), on_progress)
    }

    pub fn dup_scan_with(
        &self,
        path: &str,
        min_size: u64,
        rules: &CloudRules,
        on_progress: &mut dyn FnMut(DupProgressDto),
    ) -> Result<DupSummary> {
        let root = PathBuf::from(path);
        if path.trim().is_empty() || !root.is_dir() {
            return Err(ApiError::with("invalid_path", path));
        }
        if let Some(provider) = self.excluded_location(&root, rules) {
            return Err(ApiError::with("cloud_location", provider));
        }
        self.dup_cancel.store(false, Ordering::Relaxed);
        let opts = DupOptions {
            min_size,
            ..DupOptions::default()
        };
        let out = duplicates::find_duplicates_filtered(
            &root,
            &opts,
            &self.dup_cancel,
            &mut |p| {
                on_progress(DupProgressDto {
                    phase: match p.phase {
                        DupPhase::Walking => "walking",
                        DupPhase::PartialHash => "partial",
                        DupPhase::FullHash => "full",
                    },
                    done: p.done,
                    total: p.total,
                })
            },
            Some(&|p: &Path| rules.excluded_dir(p)),
        )
        .map_err(|e| ApiError::with("scan_failed", e))?;
        let summary = dup_summary(&out);
        *self.dup.lock().unwrap() = Some(out);
        Ok(summary)
    }

    pub fn cancel_dup(&self) {
        self.dup_cancel.store(true, Ordering::Relaxed);
    }

    /// 删除用户勾选的重复文件。
    ///
    /// 前端只传 (组序号, 文件序号)；路径取自后端保存的扫描结果。删除前逐项确认：
    /// * 每组至少保留一份，且保留的那份仍在、没有变化；
    /// * 被删文件的大小和修改时间与扫描时一致。
    ///
    /// 任何一项不满足就整体拒绝，不会删除任何文件。
    pub fn dup_delete(
        &self,
        selections: &[DupSelection],
        recycle: bool,
        exclusions: &[String],
        journal_path: &Path,
        on_progress: &mut dyn FnMut(CleanProgressDto),
    ) -> Result<ReportDto> {
        let candidates = {
            let guard = self.dup.lock().unwrap();
            let out = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
            validate_selection(out, selections, recycle)?
        };
        let policy = (self.selected_policy_factory)(exclusions)?;
        let plan = Plan::from_items(candidates, policy);
        self.clean_cancel.store(false, Ordering::Relaxed);
        let mut journal = open_journal(journal_path)?;
        let report = execute_with(
            &plan,
            ExecOptions::default(),
            Some(&mut journal as &mut dyn Write),
            None,
            &self.clean_cancel,
            &mut |done, total| on_progress(CleanProgressDto { done, total }),
        );

        // 已经删除（或进了回收站）的文件从保存的结果里移除，界面刷新后不会再看到它们。
        let gone: std::collections::HashSet<&str> = report
            .entries
            .iter()
            .filter(|e| matches!(e.status, Status::Deleted | Status::Recycled))
            .map(|e| e.path.as_str())
            .collect();
        if let Some(out) = self.dup.lock().unwrap().as_mut() {
            for g in &mut out.groups {
                g.files
                    .retain(|f| !gone.contains(f.path.to_string_lossy().as_ref()));
            }
            out.groups.retain(|g| g.files.len() > 1);
        }
        self.prune(&removed_paths(&report));
        Ok(report_dto(&report, false, journal_path))
    }

    /// 返回当前保存的重复文件结果（删除后用于刷新界面）。
    pub fn dup_current(&self) -> Result<DupSummary> {
        let guard = self.dup.lock().unwrap();
        guard
            .as_ref()
            .map(dup_summary)
            .ok_or(ApiError::new("no_scan"))
    }

    // ----- 应用卸载 -----

    /// 列出已装程序（传统程序 + Store 应用）。Store 应用的枚举失败不影响传统程序。
    pub fn apps_list(&self, include_store: bool) -> Result<Vec<AppDto>> {
        if let Some(mac) = &self.mac {
            let apps = diskclean_core::macapps::enumerate_mac_apps(&mac.app_roots);
            let dtos = apps
                .iter()
                .enumerate()
                .map(|(i, a)| app_dto(i, a))
                .collect();
            *self.apps.lock().unwrap() = apps;
            *self.leftovers.lock().unwrap() = None;
            return Ok(dtos);
        }
        if let Err(e) = self.registry.subkeys(Hive::LocalMachine, "SOFTWARE") {
            if e.kind() == std::io::ErrorKind::Unsupported {
                return Err(ApiError::new("unsupported_platform"));
            }
        }
        let mut apps = uninstall::enumerate_apps(self.registry.as_ref());
        if include_store {
            if let Ok(out) = self.runner.run("powershell.exe", uninstall::APPX_LIST_ARGS) {
                if out.code == 0 {
                    apps.extend(uninstall::parse_appx_json(&out.stdout));
                }
            }
        }
        let dtos = apps
            .iter()
            .enumerate()
            .map(|(i, a)| app_dto(i, a))
            .collect();
        *self.apps.lock().unwrap() = apps;
        *self.leftovers.lock().unwrap() = None;
        Ok(dtos)
    }

    fn app_by_id(&self, id: usize) -> Result<InstalledApp> {
        self.apps
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| ApiError::with("unknown_app", id))
    }

    /// 运行程序自带的卸载器并等待它结束。
    pub fn app_uninstall(&self, id: usize, silent: bool) -> Result<UninstallRunDto> {
        let app = self.app_by_id(id)?;
        if let (Some(mac), AppSource::MacBundle { path, .. }) = (&self.mac, &app.source) {
            diskclean_core::macapps::uninstall_mac_bundle(&app, &mac.app_roots, &*mac.trash)
                .map_err(|e| match e {
                    diskclean_core::macapps::MacUninstallError::Refused(m) => {
                        ApiError::with("invalid_command", m)
                    }
                    diskclean_core::macapps::MacUninstallError::Failed(m) => {
                        ApiError::with("uninstall_failed", m)
                    }
                })?;
            return Ok(UninstallRunDto {
                exit_code: 0,
                still_registered: std::fs::symlink_metadata(path).is_ok(),
            });
        }
        let run =
            uninstall::run_uninstaller(&app, silent, self.runner.as_ref(), self.registry.as_ref())
                .map_err(|e| match e {
                    UninstallError::NoUninstaller => ApiError::new("no_uninstaller"),
                    UninstallError::InvalidCommand => ApiError::new("invalid_command"),
                    UninstallError::Failed(m) => ApiError::with("uninstall_failed", m),
                })?;
        Ok(UninstallRunDto {
            exit_code: run.exit_code,
            still_registered: run.still_registered,
        })
    }

    /// 扫描程序卸载后残留的文件和注册表项。
    pub fn app_leftovers(
        &self,
        id: usize,
        forced: bool,
        exclusions: &[String],
    ) -> Result<LeftoversDto> {
        let app = self.app_by_id(id)?;
        let policy = (self.leftover_policy_factory)(exclusions)?;
        let scan = match &self.mac {
            Some(mac) => {
                diskclean_core::macapps::scan_mac_leftovers(&app, &mac.home, &policy, forced)
            }
            None => uninstall::scan_leftovers(
                &app,
                &self.fs_roots,
                &self.env,
                self.registry.as_ref(),
                &policy,
                forced,
            ),
        };
        let dto = leftovers_dto(&scan);
        *self.leftovers.lock().unwrap() = Some(LeftoverState {
            app_name: app.name.clone(),
            scan,
            policy,
        });
        Ok(dto)
    }

    /// 删除用户勾选的残留。前端只传序号；注册表先备份，备份失败则什么都不删。
    pub fn app_delete_leftovers(
        &self,
        selected: &[usize],
        recycle: bool,
        backup_dir: &Path,
        journal_path: &Path,
    ) -> Result<LeftoverReportDto> {
        if selected.is_empty() {
            return Err(ApiError::new("nothing_selected"));
        }
        let guard = self.leftovers.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut items: Vec<Leftover> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for &i in selected {
            let item = state
                .scan
                .items
                .get(i)
                .ok_or_else(|| ApiError::with("invalid_selection", i))?;
            if seen.insert(i) {
                items.push(item.clone());
            }
        }
        let mut journal = open_journal(journal_path)?;
        self.clean_cancel.store(false, Ordering::Relaxed);
        let ctx = DeleteCtx {
            reg: self.registry.as_ref(),
            env: &self.env,
            policy: &state.policy,
            backup_dir,
            app_name: &state.app_name,
            disposal: if recycle {
                Disposal::Recycle
            } else {
                Disposal::Permanent
            },
            cancel: &self.clean_cancel,
        };
        let out = uninstall::delete_leftovers(&items, &ctx, Some(&mut journal as &mut dyn Write))
            .map_err(|e| match e {
            DeleteError::BackupFailed(m) => ApiError::with("backup_failed", m),
        })?;
        drop(guard);
        *self.leftovers.lock().unwrap() = None;
        self.prune(&removed_paths(&out.files));
        Ok(LeftoverReportDto {
            registry: out
                .registry
                .iter()
                .map(|r| {
                    let (status, detail) = match &r.status {
                        RegStatus::Deleted => ("deleted", None),
                        RegStatus::Missing => ("missing", None),
                        RegStatus::Refused(d) => ("refused", Some(d.clone())),
                        RegStatus::Failed(d) => ("failed", Some(d.clone())),
                    };
                    RegResultDto {
                        path: format!("{}\\{}", r.hive.short_name(), r.path),
                        value_name: r.value.clone(),
                        status,
                        detail,
                    }
                })
                .collect(),
            files: report_dto(&out.files, false, journal_path),
            backup_file: out.backup_file.as_deref().map(display_path),
        })
    }

    // ----- 候选清单 -----

    /// 由扫描结果里的目录名序列得到：真实路径、是否目录、扫描时的大小和文件数。
    fn scan_entry(&self, parts: &[String]) -> Result<(PathBuf, bool, u64, u64)> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut node = &state.root;
        let mut path = state.root_path.clone();
        for part in parts {
            node = node
                .children
                .iter()
                .find(|c| &c.name == part)
                .ok_or_else(|| ApiError::with("invalid_path", part))?;
            path.push(part);
        }
        Ok((path, node.is_dir, node.size, node.file_count))
    }

    /// 把候选项（扫描树里的路径分量）解析成真实路径与当前状态，供"整体检查"展示。
    pub fn cand_resolve(&self, items: &[Vec<String>]) -> Result<Vec<CandResolved>> {
        items
            .iter()
            .map(|parts| {
                let (path, is_dir, size, files) = self.scan_entry(parts)?;
                let meta = fs::symlink_metadata(&path);
                Ok(CandResolved {
                    path: display_path(&path),
                    is_dir,
                    size,
                    files,
                    exists: meta.is_ok(),
                    is_link: meta
                        .as_ref()
                        .is_ok_and(|m| scanner::special_reason(m).is_some()),
                })
            })
            .collect()
    }

    /// 删除候选清单里的项目。前端只传扫描树里的路径分量；真实路径由后端取得。
    ///
    /// * 一项包含另一项时（目录与其子项）只处理外层，避免重复；
    /// * 链接、云占位文件、含受保护内容（如 `.git`）的目录会被拒绝并列入报告，不会删除；
    /// * 其余走统一的执行器（二次校验、先写日志）。
    pub fn cand_delete(
        &self,
        items: &[Vec<String>],
        recycle: bool,
        exclusions: &[String],
        journal_path: &Path,
        on_progress: &mut dyn FnMut(CleanProgressDto),
    ) -> Result<ReportDto> {
        if items.is_empty() {
            return Err(ApiError::new("nothing_selected"));
        }
        let mut entries: Vec<(PathBuf, bool, u64, u64)> = Vec::new();
        for parts in items {
            let e = self.scan_entry(parts)?;
            if parts.is_empty() {
                return Err(ApiError::with("invalid_path", "scan root"));
            }
            entries.push(e);
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries.dedup_by(|a, b| a.0 == b.0);
        // 外层已包含的子项不再单独处理。
        let paths: Vec<PathBuf> = entries.iter().map(|e| e.0.clone()).collect();
        entries.retain(|e| !paths.iter().any(|p| *p != e.0 && e.0.starts_with(p)));

        let disposal = if recycle {
            Disposal::Recycle
        } else {
            Disposal::Permanent
        };
        let mut candidates = Vec::new();
        let mut problems: Vec<Problem> = Vec::new();
        for (path, is_dir, size, files) in entries {
            let refuse = |detail: &str| Problem {
                rule_id: "candidates".into(),
                path: display_path(&path),
                status: "refused",
                detail: detail.into(),
            };
            match fs::symlink_metadata(&path) {
                Err(_) => problems.push(refuse("no longer exists")),
                Ok(m) if scanner::special_reason(&m).is_some() => {
                    problems.push(refuse("link or cloud placeholder"))
                }
                Ok(_) => {
                    if is_dir {
                        if let Ok(stats) = diskclean_core::plan::measure_path(&path) {
                            if let Some(b) = stats.blocker {
                                problems.push(refuse(&format!("{b:?}")));
                                continue;
                            }
                        }
                    }
                    candidates.push(Candidate {
                        rule_id: "candidates".into(),
                        path,
                        is_dir,
                        size,
                        file_count: files,
                        disposal,
                    });
                }
            }
        }

        let policy = (self.selected_policy_factory)(exclusions)?;
        let plan = Plan::from_items(candidates, policy);
        self.clean_cancel.store(false, Ordering::Relaxed);
        let mut journal = open_journal(journal_path)?;
        let report = execute_with(
            &plan,
            ExecOptions::default(),
            Some(&mut journal as &mut dyn Write),
            None,
            &self.clean_cancel,
            &mut |done, total| on_progress(CleanProgressDto { done, total }),
        );
        self.prune(&removed_paths(&report));
        let mut dto = report_dto(&report, false, journal_path);
        dto.refused += problems.len();
        problems.append(&mut dto.problems);
        problems.truncate(MAX_PROBLEMS);
        dto.problems = problems;
        Ok(dto)
    }

    // ----- 目录迁移 -----

    fn mig(&self) -> Result<&MigState> {
        self.mig
            .as_ref()
            .ok_or(ApiError::new("unsupported_platform"))
    }

    fn mig_deps<'a>(&'a self, m: &'a MigState) -> Deps<'a> {
        Deps {
            copier: m.parts.copier.as_ref(),
            mover: m.parts.mover.as_ref(),
            links: m.parts.links.as_ref(),
            volumes: m.parts.volumes.as_ref(),
            store: &m.store,
        }
    }

    /// 迁移前检查。只读。
    pub fn mig_preflight(
        &self,
        source: &str,
        target: &str,
        exclusions: &[String],
    ) -> Result<PreflightDto> {
        let m = self.mig()?;
        let policy = (m.parts.policy_factory)(exclusions)?;
        let opts = PreflightOptions {
            program_dirs: m.parts.program_dirs.clone(),
            unix_links: m.parts.unix_links,
            // 云同步目录不能迁移（搬走会破坏同步），与"是否分析云端"的设置无关。
            cloud: CloudRules::new(false, &[], &self.env),
        };
        let p = migrate::preflight(
            Path::new(source),
            Path::new(target),
            m.parts.volumes.as_ref(),
            &policy,
            &m.store.list(),
            &opts,
        );
        Ok(preflight_dto(&p))
    }

    /// 找出占用该目录的进程，并保存结果供随后的"停止"使用。
    pub fn mig_blockers(&self, dir: &str) -> Result<BlockersDto> {
        let m = self.mig()?;
        let path = PathBuf::from(dir);
        if !path.is_dir() {
            return Err(ApiError::with("invalid_path", dir));
        }
        let (files, truncated) = procs::collect_files(&path);
        let report = procs::find_blockers(
            &path,
            m.parts.procs.as_ref(),
            m.parts.rm.as_ref(),
            &files,
            truncated,
            m.parts.self_pid,
            &m.parts.system_dirs,
        );
        let dto = blockers_dto(&report);
        *m.blockers.lock().unwrap() = Some((path, report));
        Ok(dto)
    }

    /// 停止用户勾选的占用进程。只接受上一次 `mig_blockers` 列出的进程；受保护的一律拒绝。
    pub fn mig_stop(
        &self,
        pids: &[u32],
        include_related: bool,
        force: bool,
    ) -> Result<Vec<StopResultDto>> {
        let m = self.mig()?;
        let guard = m.blockers.lock().unwrap();
        let (_, report) = guard.as_ref().ok_or(ApiError::new("no_blockers"))?;
        let plan = procs::plan_stop(
            report,
            pids,
            include_related,
            m.parts.procs.as_ref(),
            m.parts.self_pid,
        );
        let results = procs::execute_stop(
            &plan,
            force,
            m.parts.procs.as_ref(),
            self.runner.as_ref(),
            m.parts.stop_timing,
        );
        Ok(results
            .into_iter()
            .map(|r| {
                let (status, detail) = match r.status {
                    StopStatus::Exited => ("exited", None),
                    StopStatus::Forced => ("forced", None),
                    StopStatus::ServiceStopped => ("service_stopped", None),
                    StopStatus::AlreadyGone => ("already_gone", None),
                    StopStatus::StillRunning => ("still_running", None),
                    StopStatus::Refused(d) => ("refused", Some(d)),
                    StopStatus::Failed(d) => ("failed", Some(d)),
                };
                StopResultDto {
                    pid: r.pid,
                    name: r.name,
                    status,
                    detail,
                }
            })
            .collect())
    }

    pub fn mig_cancel(&self) {
        if let Some(m) = &self.mig {
            m.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn mig_list(&self) -> Result<Vec<MigrationDto>> {
        let m = self.mig()?;
        let mut v: Vec<MigrationDto> = m.store.list().iter().map(migration_dto).collect();
        v.sort_by_key(|r| std::cmp::Reverse(r.created));
        Ok(v)
    }

    /// 启动时修复上次中断留下的中间状态记录。返回需要人工查看的记录数。
    pub fn mig_recover(&self) -> usize {
        let Some(m) = &self.mig else { return 0 };
        let deps = self.mig_deps(m);
        m.store
            .list()
            .iter()
            .filter(|r| matches!(migrate::recover(r, &deps), Recovery::NeedsAttention(_)))
            .count()
    }

    pub fn mig_start(
        &self,
        source: &str,
        target: &str,
        exclusions: &[String],
        journal_path: &Path,
        on_progress: &mut dyn FnMut(MigProgressDto),
    ) -> Result<MigrationDto> {
        let m = self.mig()?;
        let policy = (m.parts.policy_factory)(exclusions)?;
        m.cancel.store(false, Ordering::Relaxed);
        let opts = PreflightOptions {
            program_dirs: m.parts.program_dirs.clone(),
            unix_links: m.parts.unix_links,
            // 云同步目录不能迁移（搬走会破坏同步），与"是否分析云端"的设置无关。
            cloud: CloudRules::new(false, &[], &self.env),
        };
        let mut journal = open_journal(journal_path)?;
        let result = migrate::migrate(
            Path::new(source),
            Path::new(target),
            &self.mig_deps(m),
            &policy,
            &opts,
            &m.cancel,
            &mut |p| {
                on_progress(MigProgressDto {
                    stage: stage_name(p.stage),
                    done: p.done,
                    total: p.total,
                })
            },
        );
        match result {
            Ok(rec) => {
                migrate::journal_line(&mut journal, &rec, "done");
                // 原路径现在是指向别处的链接，扫描不会统计它：从树里去掉。
                self.prune(&[PathBuf::from(&rec.source)]);
                Ok(migration_dto(&rec))
            }
            Err(e) => Err(migrate_error(e)),
        }
    }

    pub fn mig_restore(
        &self,
        id: &str,
        journal_path: &Path,
        on_progress: &mut dyn FnMut(MigProgressDto),
    ) -> Result<MigrationDto> {
        let m = self.mig()?;
        let rec = m
            .store
            .get(id)
            .ok_or_else(|| ApiError::with("unknown_migration", id))?;
        m.cancel.store(false, Ordering::Relaxed);
        let mut journal = open_journal(journal_path)?;
        let out = migrate::restore(&rec, &self.mig_deps(m), &m.cancel, &mut |p| {
            on_progress(MigProgressDto {
                stage: stage_name(p.stage),
                done: p.done,
                total: p.total,
            })
        })
        .map_err(migrate_error)?;
        migrate::journal_line(&mut journal, &out, "restored");
        self.graft(Path::new(&out.source));
        Ok(migration_dto(&out))
    }

    // ----- 系统动作 -----

    pub fn sys_list(&self) -> Vec<SysActionDto> {
        sysaction::platform_actions()
            .iter()
            .map(|a| SysActionDto {
                id: a.id,
                risk: a.risk,
                estimate: a.estimate(&self.env),
            })
            .collect()
    }

    /// 系统动作成功后，把它改变的位置同步到扫描树里。
    fn after_system_action(&self, id: &str) {
        let Some(drive) = self.env.get("SystemDrive") else {
            return;
        };
        let root = PathBuf::from(format!("{drive}/"));
        match id {
            "windows_old" => self.prune(&[root.join("Windows.old")]),
            "hibernation" => self.prune(&[root.join("hiberfil.sys")]),
            "recycle_bin" => self.graft(&root.join("$Recycle.Bin")),
            _ => {}
        }
    }

    pub fn sys_run(&self, id: &str, journal_path: &Path) -> Result<SysResultDto> {
        let action =
            sysaction::find_action(id).ok_or_else(|| ApiError::with("unknown_action", id))?;
        let mut journal = open_journal(journal_path)?;
        let before = free_space(&self.env);
        let result = action.run(&self.env, self.runner.as_ref());
        let after = free_space(&self.env);
        let _ = writeln!(
            journal,
            "{}",
            serde_json::json!({
                "op": "system",
                "ts": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                "action": action.id,
                "ok": result.is_ok(),
                "detail": match &result { Ok(o) => o.clone(), Err(e) => format!("{}: {}", e.code, e.detail) },
            })
        );
        if result.is_ok() {
            self.after_system_action(action.id);
        }
        match result {
            Ok(output) => Ok(SysResultDto {
                id: action.id,
                free_before: before,
                free_after: after,
                output,
            }),
            Err(e) => Err(ApiError::with(
                "sys_failed",
                format!("{}: {}", e.code, e.detail),
            )),
        }
    }
}

fn stage_name(s: Stage) -> &'static str {
    match s {
        Stage::Copying => "copying",
        Stage::Verifying => "verifying",
        Stage::Switching => "switching",
        Stage::Cleaning => "cleaning",
    }
}

fn preflight_dto(p: &Preflight) -> PreflightDto {
    PreflightDto {
        size: p.size,
        files: p.files,
        can_proceed: p.can_proceed(),
        issues: p
            .issues
            .iter()
            .map(|i| IssueDto {
                severity: if i.severity == Severity::Error {
                    "error"
                } else {
                    "warning"
                },
                code: i.code,
                detail: i.detail.clone(),
            })
            .collect(),
        source_volume: p.source_volume.clone(),
        target_volume: p.target_volume.clone(),
        target_free: p.target_free,
    }
}

fn blockers_dto(r: &BlockerReport) -> BlockersDto {
    let blocker = |b: &Blocker| BlockerDto {
        pid: b.pid,
        name: b.name.clone(),
        exe: b.exe.clone(),
        kinds: b
            .kinds
            .iter()
            .map(|k| match k {
                BlockerKind::Image => "image",
                BlockerKind::CurrentDir => "current_dir",
                BlockerKind::OpenFile => "open_file",
                BlockerKind::Service => "service",
            })
            .collect(),
        service: b.service.clone(),
        protection: b.protection.map(|p| match p {
            Protection::ThisApp => "this_app",
            Protection::Critical => "critical",
            Protection::Explorer => "explorer",
            Protection::ServiceHost => "service_host",
        }),
        related: b
            .related
            .iter()
            .map(|x| RelatedDto {
                pid: x.pid,
                name: x.name.clone(),
                reason: match x.reason {
                    RelatedReason::Descendant => "descendant",
                    RelatedReason::SameFolder => "same_folder",
                },
            })
            .collect(),
    };
    BlockersDto {
        blockers: r.blockers.iter().map(blocker).collect(),
        rm_error: r.rm_error.clone(),
        files_checked: r.files_checked,
        truncated: r.truncated,
    }
}

fn migration_dto(r: &MigrationRecord) -> MigrationDto {
    use migrate::Status as S;
    MigrationDto {
        id: r.id.clone(),
        source: display_path(Path::new(&r.source)),
        target: display_path(Path::new(&r.target)),
        size: r.size,
        files: r.files,
        created: r.created,
        status: match r.status {
            S::Copying => "copying",
            S::Switching => "switching",
            S::Done => "done",
            S::Restoring => "restoring",
            S::Failed => "failed",
            S::Restored => "restored",
        },
        note: r.note.clone(),
        old_path: r.old_path.as_deref().map(|p| display_path(Path::new(p))),
    }
}

fn migrate_error(e: MigrateError) -> ApiError {
    match e {
        MigrateError::Preflight(issues) => ApiError::with(
            "mig_preflight",
            issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .map(|i| i.code)
                .collect::<Vec<_>>()
                .join(","),
        ),
        MigrateError::Cancelled => ApiError::new("cancelled"),
        MigrateError::CopyFailed(m) => ApiError::with("mig_copy_failed", m),
        MigrateError::VerifyFailed(m) => ApiError::with("mig_verify_failed", m),
        MigrateError::InUse(m) => ApiError::with("mig_in_use", m),
        MigrateError::LinkFailed(m) => ApiError::with("mig_link_failed", m),
        MigrateError::Manifest(m) => ApiError::with("mig_manifest", m),
        MigrateError::NotRestorable(m) => ApiError::with("mig_not_restorable", m),
    }
}

fn format_install_date(raw: &Option<String>) -> Option<String> {
    let r = raw.as_deref()?;
    (r.len() == 8 && r.bytes().all(|b| b.is_ascii_digit()))
        .then(|| format!("{}-{}-{}", &r[..4], &r[4..6], &r[6..8]))
}

fn app_dto(id: usize, a: &InstalledApp) -> AppDto {
    let store = matches!(a.source, AppSource::Appx { .. });
    let bundle = matches!(a.source, AppSource::MacBundle { .. });
    let command = (!store && !bundle)
        .then(|| uninstall::uninstall_command(a, false).ok())
        .flatten();
    AppDto {
        id,
        name: a.name.clone(),
        version: a.version.clone(),
        publisher: a.publisher.clone(),
        install_date: format_install_date(&a.install_date),
        size_kb: a.size_kb,
        install_location: a.install_location.clone(),
        kind: if store {
            "store"
        } else if bundle {
            "bundle"
        } else {
            "desktop"
        },
        can_uninstall: store || bundle || command.is_some(),
        uninstall_command: command,
    }
}

fn leftovers_dto(scan: &LeftoverScan) -> LeftoversDto {
    let reason = |r: Reason| match r {
        Reason::InstallLocation => "install_location",
        Reason::NameMatch => "name_match",
        Reason::PublisherEmptied => "publisher_emptied",
        Reason::UninstallEntry => "uninstall_entry",
        Reason::AppPath => "app_path",
        Reason::AutoRun => "auto_run",
        Reason::StaleService => "stale_service",
        Reason::ComRegistration => "com_registration",
        Reason::Shortcut => "shortcut",
        Reason::BundleId => "bundle_id",
    };
    let items: Vec<LeftoverDto> = scan
        .items
        .iter()
        .enumerate()
        .map(|(id, l)| {
            let (kind, path, value_name, size, files) = match &l.target {
                Target::Path {
                    path,
                    is_dir,
                    size,
                    files,
                } => (
                    if *is_dir { "folder" } else { "file" },
                    display_path(path),
                    None,
                    *size,
                    *files,
                ),
                Target::Key { hive, path, .. } => (
                    "reg_key",
                    format!("{}\\{path}", hive.short_name()),
                    None,
                    0,
                    0,
                ),
                Target::Value {
                    hive, path, name, ..
                } => (
                    "reg_value",
                    format!("{}\\{path}", hive.short_name()),
                    Some(name.clone()),
                    0,
                    0,
                ),
            };
            LeftoverDto {
                id,
                kind,
                path,
                value_name,
                confidence: if l.confidence == Confidence::High {
                    "high"
                } else {
                    "medium"
                },
                reason: reason(l.reason),
                size,
                files,
                default_selected: l.confidence == Confidence::High,
            }
        })
        .collect();
    LeftoversDto {
        total_size: items.iter().map(|i| i.size).sum(),
        items,
        still_registered: scan.still_registered,
        install_dir: scan.install_dir.as_deref().map(display_path),
    }
}

/// 规则是否允许分析云端（设置里打开了“分析云端”）。
fn rules_allow_cloud(rules: &CloudRules) -> bool {
    // 探针：云同步目录名在「不分析云端」时一定被排除，打开后则不会。
    rules
        .excluded_dir(Path::new("__probe__/Google Drive"))
        .is_none()
}

/// 由内存里的扫描树生成摘要（总量、最大文件）。
fn summarize(state: &ScanState, cancelled: bool) -> ScanSummary {
    let top_files = scanner::top_files(&state.root_path, &state.root, TOP_FILES)
        .into_iter()
        .map(|(p, size)| FileDto {
            path: display_path(&p),
            size,
        })
        .collect();
    ScanSummary {
        method: state.method,
        fallback: state.fallback,
        root: display_path(&state.root_path),
        total_size: state.root.size,
        file_count: state.root.file_count,
        skipped: state.skipped,
        excluded: excluded_dtos(&state.excluded),
        cancelled,
        elapsed_ms: state.elapsed_ms,
        min_size: state.min_size,
        top_files,
    }
}

fn excluded_dtos(v: &[scanner::Excluded]) -> Vec<ExcludedDto> {
    let mut out: Vec<ExcludedDto> = v
        .iter()
        .map(|e| ExcludedDto {
            path: display_path(&e.path),
            reason: e.reason.clone(),
            size: e.size,
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// 报告里真正被删除（或移入回收站）的路径。
fn removed_paths(report: &Report) -> Vec<PathBuf> {
    report
        .entries
        .iter()
        .filter(|e| matches!(e.status, Status::Deleted | Status::Recycled))
        .map(|e| PathBuf::from(&e.path))
        .collect()
}

fn open_journal(path: &Path) -> Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| ApiError::with("journal_failed", e))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| ApiError::with("journal_failed", e))
}

fn report_dto(report: &Report, dry_run: bool, journal_path: &Path) -> ReportDto {
    let mut problems = Vec::new();
    for e in &report.entries {
        let (status, detail) = match &e.status {
            Status::Failed(d) => ("failed", d.clone()),
            Status::Refused(d) => ("refused", d.clone()),
            _ => continue,
        };
        if problems.len() < MAX_PROBLEMS {
            problems.push(Problem {
                rule_id: e.rule_id.clone(),
                path: display_path(Path::new(&e.path)),
                status,
                detail,
            });
        }
    }
    ReportDto {
        dry_run,
        freed_bytes: report.freed_bytes,
        recycled_bytes: report.recycled_bytes,
        deleted: report.count(|s| matches!(s, Status::Deleted)),
        recycled: report.count(|s| matches!(s, Status::Recycled)),
        would_delete: report.count(|s| matches!(s, Status::WouldDelete)),
        failed: report.failed(),
        refused: report.refused(),
        cancelled: report.cancelled,
        problems,
        service_errors: report.service_errors.clone(),
        journal_path: display_path(journal_path),
    }
}

/// 系统盘的可用空间。`SystemDrive` 形如 `C:`；匹配不到时返回 `None`。
/// macOS 的 APFS 会挂载一堆内部卷（Preboot、VM、Update……），不是用户要分析的磁盘。
fn is_hidden_mount(mount: &Path) -> bool {
    let m = mount.to_string_lossy();
    m.starts_with("/System/Volumes/") && m != "/System/Volumes/Data"
        || m.starts_with("/private/var/vm")
        || m.starts_with("/System/Volumes/Data/")
}

fn free_space(env: &Env) -> Option<u64> {
    let Some(drive) = env.get("SystemDrive").map(str::to_lowercase) else {
        // 没有"系统盘符"的平台（macOS）：用启动卷 `/`。
        return sysinfo::Disks::new_with_refreshed_list()
            .list()
            .iter()
            .find(|d| d.mount_point() == Path::new("/"))
            .map(|d| d.available_space());
    };
    sysinfo::Disks::new_with_refreshed_list()
        .list()
        .iter()
        .find(|d| {
            d.mount_point()
                .to_string_lossy()
                .to_lowercase()
                .starts_with(&drive)
        })
        .map(|d| d.available_space())
}

const MAX_DUP_GROUPS: usize = 500;

fn dup_summary(out: &DupOutcome) -> DupSummary {
    let groups = out
        .groups
        .iter()
        .enumerate()
        .take(MAX_DUP_GROUPS)
        .map(|(id, g)| DupGroupDto {
            id,
            size: g.size,
            wasted: g.wasted(),
            keep: g.suggested_keep(),
            files: g
                .files
                .iter()
                .map(|f| DupFileDto {
                    path: display_path(&f.path),
                    modified: f.modified,
                })
                .collect(),
        })
        .collect();
    DupSummary {
        groups,
        hidden_groups: out.groups.len().saturating_sub(MAX_DUP_GROUPS),
        total_wasted: out.groups.iter().map(DupGroup::wasted).sum(),
        scanned_files: out.scanned_files,
        errors: out.errors,
        excluded: excluded_dtos(&out.excluded),
        cancelled: out.cancelled,
    }
}

fn mtime_secs(m: &fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

/// 校验用户的选择并生成待删除清单。任何一项不合格都整体拒绝。
fn validate_selection(
    out: &DupOutcome,
    sel: &[DupSelection],
    recycle: bool,
) -> Result<Vec<Candidate>> {
    if sel.is_empty() {
        return Err(ApiError::new("nothing_selected"));
    }
    let mut chosen: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>> =
        Default::default();
    for s in sel {
        let g = out
            .groups
            .get(s.group)
            .ok_or_else(|| ApiError::with("invalid_selection", format!("group {}", s.group)))?;
        if s.file >= g.files.len() {
            return Err(ApiError::with(
                "invalid_selection",
                format!("file {}", s.file),
            ));
        }
        if let Some(p) = &s.path {
            if display_path(&g.files[s.file].path) != *p {
                return Err(ApiError::with("invalid_selection", format!("stale: {p}")));
            }
        }
        chosen.entry(s.group).or_default().insert(s.file);
    }

    let unchanged = |g: &DupGroup, i: usize| -> bool {
        let f = &g.files[i];
        fs::symlink_metadata(&f.path)
            .map(|m| m.is_file() && m.len() == g.size && mtime_secs(&m) == f.modified)
            .unwrap_or(false)
    };

    let disposal = if recycle {
        Disposal::Recycle
    } else {
        Disposal::Permanent
    };
    let mut items = Vec::new();
    for (gi, files) in &chosen {
        let g = &out.groups[*gi];
        // 至少保留一份，并且保留的那份必须仍然存在、没有变化——否则"重复"这个前提已经不成立。
        let keeper = (0..g.files.len()).find(|i| !files.contains(i) && unchanged(g, *i));
        if keeper.is_none() {
            let code = if files.len() >= g.files.len() {
                "must_keep_one"
            } else {
                "keeper_changed"
            };
            return Err(ApiError::with(code, display_path(&g.files[0].path)));
        }
        for &fi in files {
            if !unchanged(g, fi) {
                return Err(ApiError::with(
                    "changed_since_scan",
                    display_path(&g.files[fi].path),
                ));
            }
            items.push(Candidate {
                rule_id: "duplicates".into(),
                path: g.files[fi].path.clone(),
                is_dir: false,
                size: g.size,
                file_count: 1,
                disposal,
            });
        }
    }
    Ok(items)
}

fn skip_counts(plan: &Plan) -> Vec<SkipCount> {
    let mut counts: Vec<SkipCount> = Vec::new();
    for s in &plan.skipped {
        let reason = match s.reason {
            PlanSkipReason::Denied(_) => "denied",
            PlanSkipReason::ReparsePoint => "reparse_point",
            PlanSkipReason::CloudPlaceholder => "cloud_placeholder",
            PlanSkipReason::TooNew => "too_new",
            PlanSkipReason::ProtectedInside(_) => "protected_inside",
            PlanSkipReason::NonUtf8Path => "non_utf8",
            PlanSkipReason::Io(_) => "io",
        };
        match counts.iter_mut().find(|c| c.reason == reason) {
            Some(c) => c.count += 1,
            None => counts.push(SkipCount { reason, count: 1 }),
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskclean_core::rules::{Target, TargetKind};
    use diskclean_core::safety::native_style as test_style;
    use std::sync::atomic::AtomicU64;

    static N: AtomicU64 = AtomicU64::new(0);

    fn sandbox() -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("dc-svc-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        diskclean_core::safety::canonical_plain(&d).unwrap()
    }

    fn service(base: &Path) -> Service {
        service_fast(base, None)
    }

    fn service_fast(base: &Path, fast: Option<Box<FastScanFn>>) -> Service {
        let rule = Rule {
            id: "r".into(),
            risk: Risk::Low,
            default_selected: true,
            disposal: Disposal::Permanent,
            services: vec![],
            targets: vec![Target {
                path: "%BASE%/cache".into(),
                kind: TargetKind::Contents,
                name_globs: vec![],
                min_age_days: 0,
            }],
        };
        let base_s = base.to_string_lossy().into_owned();
        let factory: Box<PolicyFactory> = Box::new(move |excl: &[String]| {
            let mut p = SafetyPolicy::empty(test_style());
            p.protect(&base_s)
                .map_err(|e| ApiError::with("policy", e))?;
            for x in excl {
                p.exclude(x)
                    .map_err(|e| ApiError::with("invalid_exclusion", format!("{x}: {e}")))?;
            }
            Ok(p)
        });
        Service::new(
            vec![rule],
            Env::from_pairs([("BASE", base.to_string_lossy())]),
            factory,
            fast,
        )
    }

    fn write(p: &Path, n: usize) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, vec![0u8; n]).unwrap();
    }

    #[test]
    fn scan_then_browse_children() {
        let d = sandbox();
        write(&d.join("a/big.bin"), 500);
        write(&d.join("a/small.bin"), 5);
        write(&d.join("b.bin"), 50);
        let svc = service(&d);
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.total_size, 555);
        assert_eq!(s.top_files[0].size, 500);

        let root = svc.children(&[]).unwrap();
        assert_eq!(root.items[0].name, "a");
        assert!(root.items[0].is_dir);
        let a = svc.children(&["a".into()]).unwrap();
        assert_eq!(a.items.len(), 2);
        assert_eq!(
            svc.children(&["nope".into()]).unwrap_err().code,
            "invalid_path"
        );
        assert_eq!(
            svc.resolve_in_scan(&["a".into(), "big.bin".into()])
                .unwrap(),
            d.join("a/big.bin")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    fn fake_tree() -> ScanOutcome {
        let file = |n: &str, size| Node {
            name: n.into(),
            is_dir: false,
            size,
            file_count: 1,
            children: vec![],
        };
        ScanOutcome {
            root: Node {
                name: "root".into(),
                is_dir: true,
                size: 30,
                file_count: 2,
                children: vec![file("x.bin", 20), file("y.bin", 10)],
            },
            skipped: vec![],
            excluded: vec![],
            cancelled: false,
        }
    }

    #[test]
    fn fast_scan_is_preferred_and_serves_children() {
        let d = sandbox();
        write(&d.join("walk-only.bin"), 999);
        let svc = service_fast(&d, Some(Box::new(|_, _, _| Ok(fake_tree()))));
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.method, "mft");
        assert_eq!(s.fallback, None);
        assert_eq!(s.total_size, 30);
        let kids = svc.children(&[]).unwrap();
        assert_eq!(kids.items[0].name, "x.bin");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_fast_scan_falls_back_to_walking() {
        let d = sandbox();
        write(&d.join("a.bin"), 500);
        let svc = service_fast(
            &d,
            Some(Box::new(|_, _, _| Err(("access_denied", "denied".into())))),
        );
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.method, "walk");
        assert_eq!(s.fallback, Some("access_denied"));
        assert_eq!(s.total_size, 500);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn no_fast_scanner_means_plain_walk_without_fallback_note() {
        let d = sandbox();
        write(&d.join("a.bin"), 1);
        let s = service(&d).scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!((s.method, s.fallback), ("walk", None));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn children_before_scan_is_an_error() {
        let d = sandbox();
        assert_eq!(service(&d).children(&[]).unwrap_err().code, "no_scan");
        assert_eq!(
            service(&d)
                .scan("/definitely/missing", &mut |_| {})
                .unwrap_err()
                .code,
            "invalid_path"
        );
    }

    #[test]
    fn plan_then_execute_and_plan_is_single_use() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        write(&d.join("cache/sub/b.bin"), 20);
        let svc = service(&d);

        let plan = svc.build_plan(&["r".into()], &[]).unwrap();
        assert_eq!(plan.total_size, 120);
        assert_eq!(plan.item_count, 2);
        assert_eq!(plan.items[0].size, 100, "largest first");

        let journal = d.join("logs/journal.jsonl");
        let mut ticks = 0;
        let rep = svc
            .execute(
                ExecRequest {
                    dry_run: false,
                    recycle: false,
                },
                &journal,
                &mut |_| ticks += 1,
            )
            .unwrap();
        assert_eq!(rep.freed_bytes, 120);
        assert_eq!(rep.deleted, 2);
        assert_eq!(ticks, 2);
        assert!(fs::read_to_string(&journal).unwrap().contains("\"intent\""));
        assert_eq!(fs::read_dir(d.join("cache")).unwrap().count(), 0);

        let again = svc.execute(
            ExecRequest {
                dry_run: false,
                recycle: false,
            },
            &journal,
            &mut |_| {},
        );
        assert_eq!(again.unwrap_err().code, "no_plan");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dry_run_reports_without_deleting() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        let svc = service(&d);
        svc.build_plan(&["r".into()], &[]).unwrap();
        let rep = svc
            .execute(
                ExecRequest {
                    dry_run: true,
                    recycle: false,
                },
                &d.join("j.jsonl"),
                &mut |_| {},
            )
            .unwrap();
        assert!(rep.dry_run);
        assert_eq!(rep.would_delete, 1);
        assert_eq!(rep.freed_bytes, 0);
        assert!(d.join("cache/a.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn unknown_rule_and_bad_exclusion_are_rejected() {
        let d = sandbox();
        let svc = service(&d);
        assert_eq!(
            svc.build_plan(&["nope".into()], &[]).unwrap_err().code,
            "unknown_rule"
        );
        assert_eq!(
            svc.build_plan(&["r".into()], &["relative/path".into()])
                .unwrap_err()
                .code,
            "invalid_exclusion"
        );
        assert_eq!(
            svc.validate_exclusion("  ").unwrap_err().code,
            "invalid_exclusion"
        );
        assert!(svc.validate_exclusion(d.to_str().unwrap()).is_ok());
    }

    #[test]
    fn exclusions_apply_to_plan() {
        let d = sandbox();
        write(&d.join("cache/keep/x"), 1);
        write(&d.join("cache/drop/y"), 1);
        let svc = service(&d);
        let plan = svc
            .build_plan(
                &["r".into()],
                &[d.join("cache/keep").to_string_lossy().into_owned()],
            )
            .unwrap();
        assert_eq!(plan.item_count, 1);
        assert!(plan.items[0].path.ends_with("drop"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn display_path_strips_extended_prefix() {
        assert_eq!(display_path(Path::new(r"\\?\C:\Users\a")), r"C:\Users\a");
        assert_eq!(display_path(Path::new("/tmp/x")), "/tmp/x");
    }

    // ---------- 重复文件 / 系统动作 / 服务停启 ----------

    use diskclean_core::sysaction::CmdOutput;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeRunner {
        calls: Mutex<Vec<String>>,
        script: Mutex<VecDeque<CmdOutput>>,
    }

    impl FakeRunner {
        fn scripted(v: Vec<CmdOutput>) -> Arc<Self> {
            Arc::new(FakeRunner {
                calls: Mutex::default(),
                script: Mutex::new(v.into()),
            })
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CmdOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok(self.script.lock().unwrap().pop_front().unwrap_or_default())
        }
    }

    fn posix_factory(base: &Path, protect_sub: Option<&str>) -> Box<PolicyFactory> {
        let base_s = base.to_string_lossy().into_owned();
        let sub = protect_sub.map(|s| base.join(s).to_string_lossy().into_owned());
        Box::new(move |excl: &[String]| {
            let mut p = SafetyPolicy::empty(test_style());
            if let Some(sub) = &sub {
                p.protect(sub).map_err(|e| ApiError::with("policy", e))?;
            } else {
                let _ = &base_s;
            }
            for x in excl {
                p.exclude(x)
                    .map_err(|e| ApiError::with("invalid_exclusion", e))?;
            }
            Ok(p)
        })
    }

    /// 用户选中文件策略：只保护 `locked` 子目录。
    fn dup_service(base: &Path, runner: Arc<FakeRunner>) -> Service {
        service(base).with_system(runner, posix_factory(base, Some("locked")))
    }

    fn selection(group: usize, file: usize) -> DupSelection {
        DupSelection {
            group,
            file,
            path: None,
        }
    }

    fn make_dups(d: &Path) {
        write(&d.join("a/one.bin"), 3000);
        write(&d.join("b/two.bin"), 3000);
        write(&d.join("c/three.bin"), 3000);
        write(&d.join("c/unique.bin"), 3001);
    }

    fn dup_names(sum: &DupSummary, g: usize) -> Vec<String> {
        sum.groups[g]
            .files
            .iter()
            .map(|f| {
                Path::new(&f.path)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    #[test]
    fn dup_scan_delete_and_refresh() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        assert_eq!(sum.groups.len(), 1);
        assert_eq!(sum.total_wasted, 6000);
        assert_eq!(dup_names(&sum, 0), ["one.bin", "two.bin", "three.bin"]);
        let keep = sum.groups[0].keep;

        // 删除除推荐保留项之外的所有文件。
        let sel: Vec<_> = (0..3)
            .filter(|i| *i != keep)
            .map(|i| selection(0, i))
            .collect();
        let journal = d.join("j.jsonl");
        let rep = svc
            .dup_delete(&sel, false, &[], &journal, &mut |_| {})
            .unwrap();
        assert_eq!((rep.deleted, rep.failed, rep.refused), (2, 0, 0));
        assert_eq!(rep.freed_bytes, 6000);
        let remaining = [
            d.join("a/one.bin"),
            d.join("b/two.bin"),
            d.join("c/three.bin"),
        ]
        .iter()
        .filter(|p| p.exists())
        .count();
        assert_eq!(remaining, 1);
        assert!(d.join("c/unique.bin").exists());
        assert!(fs::read_to_string(&journal)
            .unwrap()
            .contains("\"duplicates\""));

        // 刷新后这一组已不存在。
        assert!(svc.dup_current().unwrap().groups.is_empty());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn selecting_every_copy_is_rejected_and_nothing_is_deleted() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let all: Vec<_> = (0..3).map(|i| selection(0, i)).collect();
        let err = svc
            .dup_delete(&all, false, &[], &d.join("j"), &mut |_| {})
            .unwrap_err();
        assert_eq!(err.code, "must_keep_one");
        assert!(
            d.join("a/one.bin").exists()
                && d.join("b/two.bin").exists()
                && d.join("c/three.bin").exists()
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_file_changed_after_scanning_blocks_the_whole_deletion() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let names = dup_names(&sum, 0);
        let idx = |n: &str| names.iter().position(|x| x == n).unwrap();

        // 选中 one 和 two，保留 three；扫描后 two 被改动。
        write(&d.join("b/two.bin"), 4096);
        let sel = [selection(0, idx("one.bin")), selection(0, idx("two.bin"))];
        let err = svc
            .dup_delete(&sel, false, &[], &d.join("j"), &mut |_| {})
            .unwrap_err();
        assert_eq!(err.code, "changed_since_scan");
        assert!(
            d.join("a/one.bin").exists(),
            "未改动的 one 也不能被删：整体拒绝"
        );

        // 被保留的那份被改动：同样拒绝。
        write(&d.join("c/three.bin"), 100);
        let err = svc
            .dup_delete(
                &[selection(0, idx("one.bin"))],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(err.code, "keeper_changed");
        assert!(d.join("a/one.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn invalid_or_empty_selections_are_rejected() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        assert_eq!(
            svc.dup_delete(&[selection(0, 0)], false, &[], &d.join("j"), &mut |_| {})
                .unwrap_err()
                .code,
            "no_scan"
        );
        svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        for bad in [selection(5, 0), selection(0, 9)] {
            assert_eq!(
                svc.dup_delete(&[bad], false, &[], &d.join("j"), &mut |_| {})
                    .unwrap_err()
                    .code,
                "invalid_selection"
            );
        }
        assert_eq!(
            svc.dup_delete(&[], false, &[], &d.join("j"), &mut |_| {})
                .unwrap_err()
                .code,
            "nothing_selected"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn protected_locations_are_refused_by_the_selected_file_policy() {
        let d = sandbox();
        write(&d.join("locked/secret.bin"), 3000);
        write(&d.join("open/copy.bin"), 3000);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let names = dup_names(&sum, 0);
        let locked = names.iter().position(|n| n == "secret.bin").unwrap();
        // 保留 copy.bin，请求删除受保护目录里的 secret.bin。
        let rep = svc
            .dup_delete(
                &[selection(0, locked)],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!((rep.deleted, rep.refused), (0, 1));
        assert!(d.join("locked/secret.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn user_exclusions_protect_duplicates_too() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let names = dup_names(&sum, 0);
        let i = names.iter().position(|n| n == "one.bin").unwrap();
        let excl = [d.join("a").to_string_lossy().into_owned()];
        let rep = svc
            .dup_delete(&[selection(0, i)], false, &excl, &d.join("j"), &mut |_| {})
            .unwrap();
        assert_eq!(rep.refused, 1);
        assert!(d.join("a/one.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dup_scan_rejects_bad_paths() {
        let d = sandbox();
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        assert_eq!(
            svc.dup_scan("/no/such/dir", 1, &mut |_| {})
                .unwrap_err()
                .code,
            "invalid_path"
        );
        assert_eq!(svc.dup_current().unwrap_err().code, "no_scan");
    }

    #[test]
    fn system_action_runs_the_tool_logs_it_and_reports_failures() {
        let d = sandbox();
        let env_dir = d.to_string_lossy().into_owned();
        let runner = FakeRunner::scripted(vec![
            CmdOutput::default(),
            CmdOutput {
                code: 5,
                stdout: String::new(),
                stderr: "Access is denied.".into(),
            },
        ]);
        let base = service(&d).with_system(runner.clone(), posix_factory(&d, None));
        let svc = Service::new(
            base.rules.clone(),
            Env::from_pairs([("SystemDrive", env_dir.as_str())]),
            posix_factory(&d, None),
            None,
        )
        .with_system(runner.clone(), posix_factory(&d, None));

        let journal = d.join("sys.jsonl");
        let ok = svc.sys_run("hibernation", &journal).unwrap();
        assert_eq!(ok.id, "hibernation");
        let err = svc.sys_run("component_store", &journal).unwrap_err();
        assert_eq!(err.code, "sys_failed");
        assert!(err.detail.unwrap().contains("Access is denied"));
        assert_eq!(
            svc.sys_run("format_c", &journal).unwrap_err().code,
            "unknown_action"
        );

        assert_eq!(runner.calls().len(), 2, "未知动作不能触发任何命令");
        let log = fs::read_to_string(&journal).unwrap();
        assert_eq!(log.lines().count(), 2);
        assert!(log.contains("\"ok\":true") && log.contains("\"ok\":false"));

        let list = svc.sys_list();
        assert_eq!(list.len(), 5);
        assert!(list
            .iter()
            .any(|a| a.id == "windows_old" && a.risk == Risk::High));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn executing_a_rule_with_services_stops_then_restores_them() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        let running = |n: u32, name: &str| CmdOutput {
            code: 0,
            stdout: format!("        STATE              : {n}  {name}\n"),
            stderr: String::new(),
        };
        let runner = FakeRunner::scripted(vec![
            running(4, "RUNNING"), // query
            CmdOutput::default(),  // stop
            running(1, "STOPPED"), // 轮询
            CmdOutput::default(),  // start
        ]);
        let mut svc = service(&d).with_system(runner.clone(), posix_factory(&d, None));
        svc.rules[0].services = vec!["wuauserv".into()];
        svc.build_plan(&["r".into()], &[]).unwrap();
        let rep = svc
            .execute(
                ExecRequest {
                    dry_run: false,
                    recycle: false,
                },
                &d.join("j.jsonl"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(rep.freed_bytes, 100);
        assert!(rep.service_errors.is_empty());
        assert_eq!(runner.calls().last().unwrap(), "sc.exe start wuauserv");
        assert_eq!(runner.calls()[1], "sc.exe stop wuauserv");
        fs::remove_dir_all(&d).unwrap();
    }

    // ---------- 应用卸载 ----------

    use diskclean_core::registry::MemRegistry;
    use diskclean_core::uninstall::FsRoots;

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    /// 模拟卸载器：运行时执行一个回调（比如删掉注册表里的登记项）。
    struct ShellRunner {
        lines: Mutex<Vec<String>>,
        on_run: Box<dyn Fn() + Send + Sync>,
        powershell: Mutex<VecDeque<CmdOutput>>,
    }

    impl ShellRunner {
        fn new(on_run: impl Fn() + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                lines: Mutex::default(),
                on_run: Box::new(on_run),
                powershell: Mutex::default(),
            })
        }
        fn with_powershell(self: Arc<Self>, out: CmdOutput) -> Arc<Self> {
            self.powershell.lock().unwrap().push_back(out);
            self
        }
    }

    impl CommandRunner for ShellRunner {
        fn run(&self, _p: &str, _a: &[&str]) -> std::io::Result<CmdOutput> {
            Ok(self
                .powershell
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_default())
        }
        fn run_shell(&self, line: &str) -> std::io::Result<CmdOutput> {
            self.lines.lock().unwrap().push(line.to_string());
            (self.on_run)();
            Ok(CmdOutput::default())
        }
    }

    fn roots_in(base: &Path) -> FsRoots {
        let mk = |p: &str| {
            let d = base.join(p);
            fs::create_dir_all(&d).unwrap();
            d
        };
        FsRoots {
            program_files: vec![mk("PF")],
            program_data: Some(mk("PD")),
            roaming: Some(mk("Roaming")),
            local: Some(mk("Local")),
            local_low: None,
            local_programs: None,
            start_menu: vec![],
            desktops: vec![],
        }
    }

    fn app_service(base: &Path, reg: Arc<MemRegistry>, runner: Arc<dyn CommandRunner>) -> Service {
        let base_s = base.to_string_lossy().into_owned();
        let factory: Box<PolicyFactory> = Box::new(move |excl: &[String]| {
            let mut p = SafetyPolicy::empty(test_style());
            p.protect(&format!("{base_s}/Windows"))
                .map_err(|e| ApiError::with("policy", e))?;
            for x in excl {
                p.exclude(x)
                    .map_err(|e| ApiError::with("invalid_exclusion", e))?;
            }
            Ok(p)
        });
        Service::new(
            vec![],
            Env::from_pairs([("SystemDrive", base.to_string_lossy())]),
            posix_factory(base, None),
            None,
        )
        .with_system(runner, posix_factory(base, None))
        .with_uninstall(reg, factory, roots_in(base))
    }

    /// 一个装在 PF/Foo 里、带卸载命令的程序，以及它在文件和注册表里的各种痕迹。
    fn install_foo(d: &Path, reg: &MemRegistry) {
        let key = format!("{UNINSTALL}\\Foo");
        reg.set_sz(Hive::LocalMachine, &key, "DisplayName", "Foo");
        reg.set_sz(Hive::LocalMachine, &key, "DisplayVersion", "2.1");
        reg.set_sz(Hive::LocalMachine, &key, "Publisher", "Acme Inc.");
        reg.set_sz(Hive::LocalMachine, &key, "InstallDate", "20240131");
        reg.set_sz(
            Hive::LocalMachine,
            &key,
            "InstallLocation",
            &d.join("PF/Foo").to_string_lossy(),
        );
        reg.set_sz(
            Hive::LocalMachine,
            &key,
            "UninstallString",
            r#""C:\Program Files\Foo\unins000.exe" /SILENT"#,
        );
        reg.set_sz(Hive::LocalMachine, r"SOFTWARE\Acme\Foo", "Version", "2.1");
        reg.set_sz(Hive::LocalMachine, r"SOFTWARE\Foo", "Shared", "1");
        reg.set_sz(
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "FooTray",
            &format!(r#""{}\tray.exe""#, d.join("PF/Foo").display()),
        );
        write(&d.join("PF/Foo/foo.exe"), 100);
        write(&d.join("Roaming/Foo/settings.json"), 30);
        write(&d.join("PF/Bar/bar.exe"), 10);
    }

    fn foo_remover(reg: &Arc<MemRegistry>) -> Arc<ShellRunner> {
        let r = reg.clone();
        ShellRunner::new(move || {
            let _ = r.delete_key(Hive::LocalMachine, &format!("{UNINSTALL}\\Foo"));
        })
    }

    #[test]
    fn lists_desktop_and_store_apps_with_friendly_fields() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        reg.set_sz(
            Hive::CurrentUser,
            &format!("{UNINSTALL}\\NoCmd"),
            "DisplayName",
            "Zzz Broken",
        );
        let store = CmdOutput {
            code: 0,
            stdout: r#"[{"Name":"Contoso.Notes","PackageFullName":"Contoso.Notes_1.0.0.0_x64__abc","Version":"1.0.0.0"}]"#.into(),
            stderr: String::new(),
        };
        let svc = app_service(&d, reg.clone(), foo_remover(&reg).with_powershell(store));
        let apps = svc.apps_list(true).unwrap();
        // 传统程序按名称排序，Store 应用附在后面。
        assert_eq!(
            apps.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["Foo", "Zzz Broken", "Contoso.Notes"]
        );
        let foo = apps.iter().find(|a| a.name == "Foo").unwrap();
        assert_eq!(foo.kind, "desktop");
        assert_eq!(foo.install_date.as_deref(), Some("2024-01-31"));
        assert_eq!(foo.publisher.as_deref(), Some("Acme Inc."));
        assert!(foo.can_uninstall);
        assert!(foo
            .uninstall_command
            .as_deref()
            .unwrap()
            .contains("unins000.exe"));
        let broken = apps.iter().find(|a| a.name == "Zzz Broken").unwrap();
        assert!(!broken.can_uninstall && broken.uninstall_command.is_none());
        let notes = apps.iter().find(|a| a.name == "Contoso.Notes").unwrap();
        assert_eq!((notes.kind, notes.can_uninstall), ("store", true));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_failing_store_listing_does_not_hide_desktop_apps() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        let bad = CmdOutput {
            code: 1,
            stdout: "boom".into(),
            stderr: String::new(),
        };
        let svc = app_service(&d, reg.clone(), foo_remover(&reg).with_powershell(bad));
        let apps = svc.apps_list(true).unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(svc.apps_list(false).unwrap().len(), 1);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn default_service_reports_unsupported_platform_for_the_registry() {
        let d = sandbox();
        assert_eq!(
            service(&d).apps_list(true).unwrap_err().code,
            "unsupported_platform"
        );
    }

    #[test]
    fn uninstall_scan_and_delete_end_to_end() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        let runner = foo_remover(&reg);
        let svc = app_service(&d, reg.clone(), runner.clone());
        let apps = svc.apps_list(false).unwrap();
        let id = apps.iter().find(|a| a.name == "Foo").unwrap().id;

        // 卸载前扫描：程序还登记着，不给出任何残留。
        let early = svc.app_leftovers(id, false, &[]).unwrap();
        assert!(early.still_registered && early.items.is_empty());

        // 运行卸载器（模拟它删掉了登记项）。
        let run = svc.app_uninstall(id, false).unwrap();
        assert_eq!((run.exit_code, run.still_registered), (0, false));
        assert_eq!(runner.lines.lock().unwrap().len(), 1);

        let left = svc.app_leftovers(id, false, &[]).unwrap();
        assert!(!left.still_registered);
        let by_path = |needle: &str| {
            left.items
                .iter()
                .find(|i| {
                    i.path
                        .replace('\\', "/")
                        .contains(&needle.replace('\\', "/"))
                        && i.value_name.is_none()
                })
                .unwrap_or_else(|| panic!("{needle} not found in {:#?}", left.items))
        };
        assert_eq!(by_path("PF/Foo").kind, "folder");
        assert!(by_path("PF/Foo").default_selected);
        assert!(by_path("Roaming/Foo").default_selected);
        assert_eq!(by_path(r"HKLM\SOFTWARE\Acme\Foo").kind, "reg_key");
        assert_eq!(by_path(r"HKLM\SOFTWARE\Acme\Foo").confidence, "high");
        // 以程序名命名的根键把握较小：列出，但不默认勾选。
        let owned = left
            .items
            .iter()
            .find(|i| i.path == r"HKLM\SOFTWARE\Foo")
            .unwrap();
        assert!(!owned.default_selected && owned.confidence == "medium");
        let run_val = left.items.iter().find(|i| i.kind == "reg_value").unwrap();
        assert_eq!(run_val.value_name.as_deref(), Some("FooTray"));
        assert!(
            !left
                .items
                .iter()
                .any(|i| i.path.replace('\\', "/").contains("PF/Bar")),
            "别的程序不能列出来"
        );
        assert_eq!(left.total_size, 130);

        // 只删默认勾选的（高置信度）项。
        let selected: Vec<usize> = left
            .items
            .iter()
            .filter(|i| i.default_selected)
            .map(|i| i.id)
            .collect();
        let bk = d.join("bk");
        let rep = svc
            .app_delete_leftovers(&selected, false, &bk, &d.join("j.jsonl"))
            .unwrap();
        assert!(
            rep.registry.iter().all(|r| r.status == "deleted"),
            "{:?}",
            rep.registry
        );
        assert_eq!(rep.files.deleted, 2);
        assert!(!d.join("PF/Foo").exists() && !d.join("Roaming/Foo").exists());
        assert!(d.join("PF/Bar/bar.exe").exists());
        assert!(!reg.key_exists(Hive::LocalMachine, r"SOFTWARE\Acme\Foo"));
        assert!(
            reg.key_exists(Hive::LocalMachine, r"SOFTWARE\Foo"),
            "未勾选的中置信度项必须保留"
        );
        assert!(reg
            .value(
                Hive::CurrentUser,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "FooTray"
            )
            .is_none());

        // 备份文件可用于恢复。
        let backup = std::path::PathBuf::from(rep.backup_file.unwrap());
        assert!(backup.starts_with(&bk) && backup.extension().unwrap() == "reg");
        let bytes = fs::read(&backup).unwrap();
        assert_eq!(&bytes[..2], [0xFF, 0xFE]);

        // 扫描结果已用掉，不能重复删除。
        assert_eq!(
            svc.app_delete_leftovers(&selected, false, &bk, &d.join("j.jsonl"))
                .unwrap_err()
                .code,
            "no_scan"
        );
        let journal = fs::read_to_string(d.join("j.jsonl")).unwrap();
        assert!(journal.contains("\"op\":\"registry\"") && journal.contains("\"op\":\"intent\""));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn forced_removal_works_without_running_any_uninstaller() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        let runner = foo_remover(&reg);
        let svc = app_service(&d, reg.clone(), runner.clone());
        let id = svc
            .apps_list(false)
            .unwrap()
            .iter()
            .find(|a| a.name == "Foo")
            .unwrap()
            .id;
        let left = svc.app_leftovers(id, true, &[]).unwrap();
        assert!(left.still_registered, "强制模式仍会如实告知它还登记着");
        let entry = left
            .items
            .iter()
            .find(|i| i.reason == "uninstall_entry")
            .unwrap();
        assert_eq!(entry.confidence, "high");
        let all: Vec<usize> = left.items.iter().map(|i| i.id).collect();
        svc.app_delete_leftovers(&all, true, &d.join("bk"), &d.join("j"))
            .unwrap();
        assert!(!reg.key_exists(Hive::LocalMachine, &format!("{UNINSTALL}\\Foo")));
        assert!(
            runner.lines.lock().unwrap().is_empty(),
            "强制删除不运行卸载器"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn bad_ids_and_selections_are_rejected() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        reg.set_sz(
            Hive::LocalMachine,
            &format!("{UNINSTALL}\\Plain"),
            "DisplayName",
            "Plain App",
        );
        let svc = app_service(&d, reg.clone(), foo_remover(&reg));
        assert_eq!(
            svc.app_uninstall(0, false).unwrap_err().code,
            "unknown_app",
            "没有调用 apps_list 之前没有任何序号可用"
        );
        let apps = svc.apps_list(false).unwrap();
        assert_eq!(
            svc.app_uninstall(99, false).unwrap_err().code,
            "unknown_app"
        );
        assert_eq!(
            svc.app_leftovers(99, false, &[]).unwrap_err().code,
            "unknown_app"
        );
        let plain = apps.iter().find(|a| a.name == "Plain App").unwrap().id;
        assert_eq!(
            svc.app_uninstall(plain, false).unwrap_err().code,
            "no_uninstaller"
        );

        let bk = d.join("bk");
        let j = d.join("j");
        assert_eq!(
            svc.app_delete_leftovers(&[0], false, &bk, &j)
                .unwrap_err()
                .code,
            "no_scan"
        );
        let foo = apps.iter().find(|a| a.name == "Foo").unwrap().id;
        svc.app_leftovers(foo, true, &[]).unwrap();
        assert_eq!(
            svc.app_delete_leftovers(&[], false, &bk, &j)
                .unwrap_err()
                .code,
            "nothing_selected"
        );
        assert_eq!(
            svc.app_delete_leftovers(&[999], false, &bk, &j)
                .unwrap_err()
                .code,
            "invalid_selection"
        );
        assert!(
            d.join("PF/Foo/foo.exe").exists(),
            "出错的请求不能删除任何东西"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn backup_failure_stops_everything_and_is_reported() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        let svc = app_service(&d, reg.clone(), foo_remover(&reg));
        let id = svc
            .apps_list(false)
            .unwrap()
            .iter()
            .find(|a| a.name == "Foo")
            .unwrap()
            .id;
        svc.app_uninstall(id, false).unwrap();
        let left = svc.app_leftovers(id, false, &[]).unwrap();
        let all: Vec<usize> = left.items.iter().map(|i| i.id).collect();
        let blocker = d.join("blocker");
        write(&blocker, 1);
        let before = reg.key_count();
        let err = svc
            .app_delete_leftovers(&all, false, &blocker.join("sub"), &d.join("j"))
            .unwrap_err();
        assert_eq!(err.code, "backup_failed");
        assert_eq!(reg.key_count(), before);
        assert!(d.join("PF/Foo/foo.exe").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn user_exclusions_protect_leftover_files() {
        let d = sandbox();
        let reg = Arc::new(MemRegistry::new());
        install_foo(&d, &reg);
        let svc = app_service(&d, reg.clone(), foo_remover(&reg));
        let id = svc
            .apps_list(false)
            .unwrap()
            .iter()
            .find(|a| a.name == "Foo")
            .unwrap()
            .id;
        svc.app_uninstall(id, false).unwrap();
        let excl = [d.join("Roaming/Foo").to_string_lossy().into_owned()];
        let left = svc.app_leftovers(id, false, &excl).unwrap();
        let all: Vec<usize> = left.items.iter().map(|i| i.id).collect();
        let rep = svc
            .app_delete_leftovers(&all, false, &d.join("bk"), &d.join("j"))
            .unwrap();
        assert!(d.join("Roaming/Foo/settings.json").exists(), "排除项优先");
        assert_eq!(rep.files.refused, 1);
        assert!(!d.join("PF/Foo").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    // ---------- 候选清单 ----------

    fn scanned(d: &Path) -> Service {
        write(&d.join("keep/a.bin"), 10);
        write(&d.join("junk/big.bin"), 500);
        write(&d.join("junk/sub/x.bin"), 50);
        write(&d.join("repo/.git/HEAD"), 5);
        write(&d.join("repo/code.rs"), 5);
        let svc = dup_service(d, FakeRunner::scripted(vec![]));
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        svc
    }

    fn parts(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn candidates_resolve_to_real_paths_with_current_state() {
        let d = sandbox();
        let svc = scanned(&d);
        let r = svc
            .cand_resolve(&[parts(&["junk"]), parts(&["junk", "big.bin"])])
            .unwrap();
        assert_eq!(r[0].path, d.join("junk").to_string_lossy());
        assert!(r[0].is_dir && r[0].exists && !r[0].is_link);
        assert_eq!((r[0].size, r[0].files), (550, 2));
        assert_eq!(r[1].size, 500);
        // 扫描之后被删除的项如实报告为不存在。
        fs::remove_file(d.join("junk/big.bin")).unwrap();
        let r = svc.cand_resolve(&[parts(&["junk", "big.bin"])]).unwrap();
        assert!(!r[0].exists);
        assert_eq!(
            svc.cand_resolve(&[parts(&["nope"])]).unwrap_err().code,
            "invalid_path"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn candidate_resolution_needs_a_scan() {
        let d = sandbox();
        assert_eq!(
            dup_service(&d, FakeRunner::scripted(vec![]))
                .cand_resolve(&[parts(&["x"])])
                .unwrap_err()
                .code,
            "no_scan"
        );
    }

    #[test]
    fn deleting_candidates_removes_files_and_directories() {
        let d = sandbox();
        let svc = scanned(&d);
        let rep = svc
            .cand_delete(
                &[parts(&["junk"]), parts(&["keep", "a.bin"])],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!((rep.deleted, rep.refused, rep.failed), (2, 0, 0));
        assert_eq!(rep.freed_bytes, 560);
        assert!(!d.join("junk").exists() && !d.join("keep/a.bin").exists());
        assert!(d.join("keep").exists(), "只删选中的文件，不动它的父目录");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn nested_candidates_are_only_processed_once_through_the_outer_item() {
        let d = sandbox();
        let svc = scanned(&d);
        let rep = svc
            .cand_delete(
                &[
                    parts(&["junk", "sub", "x.bin"]),
                    parts(&["junk"]),
                    parts(&["junk", "big.bin"]),
                ],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(rep.deleted, 1, "目录与其中的文件同时被选时只处理目录");
        assert_eq!(rep.failed, 0);
        assert_eq!(rep.freed_bytes, 550, "大小不能重复计算");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn directories_with_protected_content_or_gone_items_are_refused_not_deleted() {
        let d = sandbox();
        let svc = scanned(&d);
        fs::remove_file(d.join("keep/a.bin")).unwrap();
        let rep = svc
            .cand_delete(
                &[
                    parts(&["repo"]),
                    parts(&["keep", "a.bin"]),
                    parts(&["junk", "big.bin"]),
                ],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(rep.deleted, 1);
        assert_eq!(rep.refused, 2);
        assert!(
            d.join("repo/.git/HEAD").exists(),
            "含 .git 的目录不能被整体删除"
        );
        assert!(rep.problems.iter().any(|p| p.path.ends_with("repo")));
        assert!(!d.join("junk/big.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn candidate_deletion_respects_the_policy_and_exclusions_and_validates_input() {
        let d = sandbox();
        let svc = scanned(&d);
        // 受保护目录（测试策略里的 locked）与用户排除项都不能被删。
        write(&d.join("locked/secret.bin"), 3);
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        let rep = svc
            .cand_delete(
                &[parts(&["locked", "secret.bin"])],
                false,
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!((rep.deleted, rep.refused), (0, 1));
        let excl = [d.join("junk").to_string_lossy().into_owned()];
        let rep = svc
            .cand_delete(&[parts(&["junk"])], false, &excl, &d.join("j"), &mut |_| {})
            .unwrap();
        assert_eq!((rep.deleted, rep.refused), (0, 1));
        assert!(d.join("junk/big.bin").exists());

        assert_eq!(
            svc.cand_delete(&[], false, &[], &d.join("j"), &mut |_| {})
                .unwrap_err()
                .code,
            "nothing_selected"
        );
        assert_eq!(
            svc.cand_delete(&[parts(&[])], false, &[], &d.join("j"), &mut |_| {})
                .unwrap_err()
                .code,
            "invalid_path",
            "扫描根本身不能当作候选"
        );
        assert_eq!(
            svc.cand_delete(&[parts(&["ghost"])], false, &[], &d.join("j"), &mut |_| {})
                .unwrap_err()
                .code,
            "invalid_path"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    // ---------- 目录迁移 ----------

    use diskclean_core::migrate::{CopyStats, StdCopier, StdMover, VolumeInfo};
    use diskclean_core::procs::{ProcInfo, RmKind, RmProc};

    #[derive(Clone, Default)]
    struct SharedProcs(Arc<Mutex<Vec<ProcInfo>>>);
    impl ProcessSource for SharedProcs {
        fn list(&self) -> Vec<ProcInfo> {
            self.0.lock().unwrap().clone()
        }
    }

    struct FakeRmFinder(Vec<RmProc>);
    impl OpenFileFinder for FakeRmFinder {
        fn processes_using(&self, _: &[PathBuf]) -> std::io::Result<Vec<RmProc>> {
            Ok(self.0.clone())
        }
    }

    /// 模拟 taskkill：礼貌请求让 `graceful` 里的进程退出，/F 让所有进程退出。
    struct TaskKill {
        procs: SharedProcs,
        graceful: Vec<u32>,
        calls: Mutex<Vec<String>>,
    }
    impl CommandRunner for TaskKill {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<CmdOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            if program == "taskkill.exe" {
                let pid: u32 = args[1].parse().unwrap();
                if args.contains(&"/F") || self.graceful.contains(&pid) {
                    self.procs.0.lock().unwrap().retain(|p| p.pid != pid);
                }
            }
            Ok(CmdOutput::default())
        }
    }

    struct TwoVolumes {
        c: PathBuf,
        d: PathBuf,
    }
    impl Volumes for TwoVolumes {
        fn volume_of(&self, path: &Path) -> Option<VolumeInfo> {
            let mk = |m: &Path| VolumeInfo {
                mount: m.to_path_buf(),
                label: String::new(),
                fs: "NTFS".into(),
                free: 1 << 40,
                total: 1 << 41,
                removable: false,
                remote: false,
            };
            if path.starts_with(&self.c) {
                Some(mk(&self.c))
            } else if path.starts_with(&self.d) {
                Some(mk(&self.d))
            } else {
                None
            }
        }
    }

    struct SymLinks;
    impl LinkMaker for SymLinks {
        fn make_junction(&self, link: &Path, target: &Path) -> std::io::Result<()> {
            #[cfg(unix)]
            return std::os::unix::fs::symlink(target, link);
            #[cfg(not(unix))]
            {
                let _ = (link, target);
                Err(std::io::Error::other("unsupported"))
            }
        }
        fn remove_link(&self, link: &Path) -> std::io::Result<()> {
            migrate::remove_link(link)
        }
        fn link_target(&self, link: &Path) -> Option<PathBuf> {
            fs::read_link(link).ok()
        }
    }

    struct LockedMover;
    impl DirMover for LockedMover {
        fn rename_dir(&self, _: &Path, _: &Path) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Access is denied. (os error 5)",
            ))
        }
    }

    fn migration_service(
        d: &Path,
        procs: SharedProcs,
        rm: Vec<RmProc>,
        runner: Arc<dyn CommandRunner>,
        mover: Arc<dyn DirMover>,
    ) -> Service {
        fs::create_dir_all(d.join("C")).unwrap();
        fs::create_dir_all(d.join("D")).unwrap();
        let base = d.to_string_lossy().into_owned();
        let factory: Arc<PolicyFactory> = Arc::new(move |excl: &[String]| {
            let mut p = SafetyPolicy::empty(test_style());
            p.protect(&format!("{base}/C/Windows"))
                .map_err(|e| ApiError::with("policy", e))?;
            for x in excl {
                p.exclude(x)
                    .map_err(|e| ApiError::with("invalid_exclusion", e))?;
            }
            Ok(p)
        });
        service(d)
            .with_system(runner, posix_factory(d, None))
            .with_migrate(MigrateParts {
                procs: Arc::new(procs),
                rm: Arc::new(FakeRmFinder(rm)),
                volumes: Arc::new(TwoVolumes {
                    c: d.join("C"),
                    d: d.join("D"),
                }),
                copier: Arc::new(StdCopier),
                mover,
                links: Arc::new(SymLinks),
                policy_factory: factory,
                manifest_path: d.join("meta/migrations.json"),
                program_dirs: vec![],
                system_dirs: vec![PathBuf::from("/windows")],
                unix_links: false,
                self_pid: 999,
                stop_timing: StopTiming {
                    graceful_wait: std::time::Duration::from_millis(10),
                    force_wait: std::time::Duration::from_millis(10),
                    poll: std::time::Duration::from_millis(1),
                },
            })
    }

    fn proc_in(pid: u32, parent: Option<u32>, name: &str, exe: &str) -> ProcInfo {
        ProcInfo {
            pid,
            parent,
            name: name.into(),
            exe: Some(PathBuf::from(exe)),
            cwd: None,
            start_time: 1000 + u64::from(pid),
        }
    }

    fn make_app_dir(d: &Path) {
        write(&d.join("C/App/main.bin"), 4000);
        write(&d.join("C/App/data/a.dat"), 300);
    }

    #[test]
    fn migration_needs_its_platform_parts() {
        let d = sandbox();
        let svc = service(&d);
        assert_eq!(
            svc.mig_preflight("/a", "/b", &[]).unwrap_err().code,
            "unsupported_platform"
        );
        assert_eq!(svc.mig_list().unwrap_err().code, "unsupported_platform");
        assert_eq!(svc.mig_recover(), 0);
        svc.mig_cancel();
    }

    #[test]
    fn preflight_dto_reports_size_issues_and_whether_it_can_proceed() {
        let d = sandbox();
        make_app_dir(&d);
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(StdMover),
        );
        let ok = svc
            .mig_preflight(
                &d.join("C/App").to_string_lossy(),
                &d.join("D/Migrated/App").to_string_lossy(),
                &[],
            )
            .unwrap();
        assert!(ok.can_proceed, "{:?}", ok.issues);
        assert_eq!((ok.size, ok.files), (4300, 2));
        let bad = svc
            .mig_preflight(
                &d.join("C/App").to_string_lossy(),
                &d.join("C/Other").to_string_lossy(),
                &[],
            )
            .unwrap();
        assert!(!bad.can_proceed);
        let issue = bad.issues.iter().find(|i| i.code == "same_volume").unwrap();
        assert_eq!(issue.severity, "error");
        // 用户排除项也适用于迁移源：被排除的目录不能迁移。
        let excl = [d.join("C/App").to_string_lossy().into_owned()];
        let blocked = svc
            .mig_preflight(
                &d.join("C/App").to_string_lossy(),
                &d.join("D/x").to_string_lossy(),
                &excl,
            )
            .unwrap();
        assert!(!blocked.can_proceed);
        assert!(blocked.issues.iter().any(|i| i.code == "source_protected"));
    }

    #[test]
    fn blockers_are_listed_and_only_listed_unprotected_processes_can_be_stopped() {
        let d = sandbox();
        make_app_dir(&d);
        let dir = d.join("C/App");
        let procs = SharedProcs::default();
        *procs.0.lock().unwrap() = vec![
            proc_in(1, None, "launcher.exe", "/elsewhere/launcher.exe"),
            proc_in(
                10,
                Some(1),
                "app.exe",
                &format!("{}/app.exe", dir.display()),
            ),
            proc_in(11, Some(10), "app-helper.exe", "/elsewhere/helper.exe"),
            proc_in(40, Some(1), "explorer.exe", "/windows/explorer.exe"),
        ];
        let rm = vec![RmProc {
            pid: 40,
            name: "Explorer".into(),
            service: None,
            kind: RmKind::Explorer,
        }];
        let runner = Arc::new(TaskKill {
            procs: procs.clone(),
            graceful: vec![11],
            calls: Mutex::default(),
        });
        let svc = migration_service(&d, procs.clone(), rm, runner.clone(), Arc::new(StdMover));

        assert_eq!(
            svc.mig_stop(&[10], true, false).unwrap_err().code,
            "no_blockers",
            "没检测过占用就不能停止任何进程"
        );
        let b = svc.mig_blockers(&dir.to_string_lossy()).unwrap();
        let app = b.blockers.iter().find(|x| x.pid == 10).unwrap();
        assert_eq!(app.kinds, ["image"]);
        assert_eq!(
            app.related
                .iter()
                .map(|r| (r.pid, r.reason))
                .collect::<Vec<_>>(),
            [(11, "descendant")]
        );
        let explorer = b.blockers.iter().find(|x| x.pid == 40).unwrap();
        assert_eq!(explorer.protection, Some("explorer"));
        assert!(b.rm_error.is_none() && b.files_checked == 2);

        // 请求停止：app（连同相关进程）、资源管理器（受保护）、启动器（不在占用者清单里）。
        let res = svc.mig_stop(&[10, 40, 1], true, true).unwrap();
        let st = |pid| res.iter().find(|r| r.pid == pid).unwrap().status;
        assert_eq!(st(11), "exited", "子进程先礼貌关闭");
        assert_eq!(st(10), "forced");
        assert_eq!(st(40), "refused");
        assert_eq!(st(1), "refused");
        let left: Vec<u32> = procs.0.lock().unwrap().iter().map(|p| p.pid).collect();
        assert_eq!(left, [1, 40], "启动器和资源管理器必须还在");
        let calls = runner.calls.lock().unwrap().clone();
        assert!(
            !calls
                .iter()
                .any(|c| c.contains(" 40") || c.ends_with(" 1") || c.contains("/PID 1 ")),
            "{calls:?}"
        );
    }

    #[test]
    fn blockers_need_an_existing_directory() {
        let d = sandbox();
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(StdMover),
        );
        assert_eq!(
            svc.mig_blockers("/no/such/dir").unwrap_err().code,
            "invalid_path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migrate_then_restore_end_to_end_with_history() {
        let d = sandbox();
        make_app_dir(&d);
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(StdMover),
        );
        let (src, dst) = (d.join("C/App"), d.join("D/Migrated/App"));
        let journal = d.join("j.jsonl");
        let mut stages = Vec::new();
        let rec = svc
            .mig_start(
                &src.to_string_lossy(),
                &dst.to_string_lossy(),
                &[],
                &journal,
                &mut |p| {
                    if stages.last() != Some(&p.stage) {
                        stages.push(p.stage);
                    }
                },
            )
            .unwrap();
        assert_eq!(rec.status, "done");
        assert_eq!(stages, ["copying", "verifying", "switching", "cleaning"]);
        assert!(fs::symlink_metadata(&src).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(src.join("main.bin")).unwrap().len(), 4000);
        assert!(dst.join("data/a.dat").exists());

        let list = svc.mig_list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].status, list[0].files), ("done", 2));
        assert!(fs::read_to_string(&journal)
            .unwrap()
            .contains("\"op\":\"migration\""));

        // 再迁一次同一个目录：它现在是链接，预检拒绝。
        let again = svc
            .mig_start(
                &src.to_string_lossy(),
                &d.join("D/again").to_string_lossy(),
                &[],
                &journal,
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(again.code, "mig_preflight");
        assert!(again.detail.unwrap().contains("already_migrated"));

        let back = svc.mig_restore(&rec.id, &journal, &mut |_| {}).unwrap();
        assert_eq!(back.status, "restored");
        assert!(!fs::symlink_metadata(&src).unwrap().file_type().is_symlink());
        assert!(!dst.exists());
        assert_eq!(
            svc.mig_restore("nope", &journal, &mut |_| {})
                .unwrap_err()
                .code,
            "unknown_migration"
        );
    }

    #[test]
    fn a_locked_directory_is_reported_as_in_use_and_nothing_changes() {
        let d = sandbox();
        make_app_dir(&d);
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(LockedMover),
        );
        let err = svc
            .mig_start(
                &d.join("C/App").to_string_lossy(),
                &d.join("D/App").to_string_lossy(),
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(err.code, "mig_in_use");
        assert!(err.detail.unwrap().contains("Access is denied"));
        assert!(d.join("C/App/main.bin").exists());
        assert!(!d.join("D/App").exists());
        assert_eq!(svc.mig_list().unwrap()[0].status, "failed");
    }

    #[test]
    fn interrupted_migrations_are_repaired_on_startup() {
        let d = sandbox();
        make_app_dir(&d);
        write(&d.join("D/App/partial.bin"), 5);
        let rec = MigrationRecord {
            id: "x-1".into(),
            source: d.join("C/App").to_string_lossy().into(),
            target: d.join("D/App").to_string_lossy().into(),
            old_path: None,
            size: 1,
            files: 1,
            created: 1,
            status: migrate::Status::Copying,
            note: None,
            target_created: true,
        };
        ManifestStore::open(d.join("meta/migrations.json"))
            .upsert(&rec)
            .unwrap();
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(StdMover),
        );
        assert_eq!(svc.mig_recover(), 0, "能自动回滚的不算需要人工处理");
        assert!(!d.join("D/App").exists(), "不完整的目标被清掉");
        assert!(d.join("C/App/main.bin").exists());
        assert_eq!(svc.mig_list().unwrap()[0].status, "failed");
        let _ = CopyStats::default();
    }

    // ---------- 清理之后立刻反映到已有的扫描结果 ----------

    fn names_at(svc: &Service, parts: &[&str]) -> Vec<String> {
        svc.children(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
            .items
            .into_iter()
            .map(|c| c.name)
            .collect()
    }

    #[test]
    fn deleting_candidates_updates_the_scan_tree_totals_and_top_files() {
        let d = sandbox();
        let svc = scanned(&d); // keep/a.bin 10, junk/{big.bin 500, sub/x.bin 50}, repo/...
        let before = svc.scan_current().unwrap();
        assert_eq!(before.total_size, 570);
        assert!(before.top_files.iter().any(|f| f.path.ends_with("big.bin")));

        svc.cand_delete(
            &[parts(&["junk", "big.bin"])],
            false,
            &[],
            &d.join("j"),
            &mut |_| {},
        )
        .unwrap();
        let after = svc.scan_current().unwrap();
        assert_eq!(after.total_size, 70, "500 字节的文件已删除，合计要立刻减少");
        assert_eq!(after.file_count, before.file_count - 1);
        assert!(
            !after.top_files.iter().any(|f| f.path.ends_with("big.bin")),
            "最大文件列表不能还显示已删除的文件"
        );
        assert_eq!(names_at(&svc, &["junk"]), ["sub"]);
        // 上级目录的大小一起变了。
        let root = svc.children(&[]).unwrap();
        assert_eq!(
            root.items.iter().find(|c| c.name == "junk").unwrap().size,
            50
        );

        // 整个目录被删除：它从上级列表里消失。
        svc.cand_delete(&[parts(&["junk"])], false, &[], &d.join("j"), &mut |_| {})
            .unwrap();
        assert!(!names_at(&svc, &[]).contains(&"junk".to_string()));
        assert_eq!(svc.scan_current().unwrap().total_size, 20);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn refused_or_failed_items_stay_in_the_tree() {
        let d = sandbox();
        let svc = scanned(&d);
        let before = svc.scan_current().unwrap().total_size;
        // 含 .git 的目录被拒绝，不能从树里消失。
        svc.cand_delete(&[parts(&["repo"])], false, &[], &d.join("j"), &mut |_| {})
            .unwrap();
        assert!(names_at(&svc, &[]).contains(&"repo".to_string()));
        assert_eq!(svc.scan_current().unwrap().total_size, before);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn running_cleanup_rules_updates_the_scan_tree() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        write(&d.join("cache/sub/b.bin"), 20);
        write(&d.join("keep/k.bin"), 7);
        let svc = service(&d);
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        svc.build_plan(&["r".into()], &[]).unwrap();
        svc.execute(
            ExecRequest {
                dry_run: false,
                recycle: false,
            },
            &d.join("j.jsonl"),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(svc.scan_current().unwrap().total_size, 7);
        assert!(
            names_at(&svc, &["cache"]).is_empty(),
            "规则清掉了 cache 里的内容"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_dry_run_leaves_the_scan_tree_alone() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        let svc = service(&d);
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        svc.build_plan(&["r".into()], &[]).unwrap();
        svc.execute(
            ExecRequest {
                dry_run: true,
                recycle: false,
            },
            &d.join("j.jsonl"),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(svc.scan_current().unwrap().total_size, 100);
    }

    #[test]
    fn deleting_a_file_elsewhere_removes_it_from_duplicate_results_too() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        let before = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        assert_eq!(before.groups[0].files.len(), 3);
        // 通过"候选清单"删掉其中一份。
        svc.cand_delete(
            &[parts(&["b", "two.bin"])],
            false,
            &[],
            &d.join("j"),
            &mut |_| {},
        )
        .unwrap();
        let after = svc.dup_current().unwrap();
        assert_eq!(after.groups[0].files.len(), 2, "重复文件视图也要同步");
        svc.cand_delete(
            &[parts(&["a", "one.bin"])],
            false,
            &[],
            &d.join("j"),
            &mut |_| {},
        )
        .unwrap();
        assert!(
            svc.dup_current().unwrap().groups.is_empty(),
            "只剩一份就不再算重复"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn duplicates_deleted_in_the_duplicates_view_update_the_scan_tree() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let keep = sum.groups[0].keep;
        let sel: Vec<_> = (0..3)
            .filter(|i| *i != keep)
            .map(|i| selection(0, i))
            .collect();
        svc.dup_delete(&sel, false, &[], &d.join("j"), &mut |_| {})
            .unwrap();
        assert_eq!(
            svc.scan_current().unwrap().total_size,
            3000 + 3001,
            "三份 3000 字节里删了两份"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn migrating_removes_the_source_from_the_tree_and_restoring_puts_it_back() {
        let d = sandbox();
        make_app_dir(&d);
        write(&d.join("C/other.bin"), 9);
        let svc = migration_service(
            &d,
            SharedProcs::default(),
            vec![],
            FakeRunner::scripted(vec![]),
            Arc::new(StdMover),
        );
        svc.scan(&d.join("C").to_string_lossy(), &mut |_| {})
            .unwrap();
        assert_eq!(svc.scan_current().unwrap().total_size, 4309);

        let rec = svc
            .mig_start(
                &d.join("C/App").to_string_lossy(),
                &d.join("D/App").to_string_lossy(),
                &[],
                &d.join("j"),
                &mut |_| {},
            )
            .unwrap();
        // C 盘不再占用这 4300 字节，扫描结果立刻反映。
        assert_eq!(svc.scan_current().unwrap().total_size, 9);
        assert!(!names_at(&svc, &[]).contains(&"App".to_string()));

        svc.mig_restore(&rec.id, &d.join("j"), &mut |_| {}).unwrap();
        assert_eq!(
            svc.scan_current().unwrap().total_size,
            4309,
            "还原后数据回到 C 盘，树里也要回来"
        );
        assert!(names_at(&svc, &[]).contains(&"App".to_string()));
        assert_eq!(names_at(&svc, &["App"]).len(), 2);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn scan_current_requires_a_scan() {
        let d = sandbox();
        assert_eq!(service(&d).scan_current().unwrap_err().code, "no_scan");
    }

    #[test]
    fn system_actions_update_the_scan_tree_when_they_remove_files() {
        let d = sandbox();
        write(&d.join("Windows.old/Windows/x.dll"), 800);
        write(&d.join("keep.bin"), 5);
        let reg = Arc::new(MemRegistry::new());
        let svc = app_service(&d, reg, FakeRunner::scripted(vec![]));
        svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(svc.scan_current().unwrap().total_size, 805);
        svc.sys_run("windows_old", &d.join("j")).unwrap();
        assert_eq!(svc.scan_current().unwrap().total_size, 5);
        assert!(!names_at(&svc, &[]).contains(&"Windows.old".to_string()));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_stale_selection_is_rejected_instead_of_deleting_a_different_file() {
        let d = sandbox();
        make_dups(&d);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        let keep = sum.groups[0].keep;
        let victim = (0..3).find(|i| *i != keep).unwrap();
        let other = (0..3).find(|i| *i != keep && *i != victim).unwrap();
        // 界面看到的第 victim 项其实是别的文件（序号已错位）：路径对不上就拒绝。
        let stale = DupSelection {
            group: 0,
            file: victim,
            path: Some(sum.groups[0].files[other].path.clone()),
        };
        let err = svc
            .dup_delete(&[stale], false, &[], &d.join("j"), &mut |_| {})
            .unwrap_err();
        assert_eq!(err.code, "invalid_selection");
        assert!(
            d.join("a/one.bin").exists()
                && d.join("b/two.bin").exists()
                && d.join("c/three.bin").exists()
        );
        // 路径一致时正常删除。
        let ok = DupSelection {
            group: 0,
            file: victim,
            path: Some(sum.groups[0].files[victim].path.clone()),
        };
        assert_eq!(
            svc.dup_delete(&[ok], false, &[], &d.join("j"), &mut |_| {})
                .unwrap()
                .deleted,
            1
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn unicode_names_survive_scan_candidates_deletion_and_refresh() {
        let d = sandbox();
        write(
            &d.join("资料库/二级目录 📁/公司年度总结（未剪辑）📹.mp4"),
            900,
        );
        write(&d.join("资料库/二级目录 📁/日本語.txt"), 10);
        write(&d.join("下载/한국어.bin"), 5);
        let svc = dup_service(&d, FakeRunner::scripted(vec![]));
        let sum = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert!(
            sum.top_files[0]
                .path
                .ends_with("公司年度总结（未剪辑）📹.mp4"),
            "最大文件的路径原样返回"
        );
        let names = names_at(&svc, &["资料库", "二级目录 📁"]);
        assert_eq!(names, ["公司年度总结（未剪辑）📹.mp4", "日本語.txt"]);

        let resolved = svc
            .cand_resolve(&[parts(&["资料库", "二级目录 📁", "日本語.txt"])])
            .unwrap();
        assert!(
            resolved[0]
                .path
                .replace('\\', "/")
                .ends_with("资料库/二级目录 📁/日本語.txt")
                && resolved[0].exists
        );

        let rep = svc
            .cand_delete(
                &[parts(&[
                    "资料库",
                    "二级目录 📁",
                    "公司年度总结（未剪辑）📹.mp4",
                ])],
                false,
                &[],
                &d.join("日志.jsonl"),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!((rep.deleted, rep.freed_bytes), (1, 900));
        // 日志是合法 UTF-8，中文原样可读。
        let journal = fs::read_to_string(d.join("日志.jsonl")).unwrap();
        assert!(
            journal.contains("公司年度总结（未剪辑）📹.mp4"),
            "{journal}"
        );
        // 刷新后的树和摘要立刻反映，名字没有变样。
        assert_eq!(names_at(&svc, &["资料库", "二级目录 📁"]), ["日本語.txt"]);
        assert_eq!(svc.scan_current().unwrap().total_size, 15);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn display_path_leaves_unicode_untouched() {
        assert_eq!(
            display_path(Path::new(r"\\?\D:\项目\报告📄.docx")),
            r"D:\项目\报告📄.docx"
        );
    }

    // ---------- 云端硬盘 / 云同步目录不参与分析 ----------

    /// 卷标可配置的两盘模拟：`C` 是普通盘，`G` 是云端虚拟盘或网络驱动器。
    struct LabelVolumes {
        normal: PathBuf,
        cloud: PathBuf,
        label: &'static str,
        remote: bool,
    }
    impl Volumes for LabelVolumes {
        fn volume_of(&self, path: &Path) -> Option<VolumeInfo> {
            let (mount, label, remote) = if path.starts_with(&self.cloud) {
                (&self.cloud, self.label, self.remote)
            } else if path.starts_with(&self.normal) {
                (&self.normal, "Data", false)
            } else {
                return None;
            };
            Some(VolumeInfo {
                mount: mount.clone(),
                label: label.into(),
                fs: "NTFS".into(),
                free: 1 << 40,
                total: 1 << 41,
                removable: false,
                remote,
            })
        }
    }

    fn cloud_service(d: &Path, label: &'static str, remote: bool) -> Service {
        fs::create_dir_all(d.join("C")).unwrap();
        fs::create_dir_all(d.join("G")).unwrap();
        let base = d.to_string_lossy().into_owned();
        let factory: Arc<PolicyFactory> = Arc::new(move |_: &[String]| {
            let mut p = SafetyPolicy::empty(test_style());
            p.protect(&format!("{base}/C/Windows"))
                .map_err(|e| ApiError::with("policy", e))?;
            Ok(p)
        });
        service(d).with_migrate(MigrateParts {
            procs: Arc::new(SharedProcs::default()),
            rm: Arc::new(FakeRmFinder(vec![])),
            volumes: Arc::new(LabelVolumes {
                normal: d.join("C"),
                cloud: d.join("G"),
                label,
                remote,
            }),
            copier: Arc::new(StdCopier),
            mover: Arc::new(StdMover),
            links: Arc::new(SymLinks),
            policy_factory: factory,
            manifest_path: d.join("meta/m.json"),
            program_dirs: vec![],
            system_dirs: vec![],
            unix_links: false,
            self_pid: 999,
            stop_timing: StopTiming::default(),
        })
    }

    fn names_in_root(svc: &Service) -> Vec<String> {
        names_at(svc, &[])
    }

    #[test]
    fn cloud_sync_folders_are_left_out_of_the_scan_and_reported() {
        let d = sandbox();
        write(&d.join("local/a.bin"), 100);
        write(&d.join("Google Drive/huge.bin"), 9_999);
        write(&d.join("OneDrive - 某公司/文档.docx"), 777);
        write(&d.join("local/Dropbox/x.bin"), 55);
        let svc = service(&d);
        let sum = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(sum.total_size, 100, "云目录里的内容不能计入总量");
        assert_eq!(names_in_root(&svc), ["local"]);
        let mut ex: Vec<(String, String)> = sum
            .excluded
            .iter()
            .map(|e| {
                (
                    Path::new(&e.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    e.reason.clone(),
                )
            })
            .collect();
        ex.sort();
        assert_eq!(
            ex,
            [
                ("Dropbox".into(), "Dropbox".into()),
                ("Google Drive".into(), "Google Drive".into()),
                ("OneDrive - 某公司".into(), "OneDrive".into())
            ]
        );
        assert!(
            !sum.top_files.iter().any(|f| f.path.contains("huge.bin")),
            "最大文件里也不能出现云盘文件"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn analyzing_the_cloud_can_be_switched_on_and_custom_paths_still_apply() {
        let d = sandbox();
        write(&d.join("local/a.bin"), 100);
        write(&d.join("Google Drive/huge.bin"), 9_999);
        write(&d.join("games/g.bin"), 5_000);
        let svc = service(&d);
        let env = Env::from_pairs([("X", "y")]);
        let on = CloudRules::new(true, &[], &env);
        assert_eq!(
            svc.scan_with(d.to_str().unwrap(), 0, &on, &mut |_| {})
                .unwrap()
                .total_size,
            15_099
        );
        let custom = CloudRules::new(
            true,
            &[d.join("games").to_string_lossy().into_owned()],
            &env,
        );
        let sum = svc
            .scan_with(d.to_str().unwrap(), 0, &custom, &mut |_| {})
            .unwrap();
        assert_eq!(sum.total_size, 10_099, "自定义跳过的路径始终生效");
        assert_eq!(sum.excluded.len(), 1);
        assert_eq!(sum.excluded[0].reason, "custom");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_mft_fast_path_is_pruned_afterwards() {
        let d = sandbox();
        write(&d.join("local/a.bin"), 10);
        let file = |n: &str, size| Node {
            name: n.into(),
            is_dir: false,
            size,
            file_count: 1,
            children: vec![],
        };
        let dir = |n: &str, kids: Vec<Node>| Node {
            name: n.into(),
            is_dir: true,
            size: kids.iter().map(|k| k.size).sum(),
            file_count: kids.iter().map(|k| k.file_count).sum(),
            children: kids,
        };
        let root_dir = d.clone();
        let tree = dir(
            "root",
            vec![
                dir("Google Drive", vec![file("big.bin", 9_000)]),
                dir(
                    "users",
                    vec![file("u.bin", 50), dir("Dropbox", vec![file("d.bin", 400)])],
                ),
            ],
        );
        let svc = service_fast(
            &d,
            Some(Box::new(move |_, _, _| {
                Ok(ScanOutcome {
                    root: tree.clone(),
                    skipped: vec![],
                    excluded: vec![],
                    cancelled: false,
                })
            })),
        );
        let sum = svc.scan(&root_dir.to_string_lossy(), &mut |_| {}).unwrap();
        assert_eq!(sum.method, "mft");
        assert_eq!(
            sum.total_size, 50,
            "9000 和 400 字节的云目录被剪掉，上级总量同步扣除"
        );
        assert_eq!(sum.file_count, 1);
        assert_eq!(sum.excluded.iter().map(|e| e.size).sum::<u64>(), 9_400);
        assert_eq!(names_in_root(&svc), ["users"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn scanning_inside_a_cloud_folder_or_on_a_cloud_drive_is_refused() {
        let d = sandbox();
        write(&d.join("Google Drive/Projects/a.bin"), 10);
        let svc = service(&d);
        for p in ["Google Drive", "Google Drive/Projects"] {
            let err = svc
                .scan(&d.join(p).to_string_lossy(), &mut |_| {})
                .unwrap_err();
            assert_eq!(err.code, "cloud_location", "{p}");
            assert_eq!(err.detail.as_deref(), Some("Google Drive"));
        }
        assert_eq!(
            svc.dup_scan(&d.join("Google Drive").to_string_lossy(), 1, &mut |_| {})
                .unwrap_err()
                .code,
            "cloud_location"
        );
        // 打开"分析云端"后允许。
        let on = CloudRules::new(true, &[], &Env::default());
        assert!(svc
            .scan_with(
                &d.join("Google Drive").to_string_lossy(),
                0,
                &on,
                &mut |_| {}
            )
            .is_ok());

        // 虚拟盘符：卷标是 Google Drive。
        let d2 = sandbox();
        write(&d2.join("G/My Drive/x.bin"), 10);
        write(&d2.join("C/ok.bin"), 10);
        let gd = cloud_service(&d2, "Google Drive", false);
        assert_eq!(
            gd.scan(&d2.join("G").to_string_lossy(), &mut |_| {})
                .unwrap_err()
                .code,
            "cloud_location"
        );
        assert!(gd
            .scan(&d2.join("C").to_string_lossy(), &mut |_| {})
            .is_ok());
        let net = cloud_service(&sandbox(), "Data", true);
        let _ = net;
        fs::remove_dir_all(&d).unwrap();
        fs::remove_dir_all(&d2).unwrap();
    }

    #[test]
    fn network_drives_are_treated_as_remote_and_excluded_too() {
        let d = sandbox();
        write(&d.join("G/x.bin"), 10);
        let svc = cloud_service(&d, "Data", true);
        let err = svc
            .scan(&d.join("G").to_string_lossy(), &mut |_| {})
            .unwrap_err();
        assert_eq!(
            (err.code, err.detail.as_deref()),
            ("cloud_location", Some("Network"))
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_drive_list_marks_cloud_and_network_drives() {
        let d = sandbox();
        let svc = cloud_service(&d, "Google Drive", false);
        // 本机真实磁盘（测试环境）没有云盘卷标，所以没有任何一个被标记。
        assert!(svc.drives().iter().all(|x| x.cloud.is_none()));
    }

    #[test]
    fn duplicates_do_not_look_inside_cloud_folders() {
        let d = sandbox();
        write(&d.join("local/a.bin"), 5000);
        write(&d.join("Google Drive/a-copy.bin"), 5000);
        let svc = service(&d);
        let sum = svc.dup_scan(d.to_str().unwrap(), 1, &mut |_| {}).unwrap();
        assert!(sum.groups.is_empty());
        assert_eq!(sum.excluded.len(), 1);
        let on = CloudRules::new(true, &[], &Env::default());
        assert_eq!(
            svc.dup_scan_with(d.to_str().unwrap(), 1, &on, &mut |_| {})
                .unwrap()
                .groups
                .len(),
            1
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn cloud_sync_folders_cannot_be_migrated_even_when_cloud_analysis_is_on() {
        let d = sandbox();
        write(&d.join("C/Dropbox/a.bin"), 10);
        let svc = cloud_service(&d, "Data", false);
        let p = svc
            .mig_preflight(
                &d.join("C/Dropbox").to_string_lossy(),
                &d.join("G/x").to_string_lossy(),
                &[],
            )
            .unwrap();
        assert!(p
            .issues
            .iter()
            .any(|i| i.code == "cloud_location" && i.severity == "error"));
        assert!(!p.can_proceed);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn items_below_the_minimum_size_are_folded_into_their_parent() {
        let d = sandbox();
        for i in 0..5 {
            write(&d.join(format!("proj/small{i}.txt")), 100);
        }
        write(&d.join("proj/big.bin"), 5000);
        write(&d.join("tiny_dir/a.txt"), 50);
        let svc = service(&d);
        let sum = svc
            .scan_with(
                d.to_str().unwrap(),
                1000,
                &svc.default_cloud_rules(),
                &mut |_| {},
            )
            .unwrap();
        assert_eq!(sum.min_size, 1000);
        assert_eq!(sum.total_size, 5000 + 500 + 50, "总量仍然完整");
        let root = svc.children(&[]).unwrap();
        let names: Vec<_> = root.items.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["proj"], "小目录不再单独列出");
        assert_eq!(root.small_size, 50);
        let proj = svc.children(&["proj".to_string()]).unwrap();
        assert_eq!(proj.items.len(), 1);
        assert_eq!(proj.small_size, 500);
        assert_eq!(proj.small_files, 5);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn mac_apps_are_listed_trashed_and_their_library_leftovers_removed() {
        use diskclean_core::macapps;
        let d = sandbox();
        let home = d.join("Users/alice");
        let write_plist = |rel: &str, name: &str, id: &str| {
            let p = d.join(rel).join("Contents/Info.plist");
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(
                p,
                format!(
                    "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
                     <key>CFBundleName</key><string>{name}</string>\
                     <key>CFBundleIdentifier</key><string>{id}</string></dict></plist>"
                ),
            )
            .unwrap();
        };
        write_plist("Applications/Foo.app", "Foo", "com.acme.foo");
        write(&d.join("Applications/Foo.app/Contents/MacOS/foo"), 8192);
        write(&home.join("Library/Caches/com.acme.foo/c.bin"), 4000);
        write(&home.join("Library/Application Support/Foo/data"), 3000);
        write(&home.join("Library/Application Support/Other/x"), 10);

        let trashed = Arc::new(Mutex::new(Vec::<PathBuf>::new()));
        let t2 = trashed.clone();
        let home_s = home.to_string_lossy().into_owned();
        let policy_home = home_s.clone();
        let factory: Box<PolicyFactory> = Box::new(move |_| {
            // 沙盒在系统临时目录下（macOS 上是受保护的 /private/var）：基础策略只保护家目录。
            let mut base = SafetyPolicy::empty(test_style());
            for d in ["", "/Library"] {
                base.protect(&format!("{policy_home}{d}"))
                    .map_err(|e| ApiError::with("policy", e))?;
            }
            macapps::leftover_policy_on(base, &policy_home).map_err(|e| ApiError::with("policy", e))
        });
        let svc = service(&d)
            .with_uninstall(Arc::new(NoRegistry), factory, FsRoots::default())
            .with_mac(MacConfig {
                home: home_s,
                app_roots: vec![d.join("Applications")],
                // 假的"移入废纸篓"：真的把它挪走，这样之后的"仍已安装"判断才有意义。
                trash: Arc::new(move |p| {
                    t2.lock().unwrap().push(p.to_path_buf());
                    fs::remove_dir_all(p)
                }),
            });

        let apps = svc.apps_list(false).unwrap();
        let foo = apps.iter().find(|a| a.name == "Foo").unwrap();
        assert_eq!(foo.kind, "bundle");
        assert!(foo.can_uninstall && foo.uninstall_command.is_none());

        // 应用还在：不给残留。
        let early = svc.app_leftovers(foo.id, false, &[]).unwrap();
        assert!(early.still_registered && early.items.is_empty());

        let run = svc.app_uninstall(foo.id, false).unwrap();
        assert_eq!((run.exit_code, run.still_registered), (0, false));
        assert_eq!(*trashed.lock().unwrap(), [d.join("Applications/Foo.app")]);

        let left = svc.app_leftovers(foo.id, false, &[]).unwrap();
        let mut paths: Vec<_> = left
            .items
            .iter()
            .map(|i| (i.path.replace('\\', "/"), i.reason, i.default_selected))
            .collect();
        paths.sort();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths[0].0.ends_with("Library/Application Support/Foo"));
        assert_eq!(paths[0].1, "name_match");
        assert!(!paths[0].2, "名称匹配把握较小，不默认勾选");
        assert!(paths[1].0.ends_with("Library/Caches/com.acme.foo"));
        assert_eq!(paths[1].1, "bundle_id");
        assert!(paths[1].2);

        let all: Vec<usize> = left.items.iter().map(|i| i.id).collect();
        let rep = svc
            .app_delete_leftovers(&all, false, &d.join("backup"), &d.join("j.jsonl"))
            .unwrap();
        assert_eq!(rep.files.deleted, 2);
        assert!(!home.join("Library/Caches/com.acme.foo").exists());
        assert!(!home.join("Library/Application Support/Foo").exists());
        assert!(home.join("Library/Application Support/Other/x").exists());
        fs::remove_dir_all(&d).unwrap();
    }
}
