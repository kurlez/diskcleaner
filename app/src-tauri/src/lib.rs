mod elevation;
mod service;
mod settings;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use diskclean_core::builtin::{mac_rules, windows_rules};
use diskclean_core::cloud;
use diskclean_core::migrate::{self, LinkMaker, MklinkJunction};
use diskclean_core::procs;
use diskclean_core::registry::Registry;
use diskclean_core::rules::Env;
use diskclean_core::safety::{KnownDirs, SafetyPolicy};
use diskclean_core::sysaction::CommandRunner;
use diskclean_core::uninstall::{self, FsRoots};
use tauri::{AppHandle, Emitter, Manager, State};

use service::{
    ApiError, AppDto, BlockersDto, CandResolved, ChildrenDto, DriveDto, DupSelection, DupSummary,
    ExecRequest, LeftoverReportDto, LeftoversDto, MigProgressDto, MigrateParts, MigrationDto,
    PlanSummary, PreflightDto, ReportDto, RuleDto, ScanSummary, Service, StopResultDto,
    SysActionDto, SysResultDto, UninstallRunDto,
};
use settings::Settings;

struct AppState {
    svc: Arc<Service>,
    settings: Mutex<Settings>,
    settings_path: PathBuf,
    journal_path: PathBuf,
    backup_dir: PathBuf,
}

/// Windows 下优先用 MFT 快速扫描；失败（非管理员、非 NTFS 等）由服务层回退到遍历。
#[cfg(windows)]
fn fast_scan() -> Option<Box<service::FastScanFn>> {
    use diskclean_core::mft::{self, MftError};
    Some(Box::new(|path, cancel, progress| {
        let (letter, _) = path
            .to_str()
            .and_then(mft::split_drive_path)
            .ok_or(("not_ntfs", "not a drive path".to_string()))?;
        let vol = mft::open_volume(letter).map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::PermissionDenied {
                "access_denied"
            } else {
                "other"
            };
            (code, e.to_string())
        })?;
        mft::scan_path(vol, path, cancel, progress).map_err(|e| {
            let code = match &e {
                MftError::NotNtfs(_) => "not_ntfs",
                MftError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
                    "access_denied"
                }
                MftError::PathNotFound => "path_not_found",
                _ => "other",
            };
            (code, e.to_string())
        })
    }))
}

#[cfg(not(windows))]
fn fast_scan() -> Option<Box<service::FastScanFn>> {
    None
}

/// 把用户排除项加进策略；排除项无效时给出带路径的错误。
fn with_exclusions(
    mut policy: SafetyPolicy,
    exclusions: &[String],
) -> Result<SafetyPolicy, ApiError> {
    for x in exclusions {
        policy
            .exclude(x)
            .map_err(|e| ApiError::with("invalid_exclusion", format!("{x}: {e}")))?;
    }
    Ok(policy)
}

/// 是否在 macOS 上运行。
const IS_MAC: bool = cfg!(target_os = "macos");

/// macOS 用户主目录。
fn mac_home() -> Result<String, ApiError> {
    std::env::var("HOME")
        .ok()
        .filter(|h| h.starts_with('/'))
        .ok_or(ApiError::new("unsupported_platform"))
}

/// 生产环境的安全策略：平台默认保护名单（Windows 或 macOS）+ 用户排除项。
fn windows_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    if IS_MAC {
        let policy =
            SafetyPolicy::new_mac(&mac_home()?).map_err(|e| ApiError::with("policy", e))?;
        return with_exclusions(policy, exclusions);
    }
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let policy = SafetyPolicy::new(&dirs).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 用户亲自选中文件时的策略（删除重复文件）：不保护用户文档，但系统和 AppData 仍受保护。
fn windows_selected_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    if IS_MAC {
        let policy = SafetyPolicy::for_user_selected_mac(&mac_home()?)
            .map_err(|e| ApiError::with("policy", e))?;
        return with_exclusions(policy, exclusions);
    }
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let policy = SafetyPolicy::for_user_selected(&dirs).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 删除卸载残留时的策略：默认保护名单 + 应用常驻目录的内部 + 用户排除项。
fn windows_leftover_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    if IS_MAC {
        let policy = diskclean_core::macapps::mac_leftover_policy(&mac_home()?)
            .map_err(|e| ApiError::with("policy", e))?;
        return with_exclusions(policy, exclusions);
    }
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let roots = FsRoots::from_env(&Env::from_process());
    let policy =
        uninstall::leftover_policy(&dirs, &roots).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 目录迁移的安全策略：系统目录和用户根目录本身禁止，应用数据等子目录允许。
fn windows_migration_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    if IS_MAC {
        let policy =
            migrate::mac_migration_policy(&mac_home()?).map_err(|e| ApiError::with("policy", e))?;
        return with_exclusions(policy, exclusions);
    }
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let policy = migrate::migration_policy(&dirs).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 通过命令执行器创建 junction（`mklink /J`）。
struct RunnerLinks(Arc<dyn CommandRunner>);

impl LinkMaker for RunnerLinks {
    fn make_junction(&self, link: &Path, target: &Path) -> std::io::Result<()> {
        MklinkJunction(self.0.as_ref()).make_junction(link, target)
    }
    fn remove_link(&self, link: &Path) -> std::io::Result<()> {
        migrate::remove_link(link)
    }
    fn link_target(&self, link: &Path) -> Option<PathBuf> {
        std::fs::read_link(link).ok()
    }
}

#[cfg(windows)]
fn open_file_finder(_runner: Arc<dyn CommandRunner>) -> Arc<dyn procs::OpenFileFinder> {
    Arc::new(procs::RestartManager)
}

#[cfg(target_os = "macos")]
fn open_file_finder(runner: Arc<dyn CommandRunner>) -> Arc<dyn procs::OpenFileFinder> {
    Arc::new(procs::LsofFinder(runner))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn open_file_finder(_runner: Arc<dyn CommandRunner>) -> Arc<dyn procs::OpenFileFinder> {
    Arc::new(procs::NoOpenFileFinder)
}

/// Windows 用 robocopy（保留 ACL 与所有者），macOS 用 ditto（保留权限、扩展属性与符号链接）；
/// 其他平台用纯 Rust 复制。
#[cfg(windows)]
fn real_copier() -> Arc<dyn migrate::Copier> {
    Arc::new(migrate::RobocopyCopier)
}

#[cfg(target_os = "macos")]
fn real_copier() -> Arc<dyn migrate::Copier> {
    Arc::new(migrate::DittoCopier)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn real_copier() -> Arc<dyn migrate::Copier> {
    Arc::new(migrate::StdCopier)
}

/// macOS 用符号链接代替 junction。
#[cfg(target_os = "macos")]
fn real_links(_runner: Arc<dyn CommandRunner>) -> Arc<dyn LinkMaker> {
    Arc::new(migrate::SymlinkMaker)
}

#[cfg(not(target_os = "macos"))]
fn real_links(runner: Arc<dyn CommandRunner>) -> Arc<dyn LinkMaker> {
    Arc::new(RunnerLinks(runner))
}

fn migrate_parts(manifest_path: PathBuf, runner: Arc<dyn CommandRunner>) -> MigrateParts {
    let env = Env::from_process();
    let dirs = |keys: &[&str]| -> Vec<PathBuf> {
        keys.iter()
            .filter_map(|k| env.get(k).map(PathBuf::from))
            .collect()
    };
    MigrateParts {
        procs: Arc::new(procs::SysinfoProcesses),
        rm: open_file_finder(runner.clone()),
        volumes: Arc::new(migrate::SysVolumes),
        copier: real_copier(),
        mover: Arc::new(migrate::StdMover),
        links: real_links(runner),
        policy_factory: Arc::new(windows_migration_policy),
        manifest_path,
        program_dirs: if IS_MAC {
            vec![PathBuf::from("/Applications")]
        } else {
            dirs(&["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"])
        },
        system_dirs: if IS_MAC {
            vec![PathBuf::from("/System"), PathBuf::from("/Library")]
        } else {
            dirs(&["SystemRoot"])
        },
        unix_links: IS_MAC,
        self_pid: std::process::id(),
        stop_timing: procs::StopTiming::default(),
    }
}

#[cfg(windows)]
fn real_registry() -> Arc<dyn Registry> {
    Arc::new(diskclean_core::registry::WinRegistry)
}

#[cfg(not(windows))]
fn real_registry() -> Arc<dyn Registry> {
    Arc::new(diskclean_core::registry::NoRegistry)
}

/// 由当前设置得到"哪些目录不参与分析"的规则。
fn cloud_rules(state: &AppState) -> cloud::CloudRules {
    let s = state.settings.lock().unwrap();
    cloud::CloudRules::new(s.analyze_cloud, &s.skip_paths, &Env::from_process())
}

async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| ApiError::with("internal", e))?
}

#[tauri::command]
fn list_drives(state: State<'_, AppState>) -> Vec<DriveDto> {
    state.svc.drives()
}

#[tauri::command]
async fn scan_start(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    min_size_mb: u64,
) -> Result<ScanSummary, ApiError> {
    let svc = state.svc.clone();
    let rules = cloud_rules(&state);
    blocking(move || {
        svc.scan_with(
            &path,
            min_size_mb.saturating_mul(1024 * 1024),
            &rules,
            &mut |p| {
                let _ = app.emit("scan-progress", p);
            },
        )
    })
    .await
}

#[tauri::command]
fn scan_current(state: State<'_, AppState>) -> Result<ScanSummary, ApiError> {
    state.svc.scan_current()
}

#[tauri::command]
fn scan_cancel(state: State<'_, AppState>) {
    state.svc.cancel_scan();
}

#[tauri::command]
fn scan_children(state: State<'_, AppState>, parts: Vec<String>) -> Result<ChildrenDto, ApiError> {
    state.svc.children(&parts)
}

#[tauri::command]
fn reveal_in_explorer(state: State<'_, AppState>, parts: Vec<String>) -> Result<(), ApiError> {
    let path = state.svc.resolve_in_scan(&parts)?;
    reveal(&path)
}

#[cfg(windows)]
fn reveal(path: &std::path::Path) -> Result<(), ApiError> {
    use std::os::windows::process::CommandExt;
    let p = service::display_path(path).replace('/', "\\");
    std::process::Command::new("explorer.exe")
        .raw_arg(format!("/select,\"{p}\""))
        .spawn()
        .map(|_| ())
        .map_err(|e| ApiError::with("internal", e))
}

#[cfg(target_os = "macos")]
fn reveal(path: &std::path::Path) -> Result<(), ApiError> {
    // `open -R` 在访达里选中该项目。
    std::process::Command::new("/usr/bin/open")
        .arg("-R")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| ApiError::with("internal", e))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn reveal(_path: &std::path::Path) -> Result<(), ApiError> {
    Err(ApiError::new("unsupported_platform"))
}

#[tauri::command]
fn rules_list(state: State<'_, AppState>) -> Vec<RuleDto> {
    state.svc.rules()
}

#[tauri::command]
async fn plan_build(
    state: State<'_, AppState>,
    rule_ids: Vec<String>,
) -> Result<PlanSummary, ApiError> {
    let svc = state.svc.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || svc.build_plan(&rule_ids, &exclusions)).await
}

#[tauri::command]
fn plan_discard(state: State<'_, AppState>) {
    state.svc.discard_plan();
}

#[tauri::command]
async fn plan_execute(
    app: AppHandle,
    state: State<'_, AppState>,
    dry_run: bool,
    recycle: bool,
) -> Result<ReportDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    blocking(move || {
        svc.execute(ExecRequest { dry_run, recycle }, &journal, &mut |p| {
            let _ = app.emit("clean-progress", p);
        })
    })
    .await
}

#[tauri::command]
fn clean_cancel(state: State<'_, AppState>) {
    state.svc.cancel_clean();
}

#[tauri::command]
async fn dup_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    min_size_mb: u64,
) -> Result<DupSummary, ApiError> {
    let svc = state.svc.clone();
    let rules = cloud_rules(&state);
    blocking(move || {
        svc.dup_scan_with(
            &path,
            min_size_mb.saturating_mul(1024 * 1024),
            &rules,
            &mut |p| {
                let _ = app.emit("dup-progress", p);
            },
        )
    })
    .await
}

#[tauri::command]
fn dup_cancel(state: State<'_, AppState>) {
    state.svc.cancel_dup();
}

#[tauri::command]
fn dup_current(state: State<'_, AppState>) -> Result<DupSummary, ApiError> {
    state.svc.dup_current()
}

#[tauri::command]
async fn dup_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    selections: Vec<DupSelection>,
    recycle: bool,
) -> Result<ReportDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || {
        svc.dup_delete(&selections, recycle, &exclusions, &journal, &mut |p| {
            let _ = app.emit("clean-progress", p);
        })
    })
    .await
}

#[tauri::command]
async fn sys_list(state: State<'_, AppState>) -> Result<Vec<SysActionDto>, ApiError> {
    let svc = state.svc.clone();
    blocking(move || Ok(svc.sys_list())).await
}

#[tauri::command]
async fn sys_run(state: State<'_, AppState>, id: String) -> Result<SysResultDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    blocking(move || svc.sys_run(&id, &journal)).await
}

#[tauri::command]
async fn apps_list(
    state: State<'_, AppState>,
    include_store: bool,
) -> Result<Vec<AppDto>, ApiError> {
    let svc = state.svc.clone();
    blocking(move || svc.apps_list(include_store)).await
}

#[tauri::command]
async fn app_uninstall(
    state: State<'_, AppState>,
    id: usize,
    silent: bool,
) -> Result<UninstallRunDto, ApiError> {
    let svc = state.svc.clone();
    blocking(move || svc.app_uninstall(id, silent)).await
}

#[tauri::command]
async fn app_leftovers(
    state: State<'_, AppState>,
    id: usize,
    forced: bool,
) -> Result<LeftoversDto, ApiError> {
    let svc = state.svc.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || svc.app_leftovers(id, forced, &exclusions)).await
}

#[tauri::command]
async fn app_delete_leftovers(
    state: State<'_, AppState>,
    selected: Vec<usize>,
    recycle: bool,
) -> Result<LeftoverReportDto, ApiError> {
    let svc = state.svc.clone();
    let backup = state.backup_dir.clone();
    let journal = state.journal_path.clone();
    blocking(move || svc.app_delete_leftovers(&selected, recycle, &backup, &journal)).await
}

#[tauri::command]
fn cand_resolve(
    state: State<'_, AppState>,
    items: Vec<Vec<String>>,
) -> Result<Vec<CandResolved>, ApiError> {
    state.svc.cand_resolve(&items)
}

#[tauri::command]
async fn cand_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    items: Vec<Vec<String>>,
    recycle: bool,
) -> Result<ReportDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || {
        svc.cand_delete(&items, recycle, &exclusions, &journal, &mut |p| {
            let _ = app.emit("clean-progress", p);
        })
    })
    .await
}

#[tauri::command]
async fn mig_preflight(
    state: State<'_, AppState>,
    source: String,
    target: String,
) -> Result<PreflightDto, ApiError> {
    let svc = state.svc.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || svc.mig_preflight(&source, &target, &exclusions)).await
}

#[tauri::command]
async fn mig_blockers(state: State<'_, AppState>, dir: String) -> Result<BlockersDto, ApiError> {
    let svc = state.svc.clone();
    blocking(move || svc.mig_blockers(&dir)).await
}

#[tauri::command]
async fn mig_stop(
    state: State<'_, AppState>,
    pids: Vec<u32>,
    include_related: bool,
    force: bool,
) -> Result<Vec<StopResultDto>, ApiError> {
    let svc = state.svc.clone();
    blocking(move || svc.mig_stop(&pids, include_related, force)).await
}

#[tauri::command]
async fn mig_start(
    app: AppHandle,
    state: State<'_, AppState>,
    source: String,
    target: String,
) -> Result<MigrationDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    let exclusions = state.settings.lock().unwrap().exclusions.clone();
    blocking(move || {
        svc.mig_start(
            &source,
            &target,
            &exclusions,
            &journal,
            &mut |p: MigProgressDto| {
                let _ = app.emit("mig-progress", p);
            },
        )
    })
    .await
}

#[tauri::command]
fn mig_cancel(state: State<'_, AppState>) {
    state.svc.mig_cancel();
}

#[tauri::command]
fn mig_list(state: State<'_, AppState>) -> Result<Vec<MigrationDto>, ApiError> {
    state.svc.mig_list()
}

#[tauri::command]
async fn mig_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<MigrationDto, ApiError> {
    let svc = state.svc.clone();
    let journal = state.journal_path.clone();
    blocking(move || {
        svc.mig_restore(&id, &journal, &mut |p: MigProgressDto| {
            let _ = app.emit("mig-progress", p);
        })
    })
    .await
}

#[derive(serde::Serialize)]
struct AppStatus {
    /// 当前进程是否以管理员身份运行（Windows 才有意义；其他平台恒为 `true`）。
    elevated: bool,
    /// `windows` / `macos` / `other`。界面据此调整文案与默认值。
    platform: &'static str,
    /// 用户主目录（Windows 为用户配置文件目录）。
    home: String,
    /// macOS：是否已授予"完全磁盘访问权限"；其他平台为 `None`。
    full_disk_access: Option<bool>,
}

/// macOS 的"完全磁盘访问权限"检测：能打开受 TCC 保护的数据库就说明已授权。
/// 没有这个权限时，`~/Library` 下的邮件、信息、Safari 等目录读不到，扫描结果会偏小。
#[cfg(target_os = "macos")]
fn full_disk_access() -> Option<bool> {
    Some(std::fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db").is_ok())
}

#[cfg(not(target_os = "macos"))]
fn full_disk_access() -> Option<bool> {
    None
}

#[tauri::command]
fn app_status() -> AppStatus {
    AppStatus {
        elevated: elevation::is_elevated(),
        platform: if cfg!(windows) {
            "windows"
        } else if IS_MAC {
            "macos"
        } else {
            "other"
        },
        home: std::env::var(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).unwrap_or_default(),
        full_disk_access: full_disk_access(),
    }
}

/// 打开系统设置里的"完全磁盘访问权限"页面（macOS）。
#[tauri::command]
fn open_privacy_settings() -> Result<(), ApiError> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/bin/open")
            .arg("x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")
            .spawn()
            .map(|_| ())
            .map_err(|e| ApiError::with("internal", e))
    }
    #[cfg(not(target_os = "macos"))]
    Err(ApiError::new("unsupported_platform"))
}

/// 以管理员身份重新启动：弹出 UAC，用户同意后启动新实例并退出当前进程；
/// 用户拒绝时返回错误，当前窗口保持不变。
#[tauri::command]
fn relaunch_as_admin(app: AppHandle) -> Result<(), ApiError> {
    match elevation::relaunch_elevated() {
        Ok(()) => {
            app.exit(0);
            Ok(())
        }
        Err(elevation::RelaunchError::Cancelled) => Err(ApiError::new("uac_cancelled")),
        Err(elevation::RelaunchError::Unsupported) => Err(ApiError::new("unsupported_platform")),
        Err(elevation::RelaunchError::Failed(m)) => Err(ApiError::with("relaunch_failed", m)),
    }
}

#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
fn settings_set_cloud(
    state: State<'_, AppState>,
    analyze_cloud: bool,
    skip_paths: Vec<String>,
) -> Result<Settings, ApiError> {
    let skip_paths: Vec<String> = skip_paths
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    // 跳过路径必须是带盘符的完整路径，否则永远匹配不到，静默无效比报错更糟。
    for p in &skip_paths {
        let valid = if IS_MAC {
            p.starts_with('/')
        } else {
            diskclean_core::mft::split_drive_path(p).is_some()
        };
        if !valid {
            return Err(ApiError::with("invalid_skip_path", p));
        }
    }
    let mut guard = state.settings.lock().unwrap();
    let next = Settings {
        analyze_cloud,
        skip_paths,
        ..guard.clone()
    };
    next.save(&state.settings_path)
        .map_err(|e| ApiError::with("settings_failed", e))?;
    *guard = next.clone();
    Ok(next)
}

#[tauri::command]
fn settings_set_exclusions(
    state: State<'_, AppState>,
    exclusions: Vec<String>,
) -> Result<Settings, ApiError> {
    for x in &exclusions {
        state.svc.validate_exclusion(x)?;
    }
    let mut guard = state.settings.lock().unwrap();
    let next = Settings {
        exclusions,
        ..guard.clone()
    };
    next.save(&state.settings_path)
        .map_err(|e| ApiError::with("settings_failed", e))?;
    *guard = next.clone();
    Ok(next)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // macOS：按实际占用统计大小（稀疏文件、压缩文件、虚拟机镜像的逻辑大小会严重失真）。
    diskclean_core::scanner::use_allocated_sizes(IS_MAC);
    tauri::Builder::default()
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let data_dir = app.path().app_data_dir()?;
            let settings_path = config_dir.join("settings.json");
            let settings = Settings::load(&settings_path);
            let svc = Service::new(
                if IS_MAC { mac_rules() } else { windows_rules() },
                Env::from_process(),
                Box::new(windows_policy),
                fast_scan(),
            )
            .with_system(
                Arc::new(diskclean_core::sysaction::SystemRunner),
                Box::new(windows_selected_policy),
            )
            .with_uninstall(
                real_registry(),
                Box::new(windows_leftover_policy),
                FsRoots::from_env(&Env::from_process()),
            )
            .with_migrate(migrate_parts(
                data_dir.join("migrations.json"),
                Arc::new(diskclean_core::sysaction::SystemRunner),
            ));
            let svc = if IS_MAC {
                svc.with_mac(service::MacConfig {
                    home: mac_home().unwrap_or_default(),
                    app_roots: diskclean_core::macapps::app_roots(&mac_home().unwrap_or_default()),
                    trash: Arc::new(diskclean_core::macapps::move_to_trash),
                })
            } else {
                svc
            };
            // 上次被中断的迁移：根据磁盘上的实际状态回滚或补记完成。
            let _ = svc.mig_recover();
            app.manage(AppState {
                svc: Arc::new(svc),
                settings: Mutex::new(settings),
                settings_path,
                journal_path: data_dir.join("journal.jsonl"),
                backup_dir: data_dir.join("registry-backups"),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_drives,
            scan_start,
            scan_cancel,
            scan_current,
            scan_children,
            reveal_in_explorer,
            rules_list,
            plan_build,
            plan_discard,
            plan_execute,
            clean_cancel,
            dup_scan,
            dup_cancel,
            dup_current,
            dup_delete,
            sys_list,
            sys_run,
            apps_list,
            app_uninstall,
            app_leftovers,
            app_delete_leftovers,
            cand_resolve,
            cand_delete,
            mig_preflight,
            mig_blockers,
            mig_stop,
            mig_start,
            mig_cancel,
            mig_list,
            mig_restore,
            app_status,
            open_privacy_settings,
            relaunch_as_admin,
            settings_get,
            settings_set_exclusions,
            settings_set_cloud,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DiskClean");
}
