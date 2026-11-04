mod service;
mod settings;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use diskclean_core::builtin::windows_rules;
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

/// 生产环境的安全策略：Windows 默认保护名单 + 用户排除项。
fn windows_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let policy = SafetyPolicy::new(&dirs).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 用户亲自选中文件时的策略（删除重复文件）：不保护用户文档，但系统和 AppData 仍受保护。
fn windows_selected_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let policy = SafetyPolicy::for_user_selected(&dirs).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 删除卸载残留时的策略：默认保护名单 + 应用常驻目录的内部 + 用户排除项。
fn windows_leftover_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let roots = FsRoots::from_env(&Env::from_process());
    let policy =
        uninstall::leftover_policy(&dirs, &roots).map_err(|e| ApiError::with("policy", e))?;
    with_exclusions(policy, exclusions)
}

/// 目录迁移的安全策略：系统目录和用户根目录本身禁止，应用数据等子目录允许。
fn windows_migration_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
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
fn open_file_finder() -> Arc<dyn procs::OpenFileFinder> {
    Arc::new(procs::RestartManager)
}

#[cfg(not(windows))]
fn open_file_finder() -> Arc<dyn procs::OpenFileFinder> {
    Arc::new(procs::NoOpenFileFinder)
}

/// Windows 用 robocopy（保留 ACL 与所有者）；其他平台用纯 Rust 复制。
#[cfg(windows)]
fn real_copier() -> Arc<dyn migrate::Copier> {
    Arc::new(migrate::RobocopyCopier)
}

#[cfg(not(windows))]
fn real_copier() -> Arc<dyn migrate::Copier> {
    Arc::new(migrate::StdCopier)
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
        rm: open_file_finder(),
        volumes: Arc::new(migrate::SysVolumes),
        copier: real_copier(),
        mover: Arc::new(migrate::StdMover),
        links: Arc::new(RunnerLinks(runner)),
        policy_factory: Arc::new(windows_migration_policy),
        manifest_path,
        program_dirs: dirs(&["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]),
        system_dirs: dirs(&["SystemRoot"]),
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
) -> Result<ScanSummary, ApiError> {
    let svc = state.svc.clone();
    let rules = cloud_rules(&state);
    blocking(move || {
        svc.scan_with(&path, &rules, &mut |p| {
            let _ = app.emit("scan-progress", p);
        })
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

#[cfg(not(windows))]
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
        if diskclean_core::mft::split_drive_path(p).is_none() {
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
    tauri::Builder::default()
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let data_dir = app.path().app_data_dir()?;
            let settings_path = config_dir.join("settings.json");
            let settings = Settings::load(&settings_path);
            let svc = Service::new(
                windows_rules(),
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
            settings_get,
            settings_set_exclusions,
            settings_set_cloud,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DiskClean");
}
