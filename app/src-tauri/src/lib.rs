mod service;
mod settings;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use diskclean_core::builtin::windows_rules;
use diskclean_core::registry::Registry;
use diskclean_core::rules::Env;
use diskclean_core::safety::{KnownDirs, SafetyPolicy};
use diskclean_core::uninstall::{self, FsRoots};
use tauri::{AppHandle, Emitter, Manager, State};

use service::{
    ApiError, AppDto, ChildrenDto, DriveDto, DupSelection, DupSummary, ExecRequest,
    LeftoverReportDto, LeftoversDto, PlanSummary, ReportDto, RuleDto, ScanSummary, Service,
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

#[cfg(windows)]
fn real_registry() -> Arc<dyn Registry> {
    Arc::new(diskclean_core::registry::WinRegistry)
}

#[cfg(not(windows))]
fn real_registry() -> Arc<dyn Registry> {
    Arc::new(diskclean_core::registry::NoRegistry)
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
    blocking(move || {
        svc.scan(&path, &mut |p| {
            let _ = app.emit("scan-progress", p);
        })
    })
    .await
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
    blocking(move || {
        svc.dup_scan(&path, min_size_mb.saturating_mul(1024 * 1024), &mut |p| {
            let _ = app.emit("dup-progress", p);
        })
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
fn settings_get(state: State<'_, AppState>) -> Settings {
    state.settings.lock().unwrap().clone()
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
    let next = Settings { exclusions };
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
            );
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
            settings_get,
            settings_set_exclusions,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DiskClean");
}
