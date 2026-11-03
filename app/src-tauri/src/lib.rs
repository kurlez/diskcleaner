mod service;
mod settings;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use diskclean_core::builtin::windows_rules;
use diskclean_core::rules::Env;
use diskclean_core::safety::{KnownDirs, SafetyPolicy};
use tauri::{AppHandle, Emitter, Manager, State};

use service::{
    ApiError, ChildrenDto, DriveDto, ExecRequest, PlanSummary, ReportDto, RuleDto, ScanSummary,
    Service,
};
use settings::Settings;

struct AppState {
    svc: Arc<Service>,
    settings: Mutex<Settings>,
    settings_path: PathBuf,
    journal_path: PathBuf,
}

/// 生产环境的安全策略：Windows 默认保护名单 + 用户排除项。
fn windows_policy(exclusions: &[String]) -> Result<SafetyPolicy, ApiError> {
    let dirs = KnownDirs::from_env().ok_or(ApiError::new("unsupported_platform"))?;
    let mut policy = SafetyPolicy::new(&dirs).map_err(|e| ApiError::with("policy", e))?;
    for x in exclusions {
        policy
            .exclude(x)
            .map_err(|e| ApiError::with("invalid_exclusion", format!("{x}: {e}")))?;
    }
    Ok(policy)
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
            );
            app.manage(AppState {
                svc: Arc::new(svc),
                settings: Mutex::new(settings),
                settings_path,
                journal_path: data_dir.join("journal.jsonl"),
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
            settings_get,
            settings_set_exclusions,
        ])
        .run(tauri::generate_context!())
        .expect("error while running DiskClean");
}
