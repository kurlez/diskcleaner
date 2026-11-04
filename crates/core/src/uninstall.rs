//! 应用卸载与残留清理：列出已装程序 → 运行它自带的卸载器 → 扫描残留的
//! 文件夹、快捷方式与注册表项 → 用户确认 → 备份注册表后删除。
//!
//! 设计原则（比"能删就删"更保守）：
//! * **程序还登记在系统里时，不扫描残留**（除非用户明确选择"强制删除"），
//!   避免把还在使用的程序当成残留。
//! * 残留只来自**名称/路径匹配**，并标注置信度；只有高置信度项默认勾选。
//! * 注册表删除只允许白名单位置（见 [`crate::registry`]），文件删除沿用安全策略。
//! * 删注册表**之前先导出标准 `.reg` 备份**，备份失败则整体中止，什么都不删。
//! * 注册表被改动过的项（服务重新出现、COM 注册指向了别处）在删除时会重新校验，不符就拒绝。

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::cleaner::{execute_with, ExecOptions, Report};
use crate::plan::{measure_path, Candidate, Plan, PlanSkipReason};
use crate::registry::{
    check_delete_key, check_delete_value, check_delete_vendor_root, export_keys, export_values,
    to_utf16le_with_bom, Hive, RegValue, Registry,
};
use crate::rules::{Disposal, Env};
use crate::safety::{KnownDirs, SafetyPolicy};
use crate::scanner::special_reason;
use crate::sysaction::CommandRunner;

// ====================================================================
// 已装程序
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppSource {
    /// 在 `...\Uninstall\<key>` 下登记的传统程序。
    Registry { hive: Hive, key: String },
    /// Microsoft Store（AppX/MSIX）应用。
    Appx { package_full_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledApp {
    pub source: AppSource,
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<String>,
    /// 原始安装日期（通常是 `YYYYMMDD`）。
    pub install_date: Option<String>,
    pub size_kb: Option<u64>,
    pub uninstall_string: Option<String>,
    pub quiet_uninstall_string: Option<String>,
    pub display_icon: Option<String>,
    pub windows_installer: bool,
}

const UNINSTALL_PATH: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const UNINSTALL_PATH_WOW: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

fn nonempty(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// 枚举注册表里登记的已装程序，并过滤掉系统组件和更新补丁。
pub fn enumerate_apps(reg: &dyn Registry) -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    for (hive, root) in [
        (Hive::LocalMachine, UNINSTALL_PATH),
        (Hive::LocalMachine, UNINSTALL_PATH_WOW),
        (Hive::CurrentUser, UNINSTALL_PATH),
    ] {
        let Ok(keys) = reg.subkeys(hive, root) else {
            continue;
        };
        for key in keys {
            let path = format!("{root}\\{key}");
            let Ok(values) = reg.values(hive, &path) else {
                continue;
            };
            let get = |name: &str| -> Option<&RegValue> {
                values
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            };
            let text = |name: &str| nonempty(get(name).and_then(RegValue::as_string));
            let dword = |name: &str| get(name).and_then(RegValue::as_dword);

            let Some(name) = text("DisplayName") else {
                continue;
            };
            // 系统组件、更新补丁（有父程序或属于更新类型）不在"已装程序"里展示。
            if dword("SystemComponent") == Some(1) || get("ParentKeyName").is_some() {
                continue;
            }
            let release = text("ReleaseType").unwrap_or_default().to_lowercase();
            if ["security update", "update rollup", "hotfix", "service pack"]
                .contains(&release.as_str())
            {
                continue;
            }
            apps.push(InstalledApp {
                source: AppSource::Registry {
                    hive,
                    key: key.clone(),
                },
                name,
                version: text("DisplayVersion"),
                publisher: text("Publisher"),
                install_location: text("InstallLocation"),
                install_date: text("InstallDate"),
                size_kb: dword("EstimatedSize").map(u64::from),
                uninstall_string: text("UninstallString"),
                quiet_uninstall_string: text("QuietUninstallString"),
                display_icon: text("DisplayIcon"),
                windows_installer: dword("WindowsInstaller") == Some(1),
            });
        }
    }
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

// ----- Microsoft Store 应用 -----

/// 列出可卸载的 Store 应用的 PowerShell 参数（输出 UTF-8 JSON）。
pub const APPX_LIST_ARGS: &[&str] = &[
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
     Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable } | \
     Select-Object Name,PackageFullName,Publisher,Version,InstallLocation | ConvertTo-Json -Compress",
];

/// `PackageFullName` 只含字母、数字和 `. _ ~ -`，据此拒绝一切可能被注入命令的内容。
pub fn is_safe_package_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'))
}

/// 解析 `Get-AppxPackage | ConvertTo-Json` 的输出（单个包时是对象，多个时是数组）。
pub fn parse_appx_json(json: &str) -> Vec<InstalledApp> {
    let json = json.trim().trim_start_matches('\u{feff}');
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let items = match v {
        serde_json::Value::Array(a) => a,
        o @ serde_json::Value::Object(_) => vec![o],
        _ => return Vec::new(),
    };
    let field = |o: &serde_json::Value, k: &str| {
        nonempty(o.get(k).and_then(|x| x.as_str()).map(str::to_string))
    };
    let mut apps: Vec<InstalledApp> = items
        .iter()
        .filter_map(|o| {
            let name = field(o, "Name")?;
            let full = field(o, "PackageFullName")?;
            if !is_safe_package_name(&full) {
                return None;
            }
            Some(InstalledApp {
                source: AppSource::Appx {
                    package_full_name: full,
                },
                name,
                version: field(o, "Version"),
                publisher: field(o, "Publisher"),
                install_location: field(o, "InstallLocation"),
                install_date: None,
                size_kb: None,
                uninstall_string: None,
                quiet_uninstall_string: None,
                display_icon: None,
                windows_installer: false,
            })
        })
        .collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

// ====================================================================
// 运行卸载器
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UninstallError {
    /// 没有登记卸载命令（可用"强制删除"）。
    NoUninstaller,
    /// 命令行为空、过长或含换行/NUL。
    InvalidCommand,
    /// 命令无法启动或运行出错。
    Failed(String),
}

impl fmt::Display for UninstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UninstallError::NoUninstaller => {
                write!(f, "this program has no registered uninstaller")
            }
            UninstallError::InvalidCommand => {
                write!(f, "the registered uninstall command is invalid")
            }
            UninstallError::Failed(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for UninstallError {}

/// 把 `MsiExec /I{GUID}`（修改/修复）改成 `/X{GUID}`（卸载）。
fn msi_to_uninstall(cmd: &str) -> String {
    let lower = cmd.to_lowercase();
    if !lower.contains("msiexec") {
        return cmd.to_string();
    }
    match lower.find("/i{") {
        Some(i) => format!("{}/X{}", &cmd[..i], &cmd[i + 2..]),
        None => cmd.to_string(),
    }
}

fn valid_command(cmd: &str) -> bool {
    let c = cmd.trim();
    !c.is_empty() && c.len() <= 4096 && !c.chars().any(|ch| ch == '\0' || ch == '\r' || ch == '\n')
}

/// 选出要执行的卸载命令。`silent` 为真时优先用静默卸载命令。
pub fn uninstall_command(app: &InstalledApp, silent: bool) -> Result<String, UninstallError> {
    let AppSource::Registry { key, .. } = &app.source else {
        return Err(UninstallError::NoUninstaller);
    };
    let pick = if silent {
        app.quiet_uninstall_string
            .as_ref()
            .or(app.uninstall_string.as_ref())
    } else {
        app.uninstall_string
            .as_ref()
            .or(app.quiet_uninstall_string.as_ref())
    };
    let cmd = match pick {
        Some(c) => msi_to_uninstall(c.trim()),
        // 没有登记命令但键名是 MSI 产品代码：用 msiexec 直接卸载。
        None if app.windows_installer && key.starts_with('{') && key.ends_with('}') => {
            format!("MsiExec.exe /X{key}")
        }
        None => return Err(UninstallError::NoUninstaller),
    };
    if valid_command(&cmd) {
        Ok(cmd)
    } else {
        Err(UninstallError::InvalidCommand)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallRun {
    pub exit_code: i32,
    /// 运行结束后它是否仍登记在系统里（卸载器可能被取消，或只是启动了一个后台进程就退出了）。
    pub still_registered: bool,
}

/// 运行程序自带的卸载器并等它结束，然后检查它是否还登记在系统里。
pub fn run_uninstaller(
    app: &InstalledApp,
    silent: bool,
    runner: &dyn CommandRunner,
    reg: &dyn Registry,
) -> Result<UninstallRun, UninstallError> {
    let out = match &app.source {
        AppSource::Registry { .. } => {
            let cmd = uninstall_command(app, silent)?;
            runner
                .run_shell(&cmd)
                .map_err(|e| UninstallError::Failed(e.to_string()))?
        }
        AppSource::Appx { package_full_name } => {
            if !is_safe_package_name(package_full_name) {
                return Err(UninstallError::InvalidCommand);
            }
            let script = format!("Remove-AppxPackage -Package '{package_full_name}'");
            runner
                .run(
                    "powershell.exe",
                    &["-NoProfile", "-NonInteractive", "-Command", &script],
                )
                .map_err(|e| UninstallError::Failed(e.to_string()))?
        }
    };
    Ok(UninstallRun {
        exit_code: out.code,
        still_registered: is_registered(app, reg),
    })
}

/// 程序是否还登记在系统里。Store 应用没有注册表登记项，需要重新列举才能知道，这里返回 `false`。
pub fn is_registered(app: &InstalledApp, reg: &dyn Registry) -> bool {
    match &app.source {
        AppSource::Registry { hive, key } => {
            let root = if *hive == Hive::LocalMachine && app_in_wow(app, reg) {
                UNINSTALL_PATH_WOW
            } else {
                UNINSTALL_PATH
            };
            reg.key_exists(*hive, &format!("{root}\\{key}"))
        }
        AppSource::Appx { .. } => false,
    }
}

/// 登记项实际所在的路径（普通或 WOW6432Node）。
fn registered_path(app: &InstalledApp, reg: &dyn Registry) -> Option<(Hive, String)> {
    let AppSource::Registry { hive, key } = &app.source else {
        return None;
    };
    [UNINSTALL_PATH, UNINSTALL_PATH_WOW]
        .iter()
        .map(|root| format!("{root}\\{key}"))
        .find(|p| reg.key_exists(*hive, p))
        .map(|p| (*hive, p))
}

fn app_in_wow(app: &InstalledApp, reg: &dyn Registry) -> bool {
    let AppSource::Registry { hive, key } = &app.source else {
        return false;
    };
    !reg.key_exists(*hive, &format!("{UNINSTALL_PATH}\\{key}"))
        && reg.key_exists(*hive, &format!("{UNINSTALL_PATH_WOW}\\{key}"))
}

// ====================================================================
// 名称匹配
// ====================================================================

/// 只保留字母数字并转成小写，用来比较 "Foo Bar" 与 "foo-bar" 这类写法差异。
pub fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_version_token(t: &str) -> bool {
    let t = t
        .trim_matches(|c| c == '(' || c == ')' || c == ',')
        .to_lowercase();
    if [
        "x64", "x86", "64-bit", "32-bit", "64bit", "32bit", "version", "build", "beta", "release",
    ]
    .contains(&t.as_str())
    {
        return true;
    }
    let t = t.strip_prefix('v').unwrap_or(&t);
    !t.is_empty()
        && t.chars().next().is_some_and(|c| c.is_ascii_digit())
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn long_enough(n: &str) -> bool {
    let count = n.chars().count();
    count >= 3 || (count >= 2 && !n.is_ascii())
}

/// 程序名可能带来的目录名写法：完整名，以及去掉版本号/架构后缀的名字。
pub fn name_variants(name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |n: String| {
        if long_enough(&n) && !out.contains(&n) {
            out.push(n);
        }
    };
    push(normalize(name));
    let tokens: Vec<&str> = name.split_whitespace().collect();
    let mut end = tokens.len();
    while end > 1 && is_version_token(tokens[end - 1]) {
        end -= 1;
    }
    push(normalize(&tokens[..end].join(" ")));
    out
}

/// 厂商名常带公司后缀（`Google LLC`、`Foo Inc.`），比较前先去掉。
pub fn publisher_norm(p: &str) -> String {
    const SUFFIXES: &[&str] = &[
        "inc",
        "llc",
        "ltd",
        "limited",
        "corp",
        "corporation",
        "co",
        "company",
        "gmbh",
        "ag",
        "sa",
        "bv",
        "plc",
        "oy",
        "ab",
        "pty",
        "pte",
        "sarl",
        "srl",
        "kk",
        "s.a.",
        "kg",
        "ou",
    ];
    let tokens: Vec<&str> = p.split_whitespace().collect();
    let mut end = tokens.len();
    while end > 1 {
        let t = tokens[end - 1]
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        if SUFFIXES.contains(&t.as_str()) {
            end -= 1;
        } else {
            break;
        }
    }
    normalize(&tokens[..end].join(" "))
}

/// 在厂商自己的目录/键**里面**匹配产品名时用的写法：额外去掉程序名开头的厂商名
/// （程序 `Acme Widget`、厂商 `Acme`，目录是 `Acme\Widget`）。
/// 这种宽松写法只能用在厂商目录内部，顶层目录仍然只做严格匹配。
fn inner_variants(variants: &[String], pub_norm: Option<&str>) -> Vec<String> {
    let mut v = variants.to_vec();
    if let Some(p) = pub_norm {
        for name in variants {
            if let Some(rest) = name.strip_prefix(p) {
                if long_enough(rest) && !v.iter().any(|x| x == rest) {
                    v.push(rest.to_string());
                }
            }
        }
    }
    v
}

// ====================================================================
// 残留扫描
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    InstallLocation,
    NameMatch,
    PublisherEmptied,
    UninstallEntry,
    AppPath,
    AutoRun,
    StaleService,
    ComRegistration,
    Shortcut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// 普通键（路径至少两级，或白名单里的固定形状）。
    Normal,
    /// 以程序名命名的厂商根键（`SOFTWARE\<程序名>`）。
    OwnedRoot,
    /// 厂商根键（`SOFTWARE\<厂商>`），仅当其中只剩本程序的内容时才会列出；
    /// 删除时会再次确认它已经没有其他内容。
    EmptiedVendorRoot,
}

/// 删除前必须重新满足的条件：扫描之后注册表可能又被改过。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyGuard {
    /// 服务的映像文件仍然不存在，且仍指向 `dir`。
    ServiceImageMissing { dir: String },
    /// COM 注册的服务器路径仍指向 `dir`。
    ComRefers { dir: String },
    /// App Paths 条目仍指向 `dir`。
    AppPathRefers { dir: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Path {
        path: PathBuf,
        is_dir: bool,
        size: u64,
        files: u64,
    },
    Key {
        hive: Hive,
        path: String,
        kind: KeyKind,
        guard: Option<KeyGuard>,
    },
    Value {
        hive: Hive,
        path: String,
        name: String,
        dir: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leftover {
    pub target: Target,
    pub confidence: Confidence,
    pub reason: Reason,
}

#[derive(Debug, Clone, Default)]
pub struct LeftoverScan {
    pub items: Vec<Leftover>,
    /// 程序仍登记在系统里（且没有选择强制删除）：此时不会给出任何残留。
    pub still_registered: bool,
    /// 识别出的安装目录（已通过安全校验）。
    pub install_dir: Option<PathBuf>,
}

/// 扫描残留时用到的文件系统位置。
#[derive(Debug, Clone, Default)]
pub struct FsRoots {
    pub program_files: Vec<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub roaming: Option<PathBuf>,
    pub local: Option<PathBuf>,
    pub local_low: Option<PathBuf>,
    /// `%LOCALAPPDATA%\Programs`（用户级安装的程序）。
    pub local_programs: Option<PathBuf>,
    pub start_menu: Vec<PathBuf>,
    pub desktops: Vec<PathBuf>,
}

impl FsRoots {
    pub fn from_env(env: &Env) -> Self {
        let p = |k: &str| env.get(k).map(PathBuf::from);
        let mut program_files: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
            .iter()
            .filter_map(|k| p(k))
            .collect();
        program_files.sort();
        program_files.dedup();
        let profile = p("USERPROFILE");
        let local = p("LOCALAPPDATA");
        let roaming = p("APPDATA");
        let program_data = p("ProgramData");
        let mut start_menu = Vec::new();
        if let Some(d) = &program_data {
            start_menu.push(d.join("Microsoft/Windows/Start Menu/Programs"));
        }
        if let Some(d) = &roaming {
            start_menu.push(d.join("Microsoft/Windows/Start Menu/Programs"));
        }
        let mut desktops = Vec::new();
        if let Some(d) = p("PUBLIC") {
            desktops.push(d.join("Desktop"));
        }
        if let Some(d) = &profile {
            desktops.push(d.join("Desktop"));
        }
        Self {
            program_files,
            program_data,
            roaming,
            local_programs: local.as_ref().map(|l| l.join("Programs")),
            local_low: profile.as_ref().map(|u| u.join("AppData/LocalLow")),
            local,
            start_menu,
            desktops,
        }
    }

    /// 在其下一层目录中寻找残留的根目录。
    fn app_roots(&self) -> Vec<&Path> {
        let mut v: Vec<&Path> = self.program_files.iter().map(PathBuf::as_path).collect();
        for p in [
            &self.program_data,
            &self.roaming,
            &self.local,
            &self.local_low,
            &self.local_programs,
        ]
        .into_iter()
        .flatten()
        {
            v.push(p);
        }
        v
    }
}

/// 无论名称是否匹配，永远不会作为残留列出（也不允许删除）的目录名（小写）。
const RESERVED_DIRS: &[&str] = &[
    "microsoft",
    "microsoft office",
    "microsoft shared",
    "microsoft visual studio",
    "microsoft sql server",
    "microsoft.net",
    "windows",
    "windows kits",
    "windows nt",
    "windowsapps",
    "common files",
    "packages",
    "temp",
    "programs",
    "modifiablewindowsapps",
    "uninstall information",
    "windowspowershell",
    "windows defender",
    "windows mail",
    "windows media player",
    "windows photo viewer",
    "internet explorer",
    "reference assemblies",
    "msbuild",
    "dotnet",
    "iis",
    "intel",
    "amd",
    "nvidia corporation",
    "nvidia",
    "package cache",
    "connecteddevicesplatform",
    "d3dscache",
    "history",
    "tempstates",
];

fn is_reserved_dir(name: &str) -> bool {
    let l = name.to_lowercase();
    RESERVED_DIRS.contains(&l.as_str()) || l.starts_with("microsoft ") || l.starts_with("windows ")
}

/// 删除残留文件时使用的安全策略：在默认保护名单的基础上，只放开应用常驻的几个根目录
/// 的**内部**，并把系统自带的子目录重新保护起来。
pub fn leftover_policy(
    dirs: &KnownDirs,
    roots: &FsRoots,
) -> Result<SafetyPolicy, crate::safety::Denied> {
    let mut p = SafetyPolicy::new(dirs)?;
    let to_s = |x: &Path| x.to_string_lossy().into_owned();
    for r in roots
        .app_roots()
        .into_iter()
        .chain(roots.start_menu.iter().map(PathBuf::as_path))
        .chain(roots.desktops.iter().map(PathBuf::as_path))
    {
        p.allow_root(&to_s(r))?;
    }
    for r in roots.app_roots() {
        for name in RESERVED_DIRS {
            p.protect(&to_s(&r.join(name)))?;
        }
    }
    Ok(p)
}

fn dirs_in(root: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut v: Vec<_> = rd
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            (m.is_dir() && special_reason(&m).is_none())
                .then(|| (e.file_name().to_string_lossy().into_owned(), e.path()))
        })
        .collect();
    v.sort();
    v
}

fn stem_lower(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

/// 目录名与程序名的匹配强度。
fn match_strength(
    folder: &str,
    variants: &[String],
    install_leaf: Option<&str>,
) -> Option<Confidence> {
    let n = normalize(folder);
    if !long_enough(&n) {
        return None;
    }
    if variants.contains(&n) || install_leaf.is_some_and(|l| long_enough(l) && l == n) {
        return Some(Confidence::High);
    }
    // 目录名只是程序名的一部分（如程序 "Google Chrome"，目录 "Chrome"），把握较小。
    if n.chars().count() >= 5 && variants.iter().any(|v| v.contains(&n)) {
        return Some(Confidence::Medium);
    }
    None
}

/// `data` 里是否引用了目录 `dir`（按路径边界匹配，`C:\Foo` 不会匹配 `C:\Foobar`）。
pub fn path_refers_to(data: &str, dir: &str) -> bool {
    let norm_p = |s: &str| s.replace('/', "\\").to_lowercase();
    let d = norm_p(dir);
    let d = d.trim_matches('"').trim_end_matches('\\');
    if d.len() < 4 {
        return false;
    }
    let hay = norm_p(data);
    let mut start = 0;
    while let Some(i) = hay[start..].find(d) {
        let at = start + i;
        let before = hay[..at].chars().next_back();
        let after = hay[at + d.len()..].chars().next();
        let before_ok =
            before.is_none_or(|c| matches!(c, '"' | ' ' | '=' | ',' | ';' | '\'' | '@'));
        let after_ok = after.is_none_or(|c| matches!(c, '\\' | '"' | ' ' | ',' | ';' | '\''));
        if before_ok && after_ok {
            return true;
        }
        start = at + hay[at..].chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// 把 `%VAR%` 展开成环境变量的值；没有定义的变量保持原样。
fn expand_lenient(env: &Env, s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        match after.find('%') {
            Some(j) if j > 0 => {
                match env.get(&after[..j]) {
                    Some(v) => out.push_str(v),
                    None => out.push_str(&rest[i..i + j + 2]),
                }
                rest = &after[j + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// 从服务的 `ImagePath` 里取出可执行文件路径；只认带盘符的绝对路径。
pub fn extract_exe_path(image_path: &str) -> Option<String> {
    let s = image_path.trim();
    let candidate = if let Some(rest) = s.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let lower = s.to_lowercase();
        let end = [".exe", ".sys", ".dll"]
            .iter()
            .filter_map(|e| lower.find(e).map(|i| i + e.len()))
            .min()
            .unwrap_or_else(|| s.split_whitespace().next().map_or(0, str::len));
        s[..end].to_string()
    };
    let b = candidate.as_bytes();
    // 绝对路径：带盘符，或以 `/` 开头（非 Windows 平台上的测试环境）。
    let drive_abs = b.len() > 3
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/');
    (drive_abs || candidate.starts_with('/')).then_some(candidate)
}

/// 命令行（或 `DisplayIcon`）开头的可执行文件/图标路径：带引号取引号内，否则取到 `.exe`/`.ico` 为止或第一个空白。
/// 与 [`extract_exe_path`] 不同，这里不要求盘符。
fn leading_executable(s: &str) -> Option<String> {
    let t = s.trim();
    let raw = if let Some(rest) = t.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let lower = t.to_lowercase();
        let end = [".exe", ".ico", ".dll", ".msi"]
            .iter()
            .filter_map(|e| lower.find(e).map(|i| i + e.len()))
            .min()
            .unwrap_or_else(|| t.split_whitespace().next().map_or(0, str::len));
        t[..end].to_string()
    };
    // `C:\Foo\a.exe,0` 里逗号后的图标序号不是路径的一部分。
    let raw = match raw.rsplit_once(',') {
        Some((p, idx))
            if idx
                .trim()
                .trim_start_matches('-')
                .chars()
                .all(|c| c.is_ascii_digit())
                && !idx.trim().is_empty() =>
        {
            p.to_string()
        }
        _ => raw,
    };
    let raw = raw.trim().to_string();
    (!raw.is_empty()).then_some(raw)
}

fn last_component(p: &str) -> String {
    normalize(
        p.trim_end_matches(['\\', '/'])
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(""),
    )
}

/// 从登记信息里推断安装目录，并用安全策略确认它可以被删除。
fn detect_install_dir(app: &InstalledApp, env: &Env, policy: &SafetyPolicy) -> Option<PathBuf> {
    let clean = |s: &str| {
        expand_lenient(
            env,
            s.trim().trim_matches('"').trim_end_matches(['\\', '/']),
        )
    };
    let mut candidates: Vec<String> = Vec::new();
    if let Some(l) = &app.install_location {
        candidates.push(clean(l));
    }
    // 没有 InstallLocation 时，用图标或卸载程序所在的目录。
    for s in [&app.display_icon, &app.uninstall_string]
        .into_iter()
        .flatten()
    {
        let Some(exe) = leading_executable(s) else {
            continue;
        };
        let exe = clean(&exe);
        if let Some(parent) = Path::new(&exe.replace('\\', "/")).parent() {
            candidates.push(parent.to_string_lossy().into_owned());
        }
    }
    candidates
        .into_iter()
        .filter(|c| !c.is_empty())
        .find_map(|c| {
            // 只接受通过安全策略的目录：系统目录、用户文档、安装根目录本身一律不行。
            policy.check_delete(&c).ok().map(|_| PathBuf::from(c))
        })
}

fn dir_leftover(path: &Path, confidence: Confidence, reason: Reason) -> Option<Leftover> {
    // 子树内有 .git、云占位文件等不适合删除的内容时，整项放弃。
    let stats = measure_path(path).ok()?;
    if let Some(b) = &stats.blocker {
        let _ = matches!(b, PlanSkipReason::ProtectedInside(_));
        return None;
    }
    Some(Leftover {
        target: Target::Path {
            path: path.to_path_buf(),
            is_dir: true,
            size: stats.size,
            files: stats.files,
        },
        confidence,
        reason,
    })
}

fn file_leftover(path: &Path, confidence: Confidence, reason: Reason) -> Option<Leftover> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() || special_reason(&m).is_some() {
        return None;
    }
    Some(Leftover {
        target: Target::Path {
            path: path.to_path_buf(),
            is_dir: false,
            size: m.len(),
            files: 1,
        },
        confidence,
        reason,
    })
}

fn path_of(l: &Leftover) -> Option<&Path> {
    match &l.target {
        Target::Path { path, .. } => Some(path),
        _ => None,
    }
}

/// 去掉被其他条目完全包含的条目，并按路径排序。
fn dedupe_paths(items: &mut Vec<Leftover>) {
    let paths: Vec<PathBuf> = items
        .iter()
        .filter_map(|l| path_of(l).map(Path::to_path_buf))
        .collect();
    items.retain(|l| match path_of(l) {
        Some(p) => !paths.iter().any(|q| q != p && p.starts_with(q)),
        None => true,
    });
    let mut seen = HashSet::new();
    items.retain(|l| match &l.target {
        Target::Path { path, .. } => seen.insert(path.clone()),
        _ => true,
    });
}

/// 扫描卸载后残留的文件、快捷方式和注册表项。
///
/// `forced` 为真表示用户选择"强制删除"（卸载器缺失或损坏），此时即使程序仍登记着也继续扫描，
/// 并把它的卸载登记项一起列出。
pub fn scan_leftovers(
    app: &InstalledApp,
    roots: &FsRoots,
    env: &Env,
    reg: &dyn Registry,
    policy: &SafetyPolicy,
    forced: bool,
) -> LeftoverScan {
    let registered = is_registered(app, reg);
    if registered && !forced {
        return LeftoverScan {
            items: Vec::new(),
            still_registered: true,
            install_dir: None,
        };
    }

    let variants = name_variants(&app.name);
    let pub_norm = app
        .publisher
        .as_deref()
        .map(publisher_norm)
        .filter(|n| long_enough(n));
    let inner = inner_variants(&variants, pub_norm.as_deref());
    let install_dir = detect_install_dir(app, env, policy);
    let leaf = install_dir
        .as_ref()
        .map(|d| last_component(&d.to_string_lossy()));

    let mut items: Vec<Leftover> = Vec::new();

    // ---- 文件系统 ----
    if let Some(d) = &install_dir {
        if d.is_dir() {
            items.extend(dir_leftover(d, Confidence::High, Reason::InstallLocation));
        }
    }
    for root in roots.app_roots() {
        for (name, path) in dirs_in(root) {
            if is_reserved_dir(&name) {
                continue;
            }
            let n = normalize(&name);
            if pub_norm.as_deref() == Some(n.as_str()) {
                // 厂商目录：只清理里面属于本程序的子目录；若除此之外什么都没有，连厂商目录一起清掉。
                let children = dirs_in(&path);
                let matched: Vec<_> = children
                    .iter()
                    .filter(|(cn, _)| !is_reserved_dir(cn))
                    .filter_map(|(cn, cp)| {
                        match_strength(cn, &inner, leaf.as_deref()).map(|c| (cp.clone(), c))
                    })
                    .collect();
                let total_entries = fs::read_dir(&path).map(|r| r.count()).unwrap_or(usize::MAX);
                if !matched.is_empty() && matched.len() == total_entries {
                    items.extend(dir_leftover(
                        &path,
                        Confidence::Medium,
                        Reason::PublisherEmptied,
                    ));
                } else {
                    for (cp, c) in matched {
                        items.extend(dir_leftover(&cp, c, Reason::NameMatch));
                    }
                }
                continue;
            }
            if let Some(c) = match_strength(&name, &variants, leaf.as_deref()) {
                items.extend(dir_leftover(&path, c, Reason::NameMatch));
            }
        }
    }
    // 开始菜单里的快捷方式/文件夹、桌面快捷方式：只认与程序名完全一致的。
    for dir in roots.start_menu.iter().chain(roots.desktops.iter()) {
        let Ok(rd) = fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let path = e.path();
            let Ok(m) = e.metadata() else { continue };
            if special_reason(&m).is_some() {
                continue;
            }
            let stem = if m.is_dir() {
                normalize(&e.file_name().to_string_lossy())
            } else if path
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
            {
                normalize(&stem_lower(&path))
            } else {
                continue;
            };
            if !variants.contains(&stem) {
                continue;
            }
            items.extend(if m.is_dir() {
                dir_leftover(&path, Confidence::High, Reason::Shortcut)
            } else {
                file_leftover(&path, Confidence::High, Reason::Shortcut)
            });
        }
    }
    dedupe_paths(&mut items);

    // ---- 注册表 ----
    scan_registry(
        app,
        env,
        reg,
        &variants,
        &inner,
        pub_norm.as_deref(),
        install_dir.as_deref(),
        &mut items,
    );

    LeftoverScan {
        items,
        still_registered: registered,
        install_dir,
    }
}

/// 把一个注册表键加入残留清单（先过删除白名单，并避免重复）。
fn push_key(
    items: &mut Vec<Leftover>,
    hive: Hive,
    path: String,
    kind: KeyKind,
    guard: Option<KeyGuard>,
    confidence: Confidence,
    reason: Reason,
) {
    let allowed = match kind {
        KeyKind::Normal => check_delete_key(hive, &path).is_ok(),
        KeyKind::OwnedRoot | KeyKind::EmptiedVendorRoot => {
            check_delete_vendor_root(hive, &path).is_ok()
        }
    };
    let dup = items
        .iter()
        .any(|l| matches!(&l.target, Target::Key { hive: h, path: p, .. } if *h == hive && p.eq_ignore_ascii_case(&path)));
    if allowed && !dup {
        items.push(Leftover {
            target: Target::Key {
                hive,
                path,
                kind,
                guard,
            },
            confidence,
            reason,
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn scan_registry(
    app: &InstalledApp,
    env: &Env,
    reg: &dyn Registry,
    variants: &[String],
    inner: &[String],
    pub_norm: Option<&str>,
    install_dir: Option<&Path>,
    items: &mut Vec<Leftover>,
) {
    // 1. 程序自己的卸载登记项（只有强制删除时才会走到这里仍存在）。
    if let Some((hive, path)) = registered_path(app, reg) {
        push_key(
            items,
            hive,
            path,
            KeyKind::Normal,
            None,
            Confidence::High,
            Reason::UninstallEntry,
        );
    }

    // 2. SOFTWARE\<厂商>\<程序> 与 SOFTWARE\<程序>
    for (hive, base) in [
        (Hive::LocalMachine, "SOFTWARE"),
        (Hive::LocalMachine, r"SOFTWARE\WOW6432Node"),
        (Hive::CurrentUser, "SOFTWARE"),
    ] {
        let Ok(subs) = reg.subkeys(hive, base) else {
            continue;
        };
        for sk in subs {
            let n = normalize(&sk);
            if matches!(
                n.as_str(),
                "microsoft"
                    | "classes"
                    | "policies"
                    | "windows"
                    | "wow6432node"
                    | "clients"
                    | "registeredapplications"
            ) {
                continue;
            }
            let path = format!("{base}\\{sk}");
            if pub_norm == Some(n.as_str()) {
                let Ok(children) = reg.subkeys(hive, &path) else {
                    continue;
                };
                let mine: Vec<&String> = children
                    .iter()
                    .filter(|c| inner.contains(&normalize(c)))
                    .collect();
                if mine.is_empty() {
                    continue;
                }
                let has_values = reg
                    .values(hive, &path)
                    .map(|v| !v.is_empty())
                    .unwrap_or(true);
                // 本程序的子键总是逐个列出；若厂商键里除此之外什么都没有，再把厂商根键也列出
                // （删除时先删子键，最后再确认根键确实已经空了才删它）。
                let emptied = mine.len() == children.len() && !has_values;
                for c in &mine {
                    push_key(
                        items,
                        hive,
                        format!("{path}\\{c}"),
                        KeyKind::Normal,
                        None,
                        Confidence::High,
                        Reason::NameMatch,
                    );
                }
                if emptied {
                    push_key(
                        items,
                        hive,
                        path.clone(),
                        KeyKind::EmptiedVendorRoot,
                        None,
                        Confidence::Medium,
                        Reason::PublisherEmptied,
                    );
                }
            } else if variants.contains(&n) {
                push_key(
                    items,
                    hive,
                    path,
                    KeyKind::OwnedRoot,
                    None,
                    Confidence::Medium,
                    Reason::NameMatch,
                );
            }
        }
    }

    // 以下几类都靠"引用了安装目录"来判断，没有可靠的安装目录就不做。
    let Some(dir) = install_dir.map(|d| d.to_string_lossy().into_owned()) else {
        return;
    };

    // 3. App Paths
    for (hive, base) in [
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
        ),
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
        ),
    ] {
        let Ok(subs) = reg.subkeys(hive, base) else {
            continue;
        };
        for sk in subs {
            let path = format!("{base}\\{sk}");
            let refers = reg.values(hive, &path).map(|vals| {
                vals.iter().any(|(n, v)| {
                    (n.is_empty() || n.eq_ignore_ascii_case("path"))
                        && v.as_string()
                            .is_some_and(|s| path_refers_to(&expand_lenient(env, &s), &dir))
                })
            });
            if refers.unwrap_or(false) {
                push_key(
                    items,
                    hive,
                    path,
                    KeyKind::Normal,
                    Some(KeyGuard::AppPathRefers { dir: dir.clone() }),
                    Confidence::High,
                    Reason::AppPath,
                );
            }
        }
    }

    // 4. 自启动项（只删值，不删键）
    for (hive, path) in [
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            Hive::LocalMachine,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            Hive::CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ] {
        let Ok(vals) = reg.values(hive, path) else {
            continue;
        };
        for (name, v) in vals {
            let hit = v
                .as_string()
                .is_some_and(|s| path_refers_to(&expand_lenient(env, &s), &dir));
            if hit && check_delete_value(hive, path, &name).is_ok() {
                items.push(Leftover {
                    target: Target::Value {
                        hive,
                        path: path.to_string(),
                        name,
                        dir: dir.clone(),
                    },
                    confidence: Confidence::High,
                    reason: Reason::AutoRun,
                });
            }
        }
    }

    // 5. 服务：映像文件指向安装目录、而文件已经不存在
    let svc_base = r"SYSTEM\CurrentControlSet\Services";
    if let Ok(subs) = reg.subkeys(Hive::LocalMachine, svc_base) {
        for sk in subs {
            let path = format!("{svc_base}\\{sk}");
            if service_is_stale(reg, env, &path, &dir) {
                push_key(
                    items,
                    Hive::LocalMachine,
                    path,
                    KeyKind::Normal,
                    Some(KeyGuard::ServiceImageMissing { dir: dir.clone() }),
                    Confidence::Medium,
                    Reason::StaleService,
                );
            }
        }
    }

    // 6. COM 注册：InprocServer32 / LocalServer32 指向安装目录
    for base in [
        r"SOFTWARE\Classes\CLSID",
        r"SOFTWARE\Classes\WOW6432Node\CLSID",
    ] {
        let Ok(subs) = reg.subkeys(Hive::LocalMachine, base) else {
            continue;
        };
        for guid in subs {
            let path = format!("{base}\\{guid}");
            if com_refers(reg, env, &path, &dir) {
                push_key(
                    items,
                    Hive::LocalMachine,
                    path,
                    KeyKind::Normal,
                    Some(KeyGuard::ComRefers { dir: dir.clone() }),
                    Confidence::High,
                    Reason::ComRegistration,
                );
            }
        }
    }
}

fn service_is_stale(reg: &dyn Registry, env: &Env, path: &str, dir: &str) -> bool {
    let Some(image) = reg
        .value(Hive::LocalMachine, path, "ImagePath")
        .and_then(|v| v.as_string())
    else {
        return false;
    };
    let image = expand_lenient(env, &image);
    if !path_refers_to(&image, dir) {
        return false;
    }
    // 只有能确定路径、且文件确实不在了，才算残留。
    extract_exe_path(&image).is_some_and(|exe| {
        !Path::new(&exe.replace('\\', "/")).exists() && !Path::new(&exe).exists()
    })
}

fn com_refers(reg: &dyn Registry, env: &Env, path: &str, dir: &str) -> bool {
    ["InprocServer32", "LocalServer32"].iter().any(|sub| {
        reg.value(Hive::LocalMachine, &format!("{path}\\{sub}"), "")
            .and_then(|v| v.as_string())
            .is_some_and(|s| path_refers_to(&expand_lenient(env, &s), dir))
    })
}

// ====================================================================
// 删除残留
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegStatus {
    Deleted,
    /// 扫描之后已经不存在了。
    Missing,
    Refused(String),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct RegResult {
    pub hive: Hive,
    pub path: String,
    pub value: Option<String>,
    pub status: RegStatus,
}

#[derive(Debug)]
pub enum DeleteError {
    /// 备份注册表失败；为保证可恢复，什么都没有删。
    BackupFailed(String),
}

impl fmt::Display for DeleteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeleteError::BackupFailed(m) => write!(f, "registry backup failed: {m}"),
        }
    }
}

impl std::error::Error for DeleteError {}

#[derive(Debug, Default)]
pub struct DeleteOutcome {
    pub registry: Vec<RegResult>,
    pub files: Report,
    /// 注册表备份文件（没有需要备份的注册表项时为 `None`）。
    pub backup_file: Option<PathBuf>,
}

pub struct DeleteCtx<'a> {
    pub reg: &'a dyn Registry,
    pub env: &'a Env,
    pub policy: &'a SafetyPolicy,
    pub backup_dir: &'a Path,
    pub app_name: &'a str,
    pub disposal: Disposal,
    pub cancel: &'a AtomicBool,
}

/// UTC 时间戳，形如 `20241231-235959`。
pub fn format_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // 民用历法转换（Howard Hinnant 算法）。
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn slug(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    if s.trim_matches('_').is_empty() {
        "app".into()
    } else {
        s
    }
}

/// 删除前再次确认条目没有被改动；不符就拒绝。
fn guard_holds(ctx: &DeleteCtx, hive: Hive, path: &str, guard: &Option<KeyGuard>) -> bool {
    match guard {
        None => true,
        Some(KeyGuard::ServiceImageMissing { dir }) => {
            service_is_stale(ctx.reg, ctx.env, path, dir)
        }
        Some(KeyGuard::ComRefers { dir }) => {
            com_refers(ctx.reg, ctx.env, path, dir) && hive == Hive::LocalMachine
        }
        Some(KeyGuard::AppPathRefers { dir }) => ctx
            .reg
            .values(hive, path)
            .map(|vals| {
                vals.iter().any(|(n, v)| {
                    (n.is_empty() || n.eq_ignore_ascii_case("path"))
                        && v.as_string()
                            .is_some_and(|s| path_refers_to(&expand_lenient(ctx.env, &s), dir))
                })
            })
            .unwrap_or(false),
    }
}

/// 删除用户勾选的残留：先备份并删除注册表项，再删除文件。
///
/// 备份失败时返回 `Err`，此时**没有任何东西被删除**。
pub fn delete_leftovers(
    items: &[Leftover],
    ctx: &DeleteCtx,
    mut journal: Option<&mut dyn Write>,
) -> Result<DeleteOutcome, DeleteError> {
    let mut out = DeleteOutcome::default();

    // ---- 1. 收集注册表目标，过白名单，备份 ----
    struct KeyJob<'a> {
        hive: Hive,
        path: &'a str,
        kind: KeyKind,
        guard: &'a Option<KeyGuard>,
    }
    let mut key_jobs: Vec<KeyJob> = Vec::new();
    let mut value_jobs: Vec<(Hive, &str, &str)> = Vec::new();
    for l in items {
        match &l.target {
            Target::Key {
                hive,
                path,
                kind,
                guard,
            } => {
                let allowed = match kind {
                    KeyKind::Normal => check_delete_key(*hive, path),
                    KeyKind::OwnedRoot | KeyKind::EmptiedVendorRoot => {
                        check_delete_vendor_root(*hive, path)
                    }
                };
                match allowed {
                    Ok(()) => key_jobs.push(KeyJob {
                        hive: *hive,
                        path,
                        kind: *kind,
                        guard,
                    }),
                    Err(e) => out.registry.push(RegResult {
                        hive: *hive,
                        path: path.clone(),
                        value: None,
                        status: RegStatus::Refused(e.to_string()),
                    }),
                }
            }
            Target::Value {
                hive, path, name, ..
            } => match check_delete_value(*hive, path, name) {
                Ok(()) => value_jobs.push((*hive, path, name)),
                Err(e) => out.registry.push(RegResult {
                    hive: *hive,
                    path: path.clone(),
                    value: Some(name.clone()),
                    status: RegStatus::Refused(e.to_string()),
                }),
            },
            Target::Path { .. } => {}
        }
    }

    // 已不存在的键不需要备份，也不会失败。
    let (existing_keys, missing_keys): (Vec<_>, Vec<_>) = key_jobs
        .into_iter()
        .partition(|k| ctx.reg.key_exists(k.hive, k.path));
    for k in &missing_keys {
        out.registry.push(RegResult {
            hive: k.hive,
            path: k.path.to_string(),
            value: None,
            status: RegStatus::Missing,
        });
    }

    if !existing_keys.is_empty() || !value_jobs.is_empty() {
        let mut text = String::from(crate::registry::REG_FILE_HEADER);
        let keys: Vec<(Hive, String)> = existing_keys
            .iter()
            .map(|k| (k.hive, k.path.to_string()))
            .collect();
        let body =
            export_keys(ctx.reg, &keys).map_err(|e| DeleteError::BackupFailed(e.to_string()))?;
        text.push_str(
            body.strip_prefix(crate::registry::REG_FILE_HEADER)
                .unwrap_or(&body),
        );
        for (hive, path, name) in &value_jobs {
            if let Some(v) = ctx.reg.value(*hive, path, name) {
                text.push_str(&export_values(*hive, path, &[(name.to_string(), v)]));
            }
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let file = ctx.backup_dir.join(format!(
            "{}-{}.reg",
            format_timestamp(now),
            slug(ctx.app_name)
        ));
        fs::create_dir_all(ctx.backup_dir)
            .and_then(|_| fs::write(&file, to_utf16le_with_bom(&text)))
            .map_err(|e| DeleteError::BackupFailed(e.to_string()))?;
        out.backup_file = Some(file);
    }

    // ---- 2. 删除注册表项：值 → 深层键 → 浅层键 → 厂商根键 ----
    let log = |journal: &mut Option<&mut dyn Write>, r: &RegResult| {
        if let Some(w) = journal.as_deref_mut() {
            let _ = writeln!(
                w,
                "{}",
                serde_json::json!({
                    "op": "registry",
                    "ts": SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                    "hive": r.hive.short_name(),
                    "path": r.path,
                    "value": r.value,
                    "status": format!("{:?}", r.status),
                })
            );
            let _ = w.flush();
        }
    };

    for (hive, path, name) in value_jobs {
        let status = match ctx.reg.value(hive, path, name) {
            None => RegStatus::Missing,
            Some(_) => match ctx.reg.delete_value(hive, path, name) {
                Ok(()) => RegStatus::Deleted,
                Err(e) => RegStatus::Failed(e.to_string()),
            },
        };
        let r = RegResult {
            hive,
            path: path.to_string(),
            value: Some(name.to_string()),
            status,
        };
        log(&mut journal, &r);
        out.registry.push(r);
    }

    let mut jobs = existing_keys;
    // 深的在前（先删子键），厂商根键放最后以便确认它已经空了。
    jobs.sort_by_key(|k| {
        (
            k.kind == KeyKind::EmptiedVendorRoot,
            std::cmp::Reverse(k.path.matches('\\').count()),
        )
    });
    for k in jobs {
        let status = if !ctx.reg.key_exists(k.hive, k.path) {
            RegStatus::Missing // 例如已随父键一起删除
        } else if !guard_holds(ctx, k.hive, k.path, k.guard) {
            RegStatus::Refused("changed since the scan".into())
        } else if k.kind == KeyKind::EmptiedVendorRoot
            && (!ctx
                .reg
                .subkeys(k.hive, k.path)
                .map(|s| s.is_empty())
                .unwrap_or(false)
                || !ctx
                    .reg
                    .values(k.hive, k.path)
                    .map(|v| v.is_empty())
                    .unwrap_or(false))
        {
            RegStatus::Refused("the vendor key still contains other entries".into())
        } else {
            match ctx.reg.delete_key(k.hive, k.path) {
                Ok(()) => RegStatus::Deleted,
                Err(e) => RegStatus::Failed(e.to_string()),
            }
        };
        let r = RegResult {
            hive: k.hive,
            path: k.path.to_string(),
            value: None,
            status,
        };
        log(&mut journal, &r);
        out.registry.push(r);
    }

    // ---- 3. 删除文件 ----
    let candidates: Vec<Candidate> = items
        .iter()
        .filter_map(|l| match &l.target {
            Target::Path {
                path,
                is_dir,
                size,
                files,
            } => Some(Candidate {
                rule_id: format!("uninstall:{}", slug(ctx.app_name)),
                path: path.clone(),
                is_dir: *is_dir,
                size: *size,
                file_count: *files,
                disposal: ctx.disposal,
            }),
            _ => None,
        })
        .collect();
    if !candidates.is_empty() {
        let plan = Plan::from_items(candidates, ctx.policy.clone());
        out.files = execute_with(
            &plan,
            ExecOptions::default(),
            journal,
            None,
            ctx.cancel,
            &mut |_, _| {},
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::MemRegistry;
    use crate::safety::PathStyle;
    use crate::sysaction::CmdOutput;
    use std::io;
    use Hive::{CurrentUser, LocalMachine};

    // ----------------------------------------------------------------
    // 辅助：在内存注册表里安装一个程序
    // ----------------------------------------------------------------

    fn add_app(reg: &MemRegistry, hive: Hive, key: &str, name: &str, extra: &[(&str, &str)]) {
        let path = format!("{UNINSTALL_PATH}\\{key}");
        reg.set_sz(hive, &path, "DisplayName", name);
        for (k, v) in extra {
            reg.set_sz(hive, &path, k, v);
        }
    }

    fn app_named(reg: &MemRegistry, key: &str) -> InstalledApp {
        enumerate_apps(reg)
            .into_iter()
            .find(|a| matches!(&a.source, AppSource::Registry { key: k, .. } if k == key))
            .unwrap()
    }

    // ----------------------------------------------------------------
    // 枚举
    // ----------------------------------------------------------------

    #[test]
    fn enumerates_apps_from_all_three_roots_and_sorts_by_name() {
        let r = MemRegistry::new();
        add_app(
            &r,
            LocalMachine,
            "{AAA}",
            "Zeta Tool",
            &[
                ("DisplayVersion", "1.0"),
                ("Publisher", "Zeta Inc"),
                ("UninstallString", r#""C:\Zeta\unins.exe""#),
            ],
        );
        r.set_dword(
            LocalMachine,
            &format!("{UNINSTALL_PATH}\\{{AAA}}"),
            "EstimatedSize",
            2048,
        );
        r.set_dword(
            LocalMachine,
            &format!("{UNINSTALL_PATH}\\{{AAA}}"),
            "WindowsInstaller",
            1,
        );
        r.set_sz(
            LocalMachine,
            &format!("{UNINSTALL_PATH_WOW}\\Alpha"),
            "DisplayName",
            "alpha 32-bit",
        );
        add_app(
            &r,
            CurrentUser,
            "Beta",
            "Beta",
            &[("InstallLocation", r"C:\Users\a\Beta")],
        );

        let apps = enumerate_apps(&r);
        assert_eq!(
            apps.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["alpha 32-bit", "Beta", "Zeta Tool"]
        );
        let z = &apps[2];
        assert_eq!(
            (z.version.as_deref(), z.publisher.as_deref(), z.size_kb),
            (Some("1.0"), Some("Zeta Inc"), Some(2048))
        );
        assert!(z.windows_installer);
        assert_eq!(
            apps[0].source,
            AppSource::Registry {
                hive: LocalMachine,
                key: "Alpha".into()
            }
        );
        assert_eq!(
            apps[1].install_location.as_deref(),
            Some(r"C:\Users\a\Beta")
        );
    }

    #[test]
    fn hides_system_components_updates_and_nameless_entries() {
        let r = MemRegistry::new();
        add_app(&r, LocalMachine, "Real", "Real App", &[]);
        add_app(&r, LocalMachine, "Sys", "Hidden Component", &[]);
        r.set_dword(
            LocalMachine,
            &format!("{UNINSTALL_PATH}\\Sys"),
            "SystemComponent",
            1,
        );
        add_app(
            &r,
            LocalMachine,
            "KB1",
            "Update for X (KB1)",
            &[("ParentKeyName", "OperatingSystem")],
        );
        add_app(
            &r,
            LocalMachine,
            "Hot",
            "Security Update for Y",
            &[("ReleaseType", "Security Update")],
        );
        r.set_sz(
            LocalMachine,
            &format!("{UNINSTALL_PATH}\\NoName"),
            "Publisher",
            "Nobody",
        );
        add_app(&r, LocalMachine, "Blank", "   ", &[]);
        let names: Vec<_> = enumerate_apps(&r).into_iter().map(|a| a.name).collect();
        assert_eq!(names, ["Real App"]);
    }

    #[test]
    fn parses_appx_json_for_single_and_multiple_packages() {
        let many = r#"[{"Name":"Contoso.Notes","PackageFullName":"Contoso.Notes_1.2.3.0_x64__abc123","Publisher":"CN=Contoso","Version":"1.2.3.0","InstallLocation":"C:\\Program Files\\WindowsApps\\X"},
                       {"Name":"Evil","PackageFullName":"x'; calc; '","Publisher":"","Version":"1"},
                       {"Name":"","PackageFullName":"Nameless_1_x64__a"}]"#;
        let apps = parse_appx_json(many);
        assert_eq!(apps.len(), 1, "含注入字符的包名与无名称的条目被丢弃");
        assert_eq!(apps[0].name, "Contoso.Notes");
        assert_eq!(
            apps[0].source,
            AppSource::Appx {
                package_full_name: "Contoso.Notes_1.2.3.0_x64__abc123".into()
            }
        );

        let single = r#"{"Name":"One","PackageFullName":"One_1.0.0.0_x64__z","Version":"1.0.0.0"}"#;
        assert_eq!(parse_appx_json(single).len(), 1);
        assert_eq!(parse_appx_json("\u{feff}[]").len(), 0);
        assert!(parse_appx_json("not json").is_empty());
        assert!(parse_appx_json("").is_empty());
    }

    #[test]
    fn package_names_are_strictly_validated() {
        assert!(is_safe_package_name(
            "Microsoft.WindowsCalculator_11.2.0.0_x64__8wekyb3d8bbwe"
        ));
        for bad in [
            "",
            "a b",
            "a;b",
            "a'b",
            "a\"b",
            "a$(x)",
            "a`b",
            "a|b",
            "a&b",
            "..\\x",
            &"a".repeat(300),
        ] {
            assert!(!is_safe_package_name(bad), "{bad:?}");
        }
    }

    // ----------------------------------------------------------------
    // 卸载命令
    // ----------------------------------------------------------------

    fn simple_app(uninstall: Option<&str>, quiet: Option<&str>) -> InstalledApp {
        InstalledApp {
            source: AppSource::Registry {
                hive: LocalMachine,
                key: "App".into(),
            },
            name: "App".into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            size_kb: None,
            uninstall_string: uninstall.map(str::to_string),
            quiet_uninstall_string: quiet.map(str::to_string),
            display_icon: None,
            windows_installer: false,
        }
    }

    #[test]
    fn picks_quiet_or_normal_uninstall_command() {
        let a = simple_app(Some(r#""C:\A\unins.exe""#), Some(r#""C:\A\unins.exe" /S"#));
        assert_eq!(uninstall_command(&a, false).unwrap(), r#""C:\A\unins.exe""#);
        assert_eq!(
            uninstall_command(&a, true).unwrap(),
            r#""C:\A\unins.exe" /S"#
        );
        // 只有一种时两种模式都用它
        let only_quiet = simple_app(None, Some("q.exe /S"));
        assert_eq!(uninstall_command(&only_quiet, false).unwrap(), "q.exe /S");
        let only_normal = simple_app(Some("u.exe"), None);
        assert_eq!(uninstall_command(&only_normal, true).unwrap(), "u.exe");
    }

    #[test]
    fn msi_modify_commands_become_uninstall_commands() {
        let a = simple_app(
            Some("MsiExec.exe /I{11111111-2222-3333-4444-555555555555}"),
            None,
        );
        assert_eq!(
            uninstall_command(&a, false).unwrap(),
            "MsiExec.exe /X{11111111-2222-3333-4444-555555555555}"
        );
        let lower = simple_app(Some("msiexec /i{ABC} /qb"), None);
        assert_eq!(
            uninstall_command(&lower, false).unwrap(),
            "msiexec /X{ABC} /qb"
        );
        // 不是 msiexec 的命令里即使出现 /i{ 也不动
        let other = simple_app(Some("setup.exe /i{keep}"), None);
        assert_eq!(
            uninstall_command(&other, false).unwrap(),
            "setup.exe /i{keep}"
        );
    }

    #[test]
    fn builds_msiexec_command_from_the_product_code_when_unregistered() {
        let mut a = simple_app(None, None);
        a.source = AppSource::Registry {
            hive: LocalMachine,
            key: "{ABC-1}".into(),
        };
        a.windows_installer = true;
        assert_eq!(
            uninstall_command(&a, false).unwrap(),
            "MsiExec.exe /X{ABC-1}"
        );
        a.windows_installer = false;
        assert_eq!(
            uninstall_command(&a, false),
            Err(UninstallError::NoUninstaller)
        );
    }

    #[test]
    fn rejects_missing_or_malformed_commands() {
        assert_eq!(
            uninstall_command(&simple_app(None, None), false),
            Err(UninstallError::NoUninstaller)
        );
        for bad in ["", "   ", "a.exe\r\ncalc.exe", "a.exe\0", &"x".repeat(5000)] {
            assert_eq!(
                uninstall_command(&simple_app(Some(bad), None), false),
                Err(UninstallError::InvalidCommand),
                "{bad:?}"
            );
        }
        let mut store = simple_app(Some("x"), None);
        store.source = AppSource::Appx {
            package_full_name: "P_1_x64__a".into(),
        };
        assert_eq!(
            uninstall_command(&store, false),
            Err(UninstallError::NoUninstaller)
        );
    }

    #[derive(Default)]
    struct FakeRunner {
        shell: std::sync::Mutex<Vec<String>>,
        run: std::sync::Mutex<Vec<String>>,
        code: i32,
        /// 运行完卸载器后要从注册表里删掉的登记项（模拟卸载成功）。
        remove_after: Option<(std::sync::Arc<MemRegistry>, Hive, String)>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
            self.run
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok(CmdOutput {
                code: self.code,
                ..Default::default()
            })
        }
        fn run_shell(&self, line: &str) -> io::Result<CmdOutput> {
            self.shell.lock().unwrap().push(line.to_string());
            if let Some((reg, hive, path)) = &self.remove_after {
                let _ = reg.delete_key(*hive, path);
            }
            Ok(CmdOutput {
                code: self.code,
                ..Default::default()
            })
        }
    }

    #[test]
    fn runs_the_registered_uninstaller_and_reports_whether_the_app_is_gone() {
        let reg = std::sync::Arc::new(MemRegistry::new());
        add_app(
            &reg,
            LocalMachine,
            "Foo",
            "Foo",
            &[("UninstallString", r#""C:\Foo\unins000.exe" /SILENT"#)],
        );
        let app = app_named(&reg, "Foo");

        // 卸载器被取消：仍然登记着。
        let cancelled = FakeRunner {
            code: 1223,
            ..Default::default()
        };
        let r = run_uninstaller(&app, false, &cancelled, reg.as_ref()).unwrap();
        assert_eq!((r.exit_code, r.still_registered), (1223, true));
        assert_eq!(
            *cancelled.shell.lock().unwrap(),
            [r#""C:\Foo\unins000.exe" /SILENT"#]
        );

        // 卸载成功：登记项消失。
        let ok = FakeRunner {
            remove_after: Some((reg.clone(), LocalMachine, format!("{UNINSTALL_PATH}\\Foo"))),
            ..Default::default()
        };
        let r = run_uninstaller(&app, false, &ok, reg.as_ref()).unwrap();
        assert_eq!((r.exit_code, r.still_registered), (0, false));
    }

    #[test]
    fn store_apps_are_removed_through_powershell_with_a_validated_name() {
        let reg = MemRegistry::new();
        let mut app = simple_app(None, None);
        app.source = AppSource::Appx {
            package_full_name: "Contoso.Notes_1.0.0.0_x64__abc".into(),
        };
        let runner = FakeRunner::default();
        let r = run_uninstaller(&app, false, &runner, &reg).unwrap();
        assert_eq!(r.exit_code, 0);
        assert_eq!(runner.run.lock().unwrap()[0], "powershell.exe -NoProfile -NonInteractive -Command Remove-AppxPackage -Package 'Contoso.Notes_1.0.0.0_x64__abc'");
        assert!(runner.shell.lock().unwrap().is_empty());

        app.source = AppSource::Appx {
            package_full_name: "x'; Remove-Item C:\\ -Recurse; '".into(),
        };
        let runner = FakeRunner::default();
        assert_eq!(
            run_uninstaller(&app, false, &runner, &reg),
            Err(UninstallError::InvalidCommand)
        );
        assert!(
            runner.run.lock().unwrap().is_empty(),
            "非法包名不能触发任何命令"
        );
    }

    #[test]
    fn missing_uninstaller_does_not_run_anything() {
        let reg = MemRegistry::new();
        let runner = FakeRunner::default();
        assert_eq!(
            run_uninstaller(&simple_app(None, None), false, &runner, &reg),
            Err(UninstallError::NoUninstaller)
        );
        assert!(runner.shell.lock().unwrap().is_empty());
    }

    // ----------------------------------------------------------------
    // 名称与路径匹配
    // ----------------------------------------------------------------

    #[test]
    fn normalizes_names_and_strips_version_suffixes() {
        assert_eq!(normalize("Foo-Bar  2.0!"), "foobar20");
        assert_eq!(normalize("微信 WeChat"), "微信wechat");
        assert_eq!(
            name_variants("Foo Bar 2.3.1 (x64)"),
            ["foobar231x64", "foobar"]
        );
        assert_eq!(
            name_variants("Notepad++ (64-bit)"),
            ["notepad64bit", "notepad"]
        );
        assert_eq!(name_variants("Git"), ["git"]);
        assert_eq!(
            name_variants("QQ"),
            Vec::<String>::new(),
            "两个 ASCII 字符太短，不参与匹配"
        );
        assert_eq!(name_variants("微信"), ["微信"], "两个汉字足够特异");
    }

    #[test]
    fn publisher_names_lose_their_company_suffix() {
        assert_eq!(publisher_norm("Google LLC"), "google");
        assert_eq!(publisher_norm("Acme, Inc."), "acme");
        assert_eq!(publisher_norm("Contoso Software Ltd."), "contososoftware");
        assert_eq!(publisher_norm("Co"), "co", "只剩后缀本身时保留");
        assert_eq!(publisher_norm("Igor Pavlov"), "igorpavlov");
        let v = name_variants("Acme Widget");
        assert_eq!(inner_variants(&v, Some("acme")), ["acmewidget", "widget"]);
        assert_eq!(inner_variants(&v, None), ["acmewidget"]);
    }

    #[test]
    fn match_strength_distinguishes_exact_partial_and_unrelated() {
        let v = name_variants("Google Chrome");
        assert_eq!(
            match_strength("Google Chrome", &v, None),
            Some(Confidence::High)
        );
        assert_eq!(
            match_strength("google-chrome", &v, None),
            Some(Confidence::High)
        );
        assert_eq!(match_strength("Chrome", &v, None), Some(Confidence::Medium));
        assert_eq!(
            match_strength("Chrome Remote Desktop", &v, None),
            None,
            "更长的名字可能是另一个程序"
        );
        assert_eq!(match_strength("Edge", &v, None), None);
        assert_eq!(match_strength("Go", &v, None), None, "太短");
        assert_eq!(
            match_strength("FooDir", &v, Some("foodir")),
            Some(Confidence::High),
            "与安装目录同名"
        );
    }

    #[test]
    fn path_references_respect_boundaries() {
        let dir = r"C:\Program Files\Foo";
        for yes in [
            r"C:\Program Files\Foo\bin\foo.exe",
            r#""C:\Program Files\Foo\foo.exe" --tray"#,
            r"c:/program files/foo/foo.exe",
            r"rundll32.exe C:\Program Files\Foo\x.dll,Entry",
            r"C:\Program Files\Foo",
            r"C:\Program Files\Foo ",
        ] {
            assert!(path_refers_to(yes, dir), "{yes}");
        }
        for no in [
            r"C:\Program Files\Foobar\x.exe",
            r"C:\Program Files (x86)\Foo\x.exe",
            r"D:\Program Files\Foo\x.exe",
            r"C:\Program Files\Fo",
            "",
        ] {
            assert!(!path_refers_to(no, dir), "{no}");
        }
        assert!(
            !path_refers_to(r"C:\Anything", r"C:\"),
            "太短的目录不能当作依据"
        );
    }

    #[test]
    fn extracts_executable_paths_from_image_paths() {
        assert_eq!(
            extract_exe_path(r#""C:\Program Files\Foo\svc.exe" -k run"#).as_deref(),
            Some(r"C:\Program Files\Foo\svc.exe")
        );
        assert_eq!(
            extract_exe_path(r"C:\Program Files\Foo\svc.exe -k run").as_deref(),
            Some(r"C:\Program Files\Foo\svc.exe")
        );
        assert_eq!(
            extract_exe_path(r"C:\Windows\System32\drivers\foo.sys").as_deref(),
            Some(r"C:\Windows\System32\drivers\foo.sys")
        );
        assert_eq!(
            extract_exe_path(r"\SystemRoot\System32\drivers\foo.sys"),
            None,
            "相对形式无法判断是否存在"
        );
        assert_eq!(extract_exe_path("svchost.exe -k netsvcs"), None);
    }

    #[test]
    fn expands_known_variables_and_leaves_unknown_ones() {
        let env = Env::from_pairs([("ProgramFiles", r"C:\Program Files")]);
        assert_eq!(
            expand_lenient(&env, r"%ProgramFiles%\Foo\a.exe"),
            r"C:\Program Files\Foo\a.exe"
        );
        assert_eq!(expand_lenient(&env, r"%Nope%\a"), r"%Nope%\a");
        assert_eq!(expand_lenient(&env, "50% done"), "50% done");
    }

    #[test]
    fn timestamps_format_as_utc() {
        assert_eq!(format_timestamp(0), "19700101-000000");
        assert_eq!(format_timestamp(951_782_400), "20000229-000000"); // 闰日
        assert_eq!(format_timestamp(1_735_689_599), "20241231-235959");
        assert_eq!(format_timestamp(1_700_000_000), "20231114-221320");
    }

    // ----------------------------------------------------------------
    // 残留扫描：文件系统
    // ----------------------------------------------------------------

    use std::sync::atomic::AtomicU64;
    static N: AtomicU64 = AtomicU64::new(0);

    struct Sandbox {
        base: PathBuf,
        roots: FsRoots,
    }

    impl Sandbox {
        fn new() -> Self {
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let raw = std::env::temp_dir().join(format!("dc-un-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&raw);
            let base = {
                fs::create_dir_all(&raw).unwrap();
                fs::canonicalize(&raw).unwrap()
            };
            let mk = |p: &str| {
                let d = base.join(p);
                fs::create_dir_all(&d).unwrap();
                d
            };
            let roots = FsRoots {
                program_files: vec![mk("PF"), mk("PF86")],
                program_data: Some(mk("PD")),
                roaming: Some(mk("Roaming")),
                local: Some(mk("Local")),
                local_low: Some(mk("LocalLow")),
                local_programs: Some(mk("Local/Programs")),
                start_menu: vec![mk("StartMenu")],
                desktops: vec![mk("Desktop")],
            };
            Sandbox { base, roots }
        }
        fn write(&self, rel: &str, n: usize) -> PathBuf {
            let p = self.base.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, vec![1u8; n]).unwrap();
            p
        }
        fn policy(&self) -> SafetyPolicy {
            let mut p = SafetyPolicy::empty(PathStyle::Posix);
            // 沙箱里的"系统"和"文档"目录受保护。
            p.protect(&self.base.join("Windows").to_string_lossy())
                .unwrap();
            p.protect(&self.base.join("Documents").to_string_lossy())
                .unwrap();
            p
        }
        fn env(&self) -> Env {
            Env::from_pairs([("SB", self.base.to_string_lossy())])
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn scan(sb: &Sandbox, reg: &MemRegistry, app: &InstalledApp, forced: bool) -> LeftoverScan {
        scan_leftovers(app, &sb.roots, &sb.env(), reg, &sb.policy(), forced)
    }

    fn paths_of(s: &LeftoverScan, sb: &Sandbox) -> Vec<String> {
        let mut v: Vec<String> = s
            .items
            .iter()
            .filter_map(path_of)
            .map(|p| {
                p.strip_prefix(&sb.base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        v.sort();
        v
    }

    fn gone_app(name: &str, publisher: Option<&str>, install: Option<&Path>) -> InstalledApp {
        let mut a = simple_app(None, None);
        a.name = name.into();
        a.publisher = publisher.map(str::to_string);
        a.install_location = install.map(|p| p.to_string_lossy().into_owned());
        a
    }

    #[test]
    fn still_registered_apps_are_not_scanned_unless_forced() {
        let sb = Sandbox::new();
        sb.write("PF/Foo/foo.exe", 10);
        let reg = MemRegistry::new();
        add_app(
            &reg,
            LocalMachine,
            "Foo",
            "Foo",
            &[("InstallLocation", &sb.base.join("PF/Foo").to_string_lossy())],
        );
        let app = app_named(&reg, "Foo");

        let s = scan(&sb, &reg, &app, false);
        assert!(s.still_registered);
        assert!(s.items.is_empty(), "程序还在，不能把它的目录当残留");

        let forced = scan(&sb, &reg, &app, true);
        assert!(paths_of(&forced, &sb).contains(&"PF/Foo".to_string()));
        assert!(
            forced
                .items
                .iter()
                .any(|l| l.reason == Reason::UninstallEntry),
            "强制删除时包含它自己的登记项"
        );
    }

    #[test]
    fn finds_install_dir_and_name_matching_folders_across_roots() {
        let sb = Sandbox::new();
        sb.write("PF/Foo Bar/foo.exe", 100);
        sb.write("PD/FooBar/license.dat", 10);
        sb.write("Roaming/foo-bar/settings.json", 20);
        sb.write("Local/FooBar/cache/a", 30);
        sb.write("Local/Programs/Foo Bar/x", 5);
        sb.write("PF/Unrelated/x", 1);
        sb.write("Roaming/FooBarBaz/x", 1); // 更长的名字：另一个程序
        let reg = MemRegistry::new();
        let app = gone_app("Foo Bar 2.0", None, Some(&sb.base.join("PF/Foo Bar")));
        let s = scan(&sb, &reg, &app, false);
        assert!(!s.still_registered);
        assert_eq!(
            paths_of(&s, &sb),
            [
                "Local/FooBar",
                "Local/Programs/Foo Bar",
                "PD/FooBar",
                "PF/Foo Bar",
                "Roaming/foo-bar"
            ]
        );
        assert!(s.items.iter().all(|l| l.confidence == Confidence::High));
        let pf = s
            .items
            .iter()
            .find(
                |l| matches!(&l.target, Target::Path { path, .. } if path.ends_with("PF/Foo Bar")),
            )
            .unwrap();
        assert_eq!(pf.reason, Reason::InstallLocation);
        assert!(matches!(
            &pf.target,
            Target::Path {
                size: 100,
                files: 1,
                is_dir: true,
                ..
            }
        ));
    }

    #[test]
    fn reserved_and_system_folders_are_never_listed() {
        let sb = Sandbox::new();
        for name in [
            "Microsoft",
            "Windows NT",
            "Common Files",
            "WindowsApps",
            "Packages",
            "Temp",
            "Microsoft Office",
            "Windows Defender",
        ] {
            sb.write(&format!("PF/{name}/x"), 1);
            sb.write(&format!("Local/{name}/x"), 1);
        }
        let reg = MemRegistry::new();
        for app_name in [
            "Microsoft",
            "Windows NT",
            "Common Files",
            "Temp",
            "Packages",
            "WindowsApps",
        ] {
            let s = scan(&sb, &reg, &gone_app(app_name, None, None), false);
            assert!(s.items.is_empty(), "{app_name}: {:?}", paths_of(&s, &sb));
        }
    }

    #[test]
    fn publisher_folder_is_listed_only_when_nothing_else_lives_there() {
        let sb = Sandbox::new();
        sb.write("PF/Acme/Widget/w.exe", 10);
        sb.write("PF/Acme/Other/o.exe", 10); // 同厂商的另一款软件
        sb.write("PD/Contoso/Widget/w.dat", 10); // Contoso 目录里只有 Widget
        let reg = MemRegistry::new();

        let acme = scan(&sb, &reg, &gone_app("Widget", Some("Acme"), None), false);
        assert_eq!(
            paths_of(&acme, &sb),
            ["PF/Acme/Widget"],
            "同厂商的其他软件还在，只删本程序的目录"
        );

        let contoso = scan(&sb, &reg, &gone_app("Widget", Some("Contoso"), None), false);
        assert_eq!(paths_of(&contoso, &sb), ["PD/Contoso"]);
        assert_eq!(contoso.items[0].reason, Reason::PublisherEmptied);
        assert_eq!(contoso.items[0].confidence, Confidence::Medium);
    }

    #[test]
    fn shortcuts_must_match_the_program_name_exactly() {
        let sb = Sandbox::new();
        sb.write("StartMenu/Foo Bar.lnk", 1);
        sb.write("StartMenu/Foo Bar Uninstall.lnk", 1);
        sb.write("StartMenu/Foo Bar/readme.txt", 1);
        sb.write("Desktop/foo bar.lnk", 1);
        sb.write("Desktop/foo bar.txt", 1); // 不是快捷方式
        sb.write("Desktop/Other.lnk", 1);
        let reg = MemRegistry::new();
        let s = scan(&sb, &reg, &gone_app("Foo Bar", None, None), false);
        assert_eq!(
            paths_of(&s, &sb),
            [
                "Desktop/foo bar.lnk",
                "StartMenu/Foo Bar",
                "StartMenu/Foo Bar.lnk"
            ]
        );
        assert!(s.items.iter().all(|l| l.reason == Reason::Shortcut));
    }

    #[test]
    fn unsafe_install_locations_are_ignored() {
        let sb = Sandbox::new();
        sb.write("Documents/important.docx", 5);
        sb.write("Windows/System32/x.dll", 5);
        let reg = MemRegistry::new();
        for bad in [
            sb.base.join("Documents"),
            sb.base.join("Windows/System32"),
            PathBuf::from("/"),
        ] {
            let s = scan(
                &sb,
                &reg,
                &gone_app("Whatever Tool", None, Some(&bad)),
                false,
            );
            assert!(s.install_dir.is_none(), "{bad:?}");
            assert!(s.items.is_empty());
        }
        assert!(sb.base.join("Documents/important.docx").exists());
    }

    #[test]
    fn install_dir_falls_back_to_the_uninstaller_location() {
        let sb = Sandbox::new();
        sb.write("PF/Qux/unins.exe", 1);
        sb.write("PF/Qux/q.dll", 1);
        let reg = MemRegistry::new();
        let mut app = gone_app("Qux Pro", None, None);
        app.uninstall_string = Some(format!(
            "\"{}\" /S",
            sb.base.join("PF/Qux/unins.exe").display()
        ));
        let s = scan(&sb, &reg, &app, false);
        assert_eq!(
            s.install_dir.as_deref(),
            Some(sb.base.join("PF/Qux").as_path())
        );
        assert_eq!(paths_of(&s, &sb), ["PF/Qux"]);
    }

    #[test]
    fn folders_with_protected_content_are_left_alone() {
        let sb = Sandbox::new();
        sb.write("PF/Foo/.git/HEAD", 1);
        sb.write("Roaming/Foo/a", 1);
        let reg = MemRegistry::new();
        let s = scan(&sb, &reg, &gone_app("Foo", None, None), false);
        assert_eq!(paths_of(&s, &sb), ["Roaming/Foo"]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_folders_are_not_followed() {
        let sb = Sandbox::new();
        sb.write("Documents/keep.txt", 1);
        std::os::unix::fs::symlink(sb.base.join("Documents"), sb.base.join("Roaming/Foo")).unwrap();
        let reg = MemRegistry::new();
        let s = scan(&sb, &reg, &gone_app("Foo", None, None), false);
        assert!(s.items.is_empty());
    }

    // ----------------------------------------------------------------
    // 残留扫描：注册表
    // ----------------------------------------------------------------

    fn key_paths(s: &LeftoverScan) -> Vec<String> {
        let mut v: Vec<String> = s
            .items
            .iter()
            .filter_map(|l| match &l.target {
                Target::Key { hive, path, .. } => Some(format!("{}\\{path}", hive.short_name())),
                Target::Value {
                    hive, path, name, ..
                } => Some(format!("{}\\{path}::{name}", hive.short_name())),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    fn registry_fixture(sb: &Sandbox) -> (MemRegistry, String) {
        let dir = sb
            .base
            .join("PF/Acme Widget")
            .to_string_lossy()
            .into_owned();
        let r = MemRegistry::new();
        // 厂商/产品键
        r.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget", "Version", "1");
        r.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget\Sub", "x", "y");
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\WOW6432Node\Acme\Widget",
            "Version",
            "1",
        );
        r.set_sz(CurrentUser, r"SOFTWARE\Acme\Widget", "Theme", "dark");
        // 另一个厂商的内容，必须保持不变
        r.set_sz(LocalMachine, r"SOFTWARE\Acme\Gadget", "Version", "9");
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other",
            "DisplayName",
            "Other",
        );
        // App Paths
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\widget.exe",
            "",
            &format!(r"{dir}\widget.exe"),
        );
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\other.exe",
            "",
            r"C:\Other\other.exe",
        );
        // 自启动
        r.set_sz(
            CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "AcmeWidget",
            &format!(r#""{dir}\tray.exe" --minimized"#),
        );
        r.set_sz(
            CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "OtherThing",
            r"C:\Other\o.exe",
        );
        // 服务：文件已不存在（残留）与文件仍存在（不是残留）
        r.set_sz(
            LocalMachine,
            r"SYSTEM\CurrentControlSet\Services\WidgetSvc",
            "ImagePath",
            &format!(r#""{dir}\svc.exe" -k run"#),
        );
        // COM 注册
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\Classes\CLSID\{AAAAAAAA-0000-0000-0000-000000000001}\InprocServer32",
            "",
            &format!(r"{dir}\shell.dll"),
        );
        r.set_sz(
            LocalMachine,
            r"SOFTWARE\Classes\CLSID\{BBBBBBBB-0000-0000-0000-000000000002}\InprocServer32",
            "",
            r"C:\Windows\System32\other.dll",
        );
        (r, dir)
    }

    #[test]
    fn finds_every_kind_of_registry_leftover_and_nothing_else() {
        let sb = Sandbox::new();
        let (reg, dir) = registry_fixture(&sb);
        let app = gone_app("Acme Widget", Some("Acme"), Some(Path::new(&dir)));
        let s = scan(&sb, &reg, &app, false);

        let mut expected = vec![
            r"HKCU\SOFTWARE\Acme",
            r"HKCU\SOFTWARE\Acme\Widget",
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run::AcmeWidget",
            r"HKLM\SOFTWARE\Acme\Widget",
            r"HKLM\SOFTWARE\Classes\CLSID\{AAAAAAAA-0000-0000-0000-000000000001}",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\widget.exe",
            r"HKLM\SOFTWARE\WOW6432Node\Acme",
            r"HKLM\SOFTWARE\WOW6432Node\Acme\Widget",
            r"HKLM\SYSTEM\CurrentControlSet\Services\WidgetSvc",
        ];
        expected.sort();
        assert_eq!(key_paths(&s), expected);
        // HKLM 的 Acme 里还有 Gadget，所以它不会被当作"空厂商键"列出；
        // HKCU / WOW6432Node 下只有本程序，才会连根键一起列出。
        assert!(!key_paths(&s).iter().any(|p| p == r"HKLM\SOFTWARE\Acme"));
        let reason_of = |needle: &str| {
            s.items.iter().find(|l| matches!(&l.target, Target::Key{path,..} | Target::Value{path,..} if path.contains(needle))).unwrap().reason
        };
        assert_eq!(reason_of("WidgetSvc"), Reason::StaleService);
        assert_eq!(reason_of("CLSID"), Reason::ComRegistration);
        assert_eq!(reason_of("App Paths"), Reason::AppPath);
        assert_eq!(reason_of(r"CurrentVersion\Run"), Reason::AutoRun);
        // 服务残留把握较小：不会默认勾选。
        let svc = s
            .items
            .iter()
            .find(|l| l.reason == Reason::StaleService)
            .unwrap();
        assert_eq!(svc.confidence, Confidence::Medium);
    }

    #[test]
    fn a_service_whose_executable_still_exists_is_not_a_leftover() {
        let sb = Sandbox::new();
        let (reg, dir) = registry_fixture(&sb);
        sb.write("PF/Acme Widget/svc.exe", 1);
        let s = scan(
            &sb,
            &reg,
            &gone_app("Acme Widget", Some("Acme"), Some(Path::new(&dir))),
            false,
        );
        assert!(!key_paths(&s).iter().any(|p| p.contains("WidgetSvc")));
    }

    #[test]
    fn emptied_vendor_key_is_proposed_only_when_nothing_else_is_in_it() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Solo\Widget", "v", "1");
        let app = gone_app("Widget", Some("Solo"), None);
        let s = scan(&sb, &reg, &app, false);
        assert_eq!(
            key_paths(&s),
            [r"HKLM\SOFTWARE\Solo", r"HKLM\SOFTWARE\Solo\Widget"]
        );
        let root = s
            .items
            .iter()
            .find(|l| matches!(&l.target, Target::Key { path, .. } if path == r"SOFTWARE\Solo"))
            .unwrap();
        match &root.target {
            Target::Key { kind, .. } => assert_eq!(*kind, KeyKind::EmptiedVendorRoot),
            t => panic!("{t:?}"),
        }

        // 厂商键自己有值：不能整键删除，只删本程序的子键。
        reg.set_sz(LocalMachine, "SOFTWARE\\Solo", "Shared", "1");
        let s = scan(&sb, &reg, &app, false);
        assert_eq!(key_paths(&s), [r"HKLM\SOFTWARE\Solo\Widget"]);
    }

    #[test]
    fn app_named_root_keys_are_medium_confidence_and_reserved_vendors_are_skipped() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Widget", "v", "1");
        reg.set_sz(LocalMachine, r"SOFTWARE\Microsoft\Widget", "v", "1");
        reg.set_sz(LocalMachine, r"SOFTWARE\Classes\Widget", "v", "1");
        let s = scan(&sb, &reg, &gone_app("Widget", None, None), false);
        assert_eq!(key_paths(&s), [r"HKLM\SOFTWARE\Widget"]);
        assert_eq!(s.items[0].confidence, Confidence::Medium);
    }

    #[test]
    fn without_a_safe_install_dir_only_name_based_keys_are_found() {
        let sb = Sandbox::new();
        let (reg, _) = registry_fixture(&sb);
        let s = scan(
            &sb,
            &reg,
            &gone_app("Acme Widget", Some("Acme"), None),
            false,
        );
        let keys = key_paths(&s);
        assert!(keys.contains(&r"HKLM\SOFTWARE\Acme\Widget".to_string()));
        assert!(!keys.iter().any(|k| k.contains("App Paths")
            || k.contains("Services")
            || k.contains("CLSID")
            || k.contains("Run")));
    }

    #[test]
    fn forced_scan_includes_the_uninstall_entry_itself() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        add_app(&reg, LocalMachine, "Broken", "Broken App", &[]);
        let app = app_named(&reg, "Broken");
        let s = scan(&sb, &reg, &app, true);
        assert_eq!(key_paths(&s), [format!("HKLM\\{UNINSTALL_PATH}\\Broken")]);
        assert_eq!(s.items[0].reason, Reason::UninstallEntry);
        assert!(s.still_registered);
    }

    // ----------------------------------------------------------------
    // 删除
    // ----------------------------------------------------------------

    fn ctx<'a>(
        sb: &'a Sandbox,
        reg: &'a MemRegistry,
        policy: &'a SafetyPolicy,
        env: &'a Env,
        cancel: &'a AtomicBool,
    ) -> DeleteCtx<'a> {
        let _ = sb;
        DeleteCtx {
            reg,
            env,
            policy,
            backup_dir: Path::new("/nonexistent-placeholder"),
            app_name: "Acme Widget",
            disposal: Disposal::Permanent,
            cancel,
        }
    }

    fn delete_all(
        sb: &Sandbox,
        reg: &MemRegistry,
        s: &LeftoverScan,
        backup: &Path,
    ) -> Result<DeleteOutcome, DeleteError> {
        let policy = sb.policy();
        let env = sb.env();
        let cancel = AtomicBool::new(false);
        let mut c = ctx(sb, reg, &policy, &env, &cancel);
        c.backup_dir = backup;
        delete_leftovers(&s.items, &c, None)
    }

    #[test]
    fn deletes_registry_and_files_after_writing_a_restorable_backup() {
        let sb = Sandbox::new();
        let (reg, dir) = registry_fixture(&sb);
        sb.write("PF/Acme Widget/widget.exe", 10);
        sb.write("Roaming/AcmeWidget/cfg", 5);
        let app = gone_app("Acme Widget", Some("Acme"), Some(Path::new(&dir)));
        let s = scan(&sb, &reg, &app, false);
        assert!(!s.items.is_empty());

        let backup_dir = sb.base.join("backups");
        let out = delete_all(&sb, &reg, &s, &backup_dir).unwrap();

        // 注册表：目标都已删除，其他内容原样保留。
        assert!(
            out.registry.iter().all(|r| r.status == RegStatus::Deleted),
            "{:?}",
            out.registry
        );
        assert!(!reg.key_exists(LocalMachine, r"SOFTWARE\Acme\Widget"));
        assert!(!reg.key_exists(CurrentUser, r"SOFTWARE\Acme\Widget"));
        assert!(
            reg.key_exists(LocalMachine, r"SOFTWARE\Acme\Gadget"),
            "同厂商的其他程序不能动"
        );
        assert!(reg.key_exists(LocalMachine, r"SOFTWARE\Acme"));
        assert!(reg.key_exists(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other"
        ));
        assert!(reg.key_exists(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\other.exe"
        ));
        assert!(reg
            .value(
                CurrentUser,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "OtherThing"
            )
            .is_some());
        assert!(reg
            .value(
                CurrentUser,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "AcmeWidget"
            )
            .is_none());
        assert!(
            reg.key_exists(
                CurrentUser,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            ),
            "只删值，不删 Run 键"
        );
        assert!(reg.key_exists(
            LocalMachine,
            r"SOFTWARE\Classes\CLSID\{BBBBBBBB-0000-0000-0000-000000000002}"
        ));

        // 文件
        assert!(!sb.base.join("PF/Acme Widget").exists());
        assert!(!sb.base.join("Roaming/AcmeWidget").exists());
        assert!(out.files.freed_bytes >= 15);

        // 备份：UTF-16LE + BOM，内容含被删的键与值。
        let file = out.backup_file.unwrap();
        assert!(file
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with("-Acme_Widget.reg"));
        let bytes = fs::read(&file).unwrap();
        assert_eq!(&bytes[..2], [0xFF, 0xFE]);
        let text = String::from_utf16(
            &bytes[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(text.starts_with("Windows Registry Editor Version 5.00\r\n\r\n"));
        assert!(
            text.contains("[HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\Widget\\Sub]"),
            "子键也要备份"
        );
        assert!(
            text.contains("[HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run]")
        );
        assert!(text.contains("\"AcmeWidget\"="));
        assert!(!text.contains("OtherThing"), "备份只含被删除的内容");
        assert!(!text.contains("Gadget"));
    }

    #[test]
    fn backup_failure_aborts_everything() {
        let sb = Sandbox::new();
        let (reg, dir) = registry_fixture(&sb);
        sb.write("PF/Acme Widget/widget.exe", 10);
        let s = scan(
            &sb,
            &reg,
            &gone_app("Acme Widget", Some("Acme"), Some(Path::new(&dir))),
            false,
        );
        // 备份目录的位置被一个普通文件占住，无法创建。
        let blocker = sb.write("blocked", 1);
        let before = reg.key_count();
        let err = delete_all(&sb, &reg, &s, &blocker.join("sub")).unwrap_err();
        assert!(matches!(err, DeleteError::BackupFailed(_)));
        assert_eq!(reg.key_count(), before, "备份失败时注册表一个键都不能删");
        assert!(
            sb.base.join("PF/Acme Widget/widget.exe").exists(),
            "文件也不能删"
        );
    }

    #[test]
    fn items_outside_the_whitelist_are_refused_even_if_someone_injects_them() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            "ProductName",
            "Windows",
        );
        reg.set_sz(
            LocalMachine,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "x",
            "y",
        );
        reg.set_sz(
            CurrentUser,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoRun",
            "1",
        );
        let key = |hive, path: &str| Leftover {
            target: Target::Key {
                hive,
                path: path.into(),
                kind: KeyKind::Normal,
                guard: None,
            },
            confidence: Confidence::High,
            reason: Reason::NameMatch,
        };
        let items = vec![
            key(
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            ),
            key(
                LocalMachine,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
            ),
            key(
                CurrentUser,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            ),
            key(
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ),
            Leftover {
                target: Target::Value {
                    hive: CurrentUser,
                    path: r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer".into(),
                    name: "NoRun".into(),
                    dir: "x".into(),
                },
                confidence: Confidence::High,
                reason: Reason::AutoRun,
            },
        ];
        let policy = sb.policy();
        let env = sb.env();
        let cancel = AtomicBool::new(false);
        let mut c = ctx(&sb, &reg, &policy, &env, &cancel);
        let backup = sb.base.join("bk");
        c.backup_dir = &backup;
        let out = delete_leftovers(&items, &c, None).unwrap();
        assert_eq!(out.registry.len(), 5);
        assert!(
            out.registry
                .iter()
                .all(|r| matches!(r.status, RegStatus::Refused(_))),
            "{:?}",
            out.registry
        );
        assert!(reg.key_exists(
            LocalMachine,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ));
        assert!(reg.key_exists(
            LocalMachine,
            r"SYSTEM\CurrentControlSet\Control\Session Manager"
        ));
        assert!(reg
            .value(
                CurrentUser,
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoRun"
            )
            .is_some());
        assert!(out.backup_file.is_none(), "没有可删除的项就不产生备份");
    }

    #[test]
    fn guards_refuse_entries_that_changed_since_the_scan() {
        let sb = Sandbox::new();
        let (reg, dir) = registry_fixture(&sb);
        let s = scan(
            &sb,
            &reg,
            &gone_app("Acme Widget", Some("Acme"), Some(Path::new(&dir))),
            false,
        );

        // 扫描之后：服务被重新安装（文件回来了），COM 注册被改指向别处。
        sb.write("PF/Acme Widget/svc.exe", 1);
        reg.set_sz(
            LocalMachine,
            r"SOFTWARE\Classes\CLSID\{AAAAAAAA-0000-0000-0000-000000000001}\InprocServer32",
            "",
            r"C:\Other\new.dll",
        );

        let out = delete_all(&sb, &reg, &s, &sb.base.join("bk")).unwrap();
        let status = |needle: &str| {
            out.registry
                .iter()
                .find(|r| r.path.contains(needle))
                .unwrap()
                .status
                .clone()
        };
        assert!(matches!(status("WidgetSvc"), RegStatus::Refused(_)));
        assert!(matches!(status("{AAAAAAAA"), RegStatus::Refused(_)));
        assert_eq!(
            status(r"Acme\Widget"),
            RegStatus::Deleted,
            "没变化的照常删除"
        );
        assert!(reg.key_exists(LocalMachine, r"SYSTEM\CurrentControlSet\Services\WidgetSvc"));
        assert!(reg.key_exists(
            LocalMachine,
            r"SOFTWARE\Classes\CLSID\{AAAAAAAA-0000-0000-0000-000000000001}"
        ));
    }

    #[test]
    fn a_vendor_root_that_gained_content_is_not_deleted() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Solo\Widget", "v", "1");
        let s = scan(&sb, &reg, &gone_app("Widget", Some("Solo"), None), false);
        assert_eq!(
            key_paths(&s),
            [r"HKLM\SOFTWARE\Solo", r"HKLM\SOFTWARE\Solo\Widget"]
        );
        // 扫描之后，厂商又装了另一款软件。
        reg.set_sz(LocalMachine, r"SOFTWARE\Solo\NewProduct", "v", "1");
        let out = delete_all(&sb, &reg, &s, &sb.base.join("bk")).unwrap();
        let status = |p: &str| {
            out.registry
                .iter()
                .find(|r| r.path == p)
                .unwrap()
                .status
                .clone()
        };
        assert_eq!(
            status(r"SOFTWARE\Solo\Widget"),
            RegStatus::Deleted,
            "本程序的子键照常删除"
        );
        assert!(
            matches!(status(r"SOFTWARE\Solo"), RegStatus::Refused(_)),
            "厂商根键多了新内容就不能删"
        );
        assert!(reg.key_exists(LocalMachine, r"SOFTWARE\Solo\NewProduct"));
        assert!(reg.key_exists(LocalMachine, r"SOFTWARE\Solo"));
    }

    #[test]
    fn already_missing_entries_are_reported_not_failed() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget", "v", "1");
        let s = scan(&sb, &reg, &gone_app("Widget", Some("Acme"), None), false);
        reg.delete_key(LocalMachine, r"SOFTWARE\Acme").unwrap();
        let out = delete_all(&sb, &reg, &s, &sb.base.join("bk")).unwrap();
        assert!(out.registry.iter().all(|r| r.status == RegStatus::Missing));
        assert!(out.backup_file.is_none());
    }

    #[test]
    fn parent_key_deleted_first_does_not_make_children_fail() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget", "v", "1");
        reg.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget\Deep", "v", "1");
        let mk = |path: &str| Leftover {
            target: Target::Key {
                hive: LocalMachine,
                path: path.into(),
                kind: KeyKind::Normal,
                guard: None,
            },
            confidence: Confidence::High,
            reason: Reason::NameMatch,
        };
        let items = vec![
            mk(r"SOFTWARE\Acme\Widget"),
            mk(r"SOFTWARE\Acme\Widget\Deep"),
        ];
        let policy = sb.policy();
        let env = sb.env();
        let cancel = AtomicBool::new(false);
        let mut c = ctx(&sb, &reg, &policy, &env, &cancel);
        let backup = sb.base.join("bk");
        c.backup_dir = &backup;
        let out = delete_leftovers(&items, &c, None).unwrap();
        assert!(
            out.registry
                .iter()
                .all(|r| matches!(r.status, RegStatus::Deleted | RegStatus::Missing)),
            "{:?}",
            out.registry
        );
        assert!(!reg.key_exists(LocalMachine, r"SOFTWARE\Acme\Widget"));
    }

    #[test]
    fn registry_operations_are_journaled() {
        let sb = Sandbox::new();
        let reg = MemRegistry::new();
        reg.set_sz(LocalMachine, r"SOFTWARE\Acme\Widget", "v", "1");
        let s = scan(&sb, &reg, &gone_app("Widget", Some("Acme"), None), false);
        let policy = sb.policy();
        let env = sb.env();
        let cancel = AtomicBool::new(false);
        let mut c = ctx(&sb, &reg, &policy, &env, &cancel);
        let backup = sb.base.join("bk");
        c.backup_dir = &backup;
        let mut buf: Vec<u8> = Vec::new();
        delete_leftovers(&s.items, &c, Some(&mut buf)).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(String::from_utf8(buf).unwrap().lines().next().unwrap()).unwrap();
        assert_eq!(line["op"], "registry");
        assert_eq!(line["hive"], "HKLM");
        assert_eq!(line["path"], r"SOFTWARE\Acme\Widget", "先删子键");
    }

    // ----------------------------------------------------------------
    // 安全策略（Windows 路径风格）
    // ----------------------------------------------------------------

    #[test]
    fn leftover_policy_opens_app_roots_but_keeps_system_and_user_data_protected() {
        let env = Env::from_pairs([
            ("ProgramFiles", r"C:\Program Files"),
            ("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            ("ProgramData", r"C:\ProgramData"),
            ("APPDATA", r"C:\Users\alice\AppData\Roaming"),
            ("LOCALAPPDATA", r"C:\Users\alice\AppData\Local"),
            ("USERPROFILE", r"C:\Users\alice"),
            ("PUBLIC", r"C:\Users\Public"),
        ]);
        let roots = FsRoots::from_env(&env);
        let p = leftover_policy(&KnownDirs::typical("alice"), &roots).unwrap();
        for ok in [
            r"C:\Program Files\Foo",
            r"C:\Program Files (x86)\Foo\bin",
            r"C:\ProgramData\Foo",
            r"C:\Users\alice\AppData\Roaming\Foo",
            r"C:\Users\alice\AppData\Local\Foo\cache",
            r"C:\Users\alice\AppData\Local\Programs\Foo",
            r"C:\Users\alice\AppData\LocalLow\Foo",
            r"D:\Games\Foo",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Foo.lnk",
            r"C:\Users\Public\Desktop\Foo.lnk",
        ] {
            assert!(p.check_delete(ok).is_ok(), "{ok}");
        }
        for bad in [
            r"C:\Program Files",
            r"C:\Windows\System32",
            r"C:\Program Files\Common Files\x",
            r"C:\Program Files\WindowsApps\Pkg",
            r"C:\Program Files\Microsoft Office",
            r"C:\ProgramData\Microsoft\Windows",
            r"C:\Users\alice\AppData\Local\Microsoft\Edge",
            r"C:\Users\alice\AppData\Roaming\Microsoft\Windows",
            r"C:\Users\alice\AppData\Local",
            r"C:\Users\alice\Documents\Foo",
            r"C:\Users\alice",
            r"C:\Users",
            r"D:\",
            r"C:\Program Files\Foo\.git",
        ] {
            assert!(p.check_delete(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn fs_roots_are_built_from_the_environment() {
        let env = Env::from_pairs([
            ("ProgramFiles", r"C:\Program Files"),
            ("ProgramW6432", r"C:\Program Files"),
            ("LOCALAPPDATA", r"C:\Users\a\AppData\Local"),
            ("USERPROFILE", r"C:\Users\a"),
        ]);
        let r = FsRoots::from_env(&env);
        assert_eq!(r.program_files.len(), 1, "重复的目录只算一次");
        assert_eq!(
            r.local_programs.unwrap(),
            PathBuf::from(r"C:\Users\a\AppData\Local").join("Programs")
        );
        assert!(r.program_data.is_none());
        assert_eq!(r.desktops.len(), 1);
    }
}
