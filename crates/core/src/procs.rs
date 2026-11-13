//! 找出"谁占用了某个目录"，并安全地停止它们。
//!
//! 占用来源有三类：
//! * 进程的**可执行文件**在该目录里（运行中的程序本身）；
//! * 进程的**当前工作目录**在该目录里；
//! * **打开了该目录里的文件**，以及持有这些文件的 Windows 服务（Windows 的 Restart Manager 给出）。
//!
//! 停止策略很保守：系统关键进程、资源管理器、本程序自身永远不碰；
//! 先礼貌地请求关闭，只有用户明确要求才强制结束；结束前会再确认 PID 没有被别的进程复用。
//! 外部依赖（进程列表、Restart Manager、命令执行）都通过接口注入，逻辑可以在任何平台上测试。

use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::sysaction::{CommandRunner, ScServices, ServiceControl};

// ====================================================================
// 进程列表
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub parent: Option<u32>,
    pub name: String,
    pub exe: Option<PathBuf>,
    pub cwd: Option<PathBuf>,
    /// 进程启动时间（Unix 秒），与 PID 一起确定"同一个进程"，防止 PID 被复用后误杀。
    pub start_time: u64,
}

pub trait ProcessSource: Send + Sync {
    fn list(&self) -> Vec<ProcInfo>;
}

/// 用 `sysinfo` 读取真实进程列表。
pub struct SysinfoProcesses;

impl ProcessSource for SysinfoProcesses {
    fn list(&self) -> Vec<ProcInfo> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System, UpdateKind};
        // 创建失败（极少见）时当作没有进程，而不是 panic。
        let Ok(mut sys) = System::new_with_specifics(RefreshKind::nothing()) else {
            return Vec::new();
        };
        sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::Always)
                .with_cwd(UpdateKind::Always),
        );
        sys.processes()
            .values()
            .map(|p| ProcInfo {
                pid: p.pid().as_u32(),
                parent: p.parent().map(|x| x.as_u32()),
                name: p.name().to_string_lossy().into_owned(),
                exe: p.exe().map(Path::to_path_buf),
                cwd: p.cwd().map(Path::to_path_buf),
                start_time: p.start_time(),
            })
            .collect()
    }
}

// ====================================================================
// Restart Manager（打开的文件 / 服务）
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmKind {
    Application,
    Service,
    Explorer,
    Console,
    Critical,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmProc {
    pub pid: u32,
    pub name: String,
    /// 服务的短名（仅当它是服务时）。
    pub service: Option<String>,
    pub kind: RmKind,
}

/// 查询"哪些进程打开了这些文件"。
pub trait OpenFileFinder: Send + Sync {
    fn processes_using(&self, files: &[PathBuf]) -> io::Result<Vec<RmProc>>;
}

/// 不支持（非 Windows）时：什么都查不到，但也不报错。
pub struct NoOpenFileFinder;

impl OpenFileFinder for NoOpenFileFinder {
    fn processes_using(&self, _files: &[PathBuf]) -> io::Result<Vec<RmProc>> {
        Ok(Vec::new())
    }
}

/// 解析 `lsof -F pcn` 的输出：`p` 行是 PID，`c` 行是命令名，`n` 行是文件名（这里不需要）。
/// 同一个进程可能因多个文件或线程重复出现，按 PID 去重。
pub fn parse_lsof(output: &str) -> Vec<RmProc> {
    let mut procs: Vec<RmProc> = Vec::new();
    let mut cur: Option<RmProc> = None;
    let flush = |c: Option<RmProc>, procs: &mut Vec<RmProc>| {
        if let Some(c) = c {
            if !procs.iter().any(|p| p.pid == c.pid) {
                procs.push(c);
            }
        }
    };
    for line in output.lines() {
        let (tag, rest) = line.split_at(line.chars().next().map_or(0, char::len_utf8));
        match tag {
            "p" => {
                flush(cur.take(), &mut procs);
                if let Ok(pid) = rest.trim().parse::<u32>() {
                    cur = Some(RmProc {
                        pid,
                        name: String::new(),
                        service: None,
                        kind: RmKind::Application,
                    });
                }
            }
            "c" => {
                if let Some(c) = cur.as_mut() {
                    c.name = rest.to_string();
                }
            }
            _ => {}
        }
    }
    flush(cur.take(), &mut procs);
    procs
}

/// macOS：用 `lsof` 查询哪些进程打开了这些文件。
pub struct LsofFinder(pub std::sync::Arc<dyn CommandRunner>);

impl OpenFileFinder for LsofFinder {
    fn processes_using(&self, files: &[PathBuf]) -> io::Result<Vec<RmProc>> {
        /// 每次调用传给 lsof 的文件数（命令行长度有上限）。
        const BATCH: usize = 200;
        let mut found: Vec<RmProc> = Vec::new();
        for chunk in files.chunks(BATCH) {
            let paths: Vec<String> = chunk
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            let mut args: Vec<&str> = vec!["-F", "pc", "--"];
            args.extend(paths.iter().map(String::as_str));
            let out = self.0.run("/usr/sbin/lsof", &args)?;
            // lsof 没找到任何打开者时退出码为 1、输出为空，这是正常结果。
            if out.code != 0 && out.code != 1 {
                return Err(io::Error::other(format!(
                    "lsof exited with {}: {}",
                    out.code,
                    out.stderr.trim()
                )));
            }
            for p in parse_lsof(&out.stdout) {
                if !found.iter().any(|f| f.pid == p.pid) {
                    found.push(p);
                }
            }
        }
        Ok(found)
    }
}

#[cfg(windows)]
pub use rm::RestartManager;

#[cfg(windows)]
mod rm {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
    use windows_sys::Win32::System::RestartManager::{
        RmConsole, RmCritical, RmEndSession, RmExplorer, RmGetList, RmRegisterResources, RmService,
        RmStartSession, CCH_RM_SESSION_KEY, RM_PROCESS_INFO,
    };

    /// 每个 Restart Manager 会话最多登记的文件数。
    const BATCH: usize = 800;

    pub struct RestartManager;

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn text(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    fn err(code: u32, what: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::Other,
            format!("{what} failed with error {code}"),
        )
    }

    fn query_batch(files: &[PathBuf]) -> io::Result<Vec<RmProc>> {
        let mut session: u32 = 0;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: 所有指针都指向本函数内有效的缓冲区，会话在返回前一定被关闭。
        unsafe {
            let r = RmStartSession(&mut session, 0, key.as_mut_ptr());
            if r != ERROR_SUCCESS {
                return Err(err(r, "RmStartSession"));
            }
            let result = (|| {
                let wides: Vec<Vec<u16>> = files.iter().map(|f| wide(f)).collect();
                let ptrs: Vec<*const u16> = wides.iter().map(|w| w.as_ptr()).collect();
                let r = RmRegisterResources(
                    session,
                    ptrs.len() as u32,
                    ptrs.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                );
                if r != ERROR_SUCCESS {
                    return Err(err(r, "RmRegisterResources"));
                }
                let mut needed: u32 = 0;
                let mut count: u32 = 0;
                let mut reasons: u32 = 0;
                let mut r = RmGetList(
                    session,
                    &mut needed,
                    &mut count,
                    std::ptr::null_mut(),
                    &mut reasons,
                );
                let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
                // 进程数可能在两次调用之间变化，循环直到缓冲区够大。
                for _ in 0..5 {
                    if r == ERROR_SUCCESS && needed == 0 {
                        return Ok(Vec::new());
                    }
                    if r != ERROR_MORE_DATA && r != ERROR_SUCCESS {
                        return Err(err(r, "RmGetList"));
                    }
                    infos = vec![std::mem::zeroed(); needed as usize + 4];
                    count = infos.len() as u32;
                    r = RmGetList(
                        session,
                        &mut needed,
                        &mut count,
                        infos.as_mut_ptr(),
                        &mut reasons,
                    );
                    if r == ERROR_SUCCESS {
                        infos.truncate(count as usize);
                        break;
                    }
                    if r != ERROR_MORE_DATA {
                        return Err(err(r, "RmGetList"));
                    }
                }
                Ok(infos
                    .iter()
                    .map(|i| {
                        let kind = match i.ApplicationType {
                            t if t == RmService => RmKind::Service,
                            t if t == RmExplorer => RmKind::Explorer,
                            t if t == RmConsole => RmKind::Console,
                            t if t == RmCritical => RmKind::Critical,
                            1 | 2 => RmKind::Application,
                            _ => RmKind::Other,
                        };
                        let svc = text(&i.strServiceShortName);
                        RmProc {
                            pid: i.Process.dwProcessId,
                            name: text(&i.strAppName),
                            service: (!svc.is_empty()).then_some(svc),
                            kind,
                        }
                    })
                    .collect())
            })();
            RmEndSession(session);
            result
        }
    }

    impl OpenFileFinder for RestartManager {
        fn processes_using(&self, files: &[PathBuf]) -> io::Result<Vec<RmProc>> {
            let mut all: Vec<RmProc> = Vec::new();
            for chunk in files.chunks(BATCH) {
                for p in query_batch(chunk)? {
                    if !all.iter().any(|x| x.pid == p.pid && x.service == p.service) {
                        all.push(p);
                    }
                }
            }
            Ok(all)
        }
    }
}

// ====================================================================
// 占用者
// ====================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    /// 进程的可执行文件在该目录里。
    Image,
    /// 进程的当前工作目录在该目录里。
    CurrentDir,
    /// 进程打开了该目录里的文件。
    OpenFile,
    /// 由 Windows 服务持有。
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protection {
    /// 本程序自己。
    ThisApp,
    /// 系统关键进程，结束会导致系统不稳定。
    Critical,
    /// 资源管理器：它占用通常是因为有窗口停在这个目录，应关闭窗口而不是结束它。
    Explorer,
    /// 承载多个服务的 `svchost`，且不知道具体是哪个服务。
    ServiceHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelatedReason {
    /// 是占用者的子孙进程。
    Descendant,
    /// 与占用者的可执行文件在同一个安装目录（同一个程序的其他进程）。
    SameFolder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Related {
    pub pid: u32,
    pub name: String,
    pub reason: RelatedReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    pub pid: u32,
    pub name: String,
    pub exe: Option<String>,
    pub kinds: Vec<BlockerKind>,
    /// 占用它的服务短名（如果是服务）。
    pub service: Option<String>,
    pub protection: Option<Protection>,
    pub related: Vec<Related>,
    pub start_time: u64,
}

#[derive(Debug, Clone, Default)]
pub struct BlockerReport {
    pub blockers: Vec<Blocker>,
    /// Restart Manager 查询失败时的说明（此时只有按路径找到的结果）。
    pub rm_error: Option<String>,
    pub files_checked: usize,
    /// 文件太多，只检查了其中一部分。
    pub truncated: bool,
}

/// 永远不允许结束的系统进程（小写）。
const CRITICAL: &[&str] = &[
    "system",
    "system idle process",
    "registry",
    "memory compression",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "lsaiso.exe",
    "securityhealthservice.exe",
    "sihost.exe",
    "ctfmon.exe",
    // macOS
    "launchd",
    "kernel_task",
    "windowserver",
    "loginwindow",
    "systemuiserver",
    "dock",
    "coreservicesd",
    "launchservicesd",
    "opendirectoryd",
    "configd",
    "cfprefsd",
    "securityd",
    "trustd",
    "mds",
    "mds_stores",
    "diskarbitrationd",
    "fseventsd",
    "notifyd",
    "logd",
    "powerd",
    "coreaudiod",
    "bluetoothd",
    "hidd",
];

fn protection_of(p: &ProcInfo, self_pid: u32) -> Option<Protection> {
    let n = p.name.to_lowercase();
    if p.pid == self_pid {
        Some(Protection::ThisApp)
    } else if p.pid <= 4 || CRITICAL.contains(&n.as_str()) {
        Some(Protection::Critical)
    } else if n == "explorer.exe" || n == "finder" {
        Some(Protection::Explorer)
    } else {
        None
    }
}

fn under(p: &Path, dir: &Path) -> bool {
    let norm = |x: &Path| {
        x.to_string_lossy()
            .replace('/', "\\")
            .to_lowercase()
            .trim_end_matches('\\')
            .to_string()
    };
    let (a, d) = (norm(p), norm(dir));
    a == d || a.starts_with(&format!("{d}\\"))
}

/// 要登记给 Restart Manager 的文件数上限（目录里文件特别多时只取一部分）。
pub const MAX_RM_FILES: usize = 20_000;

/// 列出目录里的文件（用于 Restart Manager），最多 `MAX_RM_FILES` 个。返回 (文件, 是否被截断)。
pub fn collect_files(dir: &Path) -> (Vec<PathBuf>, bool) {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if crate::scanner::special_reason(&m).is_some() {
                continue;
            }
            if m.is_dir() {
                stack.push(e.path());
            } else {
                if out.len() >= MAX_RM_FILES {
                    return (out, true);
                }
                out.push(e.path());
            }
        }
    }
    (out, false)
}

/// 找出占用 `dir` 的进程及其相关进程。
///
/// `system_dirs`：系统目录（如 `C:\Windows`）。位于其中的进程不会被当作"同一个程序的其他进程"。
pub fn find_blockers(
    dir: &Path,
    procs: &dyn ProcessSource,
    rm: &dyn OpenFileFinder,
    files: &[PathBuf],
    truncated: bool,
    self_pid: u32,
    system_dirs: &[PathBuf],
) -> BlockerReport {
    let list = procs.list();
    let by_pid: HashMap<u32, &ProcInfo> = list.iter().map(|p| (p.pid, p)).collect();

    // pid -> (kinds, service)
    let mut found: HashMap<u32, (BTreeSet<BlockerKind>, Option<String>)> = HashMap::new();
    for p in &list {
        if p.exe.as_deref().is_some_and(|e| under(e, dir)) {
            found.entry(p.pid).or_default().0.insert(BlockerKind::Image);
        }
        if p.cwd.as_deref().is_some_and(|c| under(c, dir)) {
            found
                .entry(p.pid)
                .or_default()
                .0
                .insert(BlockerKind::CurrentDir);
        }
    }

    let mut rm_error = None;
    if !files.is_empty() {
        match rm.processes_using(files) {
            Ok(users) => {
                for u in users {
                    let e = found.entry(u.pid).or_default();
                    if u.kind == RmKind::Service || u.service.is_some() {
                        e.0.insert(BlockerKind::Service);
                        e.1 = e.1.take().or(u.service);
                    } else {
                        e.0.insert(BlockerKind::OpenFile);
                    }
                }
            }
            Err(e) => rm_error = Some(e.to_string()),
        }
    }

    let mut blockers: Vec<Blocker> = Vec::new();
    for (pid, (kinds, service)) in &found {
        // RM 报告了已不存在的进程时，没有可展示的信息，直接忽略。
        let Some(p) = by_pid.get(pid) else { continue };
        let mut protection = protection_of(p, self_pid);
        // 承载服务的 svchost：知道具体服务名才能通过停服务处理，否则不允许动它。
        if protection.is_none() && p.name.eq_ignore_ascii_case("svchost.exe") && service.is_none() {
            protection = Some(Protection::ServiceHost);
        }
        blockers.push(Blocker {
            pid: *pid,
            name: p.name.clone(),
            exe: p.exe.as_deref().map(|e| e.to_string_lossy().into_owned()),
            kinds: kinds.iter().copied().collect(),
            service: service.clone(),
            protection,
            related: Vec::new(),
            start_time: p.start_time,
        });
    }
    blockers.sort_by(|a, b| {
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.pid.cmp(&b.pid))
    });

    // 相关进程：子孙进程，以及与它同一个安装目录的其他进程。
    let blocker_pids: HashSet<u32> = blockers.iter().map(|b| b.pid).collect();
    for b in &mut blockers {
        if b.protection.is_some() {
            continue;
        }
        let mut seen: HashSet<u32> = HashSet::new();
        for d in descendants(b.pid, &list) {
            if blocker_pids.contains(&d.pid) || protection_of(d, self_pid).is_some() {
                continue;
            }
            if seen.insert(d.pid) {
                b.related.push(Related {
                    pid: d.pid,
                    name: d.name.clone(),
                    reason: RelatedReason::Descendant,
                });
            }
        }
        // 同目录进程只在"程序自己的安装目录"成立：可执行文件所在目录不能是系统目录或其祖先。
        if let Some(home) = by_pid
            .get(&b.pid)
            .and_then(|p| p.exe.as_deref())
            .and_then(Path::parent)
        {
            let in_system = system_dirs.iter().any(|s| under(home, s) || under(s, home));
            if !in_system {
                for p in &list {
                    if p.pid != b.pid
                        && !blocker_pids.contains(&p.pid)
                        && protection_of(p, self_pid).is_none()
                        && p.exe.as_deref().is_some_and(|e| under(e, home))
                        && seen.insert(p.pid)
                    {
                        b.related.push(Related {
                            pid: p.pid,
                            name: p.name.clone(),
                            reason: RelatedReason::SameFolder,
                        });
                    }
                }
            }
        }
        b.related.sort_by_key(|r| r.pid);
    }

    BlockerReport {
        blockers,
        rm_error,
        files_checked: files.len(),
        truncated,
    }
}

/// `pid` 的所有子孙进程（不含自己）。
fn descendants(pid: u32, list: &[ProcInfo]) -> Vec<&ProcInfo> {
    let mut out: Vec<&ProcInfo> = Vec::new();
    let mut frontier = vec![pid];
    let mut seen: HashSet<u32> = HashSet::from([pid]);
    while let Some(cur) = frontier.pop() {
        for p in list.iter().filter(|p| p.parent == Some(cur)) {
            if seen.insert(p.pid) {
                out.push(p);
                frontier.push(p.pid);
            }
        }
    }
    out
}

// ====================================================================
// 停止进程
// ====================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepKind {
    Process,
    /// 通过停止 Windows 服务来释放，而不是结束进程。
    Service(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopStep {
    pub pid: u32,
    pub name: String,
    pub start_time: u64,
    pub exe: Option<PathBuf>,
    pub kind: StepKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopStatus {
    /// 请求关闭后正常退出。
    Exited,
    /// 经强制结束后退出。
    Forced,
    /// 服务已停止。
    ServiceStopped,
    /// 在我们动手之前它已经不在了（或 PID 已被别的程序复用）。
    AlreadyGone,
    /// 仍在运行（未勾选强制，或强制后仍未退出）。
    StillRunning,
    /// 受保护，拒绝操作。
    Refused(String),
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopResult {
    pub pid: u32,
    pub name: String,
    pub status: StopStatus,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StopPlan {
    pub steps: Vec<StopStep>,
    pub refused: Vec<StopResult>,
}

/// 生成停止计划：`selected` 是用户勾选的占用者；`include_related` 为真时连同它们的相关进程。
///
/// 顺序是**子进程在前、父进程在后**，避免父进程把刚结束的子进程重新拉起时来不及处理。
/// 受保护的进程不会进入计划，而是记入 `refused`。
pub fn plan_stop(
    report: &BlockerReport,
    selected: &[u32],
    include_related: bool,
    procs: &dyn ProcessSource,
    self_pid: u32,
) -> StopPlan {
    let list = procs.list();
    let by_pid: HashMap<u32, &ProcInfo> = list.iter().map(|p| (p.pid, p)).collect();
    let mut plan = StopPlan::default();
    let mut wanted: Vec<(u32, Option<String>)> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();

    for pid in selected {
        let Some(b) = report.blockers.iter().find(|b| b.pid == *pid) else {
            // 不在占用者清单里的 PID 一律不处理：前端不能让后端去结束任意进程。
            plan.refused.push(StopResult {
                pid: *pid,
                name: String::new(),
                status: StopStatus::Refused("not a blocker".into()),
            });
            continue;
        };
        if let Some(prot) = b.protection {
            plan.refused.push(StopResult {
                pid: b.pid,
                name: b.name.clone(),
                status: StopStatus::Refused(format!("{prot:?}")),
            });
            continue;
        }
        if seen.insert(b.pid) {
            wanted.push((b.pid, b.service.clone()));
        }
        if include_related {
            for r in &b.related {
                if seen.insert(r.pid) {
                    wanted.push((r.pid, None));
                }
            }
        }
    }

    for (pid, service) in wanted {
        let Some(p) = by_pid.get(&pid) else { continue };
        // 相关进程在生成清单之后可能变成受保护对象（例如 PID 复用），再检查一次。
        if let Some(prot) = protection_of(p, self_pid) {
            plan.refused.push(StopResult {
                pid,
                name: p.name.clone(),
                status: StopStatus::Refused(format!("{prot:?}")),
            });
            continue;
        }
        plan.steps.push(StopStep {
            pid,
            name: p.name.clone(),
            start_time: p.start_time,
            exe: p.exe.clone(),
            kind: service.map_or(StepKind::Process, StepKind::Service),
        });
    }

    // 深度大的（更靠近叶子）先停。
    let depth = |pid: u32| -> usize {
        let mut d = 0;
        let mut cur = by_pid.get(&pid).and_then(|p| p.parent);
        while let Some(par) = cur {
            d += 1;
            if d > 64 {
                break;
            }
            cur = by_pid.get(&par).and_then(|p| p.parent);
        }
        d
    };
    plan.steps.sort_by_key(|s| std::cmp::Reverse(depth(s.pid)));
    plan
}

#[derive(Debug, Clone, Copy)]
pub struct StopTiming {
    /// 请求关闭后最多等多久。
    pub graceful_wait: Duration,
    /// 强制结束后最多等多久。
    pub force_wait: Duration,
    pub poll: Duration,
}

impl Default for StopTiming {
    fn default() -> Self {
        Self {
            graceful_wait: Duration::from_secs(8),
            force_wait: Duration::from_secs(3),
            poll: Duration::from_millis(250),
        }
    }
}

fn same_process(p: &ProcInfo, step: &StopStep) -> bool {
    p.pid == step.pid && p.start_time == step.start_time && p.name.eq_ignore_ascii_case(&step.name)
}

fn wait_gone(procs: &dyn ProcessSource, step: &StopStep, total: Duration, poll: Duration) -> bool {
    let start = Instant::now();
    loop {
        if !procs.list().iter().any(|p| same_process(p, step)) {
            return true;
        }
        if start.elapsed() >= total {
            return false;
        }
        thread::sleep(poll);
    }
}

/// 结束进程用的命令：Windows 用 `taskkill`，macOS 用 `kill`（SIGTERM → SIGKILL）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopCommands {
    Windows,
    Unix,
}

impl StopCommands {
    pub fn for_platform() -> Self {
        if cfg!(windows) {
            StopCommands::Windows
        } else if cfg!(target_os = "macos") {
            StopCommands::Unix
        } else {
            // 其他平台没有受支持的前端，沿用原行为；测试依赖这一点。
            StopCommands::Windows
        }
    }

    pub fn graceful(self, pid: &str) -> (&'static str, Vec<String>) {
        match self {
            StopCommands::Windows => ("taskkill.exe", vec!["/PID".into(), pid.into()]),
            StopCommands::Unix => ("/bin/kill", vec!["-TERM".into(), pid.into()]),
        }
    }

    pub fn force(self, pid: &str) -> (&'static str, Vec<String>) {
        match self {
            StopCommands::Windows => ("taskkill.exe", vec!["/PID".into(), pid.into(), "/F".into()]),
            StopCommands::Unix => ("/bin/kill", vec!["-KILL".into(), pid.into()]),
        }
    }
}

/// 执行停止计划。`force` 为真时，礼貌关闭超时后再强制结束。
///
/// 每一步之前都会重新确认"这个 PID 还是当初那个进程"（PID、启动时间、名称都一致），
/// 防止进程退出后 PID 被别的程序复用而误杀。
pub fn execute_stop(
    plan: &StopPlan,
    force: bool,
    procs: &dyn ProcessSource,
    runner: &dyn CommandRunner,
    timing: StopTiming,
) -> Vec<StopResult> {
    let mut out: Vec<StopResult> = plan.refused.clone();
    let services = ScServices::new(runner);
    for step in &plan.steps {
        let mk = |status| StopResult {
            pid: step.pid,
            name: step.name.clone(),
            status,
        };
        let alive = procs.list().iter().any(|p| same_process(p, step));
        if !alive {
            out.push(mk(StopStatus::AlreadyGone));
            continue;
        }
        if let StepKind::Service(svc) = &step.kind {
            out.push(mk(match services.stop(svc) {
                Ok(_) => StopStatus::ServiceStopped,
                Err(e) => StopStatus::Failed(e),
            }));
            continue;
        }
        let pid = step.pid.to_string();
        let cmds = StopCommands::for_platform();
        // 礼貌地请求关闭（Windows 向窗口发送关闭消息；macOS 发送 SIGTERM）。
        let (prog, args) = cmds.graceful(&pid);
        let _ = runner.run(prog, &args.iter().map(String::as_str).collect::<Vec<_>>());
        if wait_gone(procs, step, timing.graceful_wait, timing.poll) {
            out.push(mk(StopStatus::Exited));
            continue;
        }
        if !force {
            out.push(mk(StopStatus::StillRunning));
            continue;
        }
        // 强制前再确认一次，尽量缩小 PID 复用的窗口。
        if !procs.list().iter().any(|p| same_process(p, step)) {
            out.push(mk(StopStatus::Exited));
            continue;
        }
        let (prog, args) = cmds.force(&pid);
        match runner.run(prog, &args.iter().map(String::as_str).collect::<Vec<_>>()) {
            Ok(_) if wait_gone(procs, step, timing.force_wait, timing.poll) => {
                out.push(mk(StopStatus::Forced))
            }
            Ok(_) => out.push(mk(StopStatus::StillRunning)),
            Err(e) => out.push(mk(StopStatus::Failed(e.to_string()))),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysaction::CmdOutput;
    use std::sync::Mutex;

    fn p(
        pid: u32,
        parent: Option<u32>,
        name: &str,
        exe: Option<&str>,
        cwd: Option<&str>,
    ) -> ProcInfo {
        ProcInfo {
            pid,
            parent,
            name: name.into(),
            exe: exe.map(PathBuf::from),
            cwd: cwd.map(PathBuf::from),
            start_time: 1000 + u64::from(pid),
        }
    }

    struct FakeProcs(Mutex<Vec<ProcInfo>>);
    impl FakeProcs {
        fn new(v: Vec<ProcInfo>) -> Self {
            Self(Mutex::new(v))
        }
        fn remove(&self, pid: u32) {
            self.0.lock().unwrap().retain(|p| p.pid != pid);
        }
    }
    impl ProcessSource for FakeProcs {
        fn list(&self) -> Vec<ProcInfo> {
            self.0.lock().unwrap().clone()
        }
    }

    struct FakeRm(io::Result<Vec<RmProc>>);
    impl OpenFileFinder for FakeRm {
        fn processes_using(&self, _: &[PathBuf]) -> io::Result<Vec<RmProc>> {
            match &self.0 {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
            }
        }
    }

    fn rm_app(pid: u32, name: &str) -> RmProc {
        RmProc {
            pid,
            name: name.into(),
            service: None,
            kind: RmKind::Application,
        }
    }

    const DIR: &str = r"C:\Users\a\AppData\Local\Docker";
    const SYS: &[&str] = &[r"C:\Windows"];

    fn sys() -> Vec<PathBuf> {
        SYS.iter().map(PathBuf::from).collect()
    }

    fn files() -> Vec<PathBuf> {
        vec![PathBuf::from(format!(r"{DIR}\data.vhdx"))]
    }

    fn find(list: Vec<ProcInfo>, rm: io::Result<Vec<RmProc>>) -> BlockerReport {
        find_blockers(
            Path::new(DIR),
            &FakeProcs::new(list),
            &FakeRm(rm),
            &files(),
            false,
            999,
            &sys(),
        )
    }

    // ----- 找占用者 -----

    #[test]
    fn finds_processes_by_image_cwd_and_open_files() {
        let report = find(
            vec![
                p(
                    10,
                    Some(1),
                    "docker.exe",
                    Some(&format!(r"{DIR}\bin\docker.exe")),
                    None,
                ),
                p(
                    11,
                    Some(1),
                    "shell.exe",
                    Some(r"C:\Windows\System32\cmd.exe"),
                    Some(&format!(r"{DIR}\logs")),
                ),
                p(12, Some(1), "db.exe", Some(r"C:\Other\db.exe"), None),
                p(
                    13,
                    Some(1),
                    "bystander.exe",
                    Some(r"C:\Other\b.exe"),
                    Some(r"C:\Elsewhere"),
                ),
            ],
            Ok(vec![rm_app(12, "Database")]),
        );
        let get = |pid| report.blockers.iter().find(|b| b.pid == pid).unwrap();
        assert_eq!(get(10).kinds, [BlockerKind::Image]);
        assert_eq!(get(11).kinds, [BlockerKind::CurrentDir]);
        assert_eq!(get(12).kinds, [BlockerKind::OpenFile]);
        assert!(!report.blockers.iter().any(|b| b.pid == 13));
        assert_eq!(report.files_checked, 1);
        assert!(report.rm_error.is_none());
    }

    #[test]
    fn matching_respects_directory_boundaries_and_case() {
        let report = find(
            vec![
                p(
                    1,
                    None,
                    "a.exe",
                    Some(r"c:\users\a\appdata\local\DOCKER\x.exe"),
                    None,
                ), // 大小写不同：算
                p(
                    2,
                    None,
                    "b.exe",
                    Some(r"C:\Users\a\AppData\Local\DockerDesktop\x.exe"),
                    None,
                ), // 前缀相同但不是子目录：不算
            ],
            Ok(vec![]),
        );
        assert_eq!(
            report.blockers.iter().map(|b| b.pid).collect::<Vec<_>>(),
            [1]
        );
    }

    #[test]
    fn one_process_with_several_reasons_is_listed_once() {
        let report = find(
            vec![p(
                5,
                None,
                "app.exe",
                Some(&format!(r"{DIR}\app.exe")),
                Some(DIR),
            )],
            Ok(vec![rm_app(5, "App")]),
        );
        assert_eq!(report.blockers.len(), 1);
        assert_eq!(
            report.blockers[0].kinds,
            [
                BlockerKind::Image,
                BlockerKind::CurrentDir,
                BlockerKind::OpenFile
            ]
        );
    }

    #[test]
    fn rm_failure_is_reported_but_path_based_results_remain() {
        let report = find(
            vec![p(
                10,
                None,
                "docker.exe",
                Some(&format!(r"{DIR}\docker.exe")),
                None,
            )],
            Err(io::Error::other("RmStartSession failed with error 5")),
        );
        assert_eq!(report.blockers.len(), 1);
        assert!(report.rm_error.unwrap().contains("error 5"));
    }

    #[test]
    fn rm_reporting_a_process_that_no_longer_exists_is_ignored() {
        let report = find(vec![], Ok(vec![rm_app(4242, "Ghost")]));
        assert!(report.blockers.is_empty());
    }

    #[test]
    fn services_are_recorded_with_their_service_name() {
        let report = find(
            vec![p(
                20,
                Some(1),
                "svchost.exe",
                Some(r"C:\Windows\System32\svchost.exe"),
                None,
            )],
            Ok(vec![RmProc {
                pid: 20,
                name: "Docker Service".into(),
                service: Some("com.docker.service".into()),
                kind: RmKind::Service,
            }]),
        );
        let b = &report.blockers[0];
        assert_eq!(b.kinds, [BlockerKind::Service]);
        assert_eq!(b.service.as_deref(), Some("com.docker.service"));
        assert_eq!(b.protection, None, "知道具体服务名，就可以通过停服务处理");
    }

    #[test]
    fn protected_processes_are_flagged() {
        let report = find_blockers(
            Path::new(DIR),
            &FakeProcs::new(vec![
                p(4, None, "System", None, None),
                p(
                    30,
                    Some(1),
                    "explorer.exe",
                    Some(r"C:\Windows\explorer.exe"),
                    Some(DIR),
                ),
                p(
                    31,
                    Some(1),
                    "lsass.exe",
                    Some(r"C:\Windows\System32\lsass.exe"),
                    None,
                ),
                p(
                    999,
                    Some(1),
                    "diskclean.exe",
                    Some(r"C:\Apps\diskclean.exe"),
                    Some(DIR),
                ),
                p(
                    32,
                    Some(1),
                    "svchost.exe",
                    Some(r"C:\Windows\System32\svchost.exe"),
                    None,
                ),
                p(33, Some(1), "ok.exe", Some(&format!(r"{DIR}\ok.exe")), None),
            ]),
            &FakeRm(Ok(vec![
                rm_app(4, "System"),
                rm_app(31, "LSA"),
                rm_app(32, "Host"),
            ])),
            &files(),
            false,
            999,
            &sys(),
        );
        let prot = |pid| {
            report
                .blockers
                .iter()
                .find(|b| b.pid == pid)
                .unwrap()
                .protection
        };
        assert_eq!(prot(4), Some(Protection::Critical));
        assert_eq!(prot(30), Some(Protection::Explorer));
        assert_eq!(prot(31), Some(Protection::Critical));
        assert_eq!(prot(999), Some(Protection::ThisApp));
        assert_eq!(
            prot(32),
            Some(Protection::ServiceHost),
            "不知道具体服务的 svchost 不能动"
        );
        assert_eq!(prot(33), None);
    }

    // ----- 相关进程 -----

    #[test]
    fn related_processes_are_descendants_and_same_install_folder() {
        let list = vec![
            p(
                1,
                None,
                "launcher.exe",
                Some(r"C:\Apps\Foo\launcher.exe"),
                None,
            ),
            p(
                10,
                Some(1),
                "foo.exe",
                Some(&format!(r"{DIR}\foo.exe")),
                None,
            ), // 占用者
            p(
                11,
                Some(10),
                "foo-helper.exe",
                Some(r"C:\Elsewhere\h.exe"),
                None,
            ), // 子进程
            p(
                12,
                Some(11),
                "foo-gpu.exe",
                Some(r"C:\Elsewhere\g.exe"),
                None,
            ), // 孙进程
            p(
                13,
                Some(1),
                "foo-tray.exe",
                Some(&format!(r"{DIR}\tray.exe")),
                None,
            ), // 同目录（本身也是占用者）
            p(
                14,
                Some(1),
                "foo-updater.exe",
                Some(&format!(r"{DIR}\updater\u.exe")),
                None,
            ),
            p(15, Some(1), "other.exe", Some(r"C:\Other\o.exe"), None),
        ];
        let report = find(list, Ok(vec![]));
        let b = report.blockers.iter().find(|b| b.pid == 10).unwrap();
        let rel: Vec<(u32, RelatedReason)> = b.related.iter().map(|r| (r.pid, r.reason)).collect();
        assert!(rel.contains(&(11, RelatedReason::Descendant)));
        assert!(rel.contains(&(12, RelatedReason::Descendant)));
        assert!(
            !rel.iter().any(|(pid, _)| *pid == 13 || *pid == 14),
            "同目录进程本身就是占用者，不重复列为相关"
        );
        assert!(!rel.iter().any(|(pid, _)| *pid == 15 || *pid == 1));
    }

    #[test]
    fn same_folder_rule_does_not_apply_to_system_directories() {
        // 占用者是系统目录里的程序：不能把整个 System32 里的进程都当成"相关"。
        let list = vec![
            p(
                10,
                Some(1),
                "cmd.exe",
                Some(r"C:\Windows\System32\cmd.exe"),
                Some(DIR),
            ),
            p(
                11,
                Some(1),
                "notepad.exe",
                Some(r"C:\Windows\System32\notepad.exe"),
                None,
            ),
            p(
                12,
                Some(1),
                "calc.exe",
                Some(r"C:\Windows\System32\calc.exe"),
                None,
            ),
        ];
        let report = find(list, Ok(vec![]));
        let b = &report.blockers[0];
        assert!(b.related.is_empty(), "{:?}", b.related);
    }

    #[test]
    fn protected_descendants_are_never_listed_as_related() {
        let list = vec![
            p(
                10,
                Some(1),
                "foo.exe",
                Some(&format!(r"{DIR}\foo.exe")),
                None,
            ),
            p(
                11,
                Some(10),
                "lsass.exe",
                Some(r"C:\Windows\System32\lsass.exe"),
                None,
            ),
            p(
                12,
                Some(10),
                "explorer.exe",
                Some(r"C:\Windows\explorer.exe"),
                None,
            ),
            p(13, Some(10), "child.exe", Some(r"C:\X\c.exe"), None),
        ];
        let report = find(list, Ok(vec![]));
        let b = report.blockers.iter().find(|b| b.pid == 10).unwrap();
        assert_eq!(b.related.iter().map(|r| r.pid).collect::<Vec<_>>(), [13]);
    }

    // ----- 停止计划 -----

    fn report_with_family() -> (BlockerReport, FakeProcs) {
        let list = vec![
            p(1, None, "launcher.exe", Some(r"C:\Apps\launcher.exe"), None),
            p(
                10,
                Some(1),
                "foo.exe",
                Some(&format!(r"{DIR}\foo.exe")),
                None,
            ),
            p(11, Some(10), "foo-helper.exe", Some(r"C:\E\h.exe"), None),
            p(12, Some(11), "foo-gpu.exe", Some(r"C:\E\g.exe"), None),
            p(
                40,
                Some(1),
                "explorer.exe",
                Some(r"C:\Windows\explorer.exe"),
                Some(DIR),
            ),
        ];
        let procs = FakeProcs::new(list.clone());
        let report = find_blockers(
            Path::new(DIR),
            &procs,
            &FakeRm(Ok(vec![])),
            &files(),
            false,
            999,
            &sys(),
        );
        (report, procs)
    }

    #[test]
    fn stop_plan_orders_children_before_parents() {
        let (report, procs) = report_with_family();
        let plan = plan_stop(&report, &[10], true, &procs, 999);
        assert_eq!(
            plan.steps.iter().map(|s| s.pid).collect::<Vec<_>>(),
            [12, 11, 10]
        );
        let alone = plan_stop(&report, &[10], false, &procs, 999);
        assert_eq!(alone.steps.iter().map(|s| s.pid).collect::<Vec<_>>(), [10]);
    }

    #[test]
    fn stop_plan_refuses_protected_and_unknown_pids() {
        let (report, procs) = report_with_family();
        let plan = plan_stop(&report, &[40, 1, 12345], true, &procs, 999);
        assert!(plan.steps.is_empty());
        assert_eq!(plan.refused.len(), 3);
        assert!(plan
            .refused
            .iter()
            .all(|r| matches!(r.status, StopStatus::Refused(_))));
        // 不在占用者清单里的 PID（比如启动器 1）不能被结束，即使前端传了它。
        assert!(plan.refused.iter().any(|r| r.pid == 1));
    }

    #[test]
    fn service_blockers_become_service_stops() {
        let list = vec![p(
            20,
            Some(1),
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            None,
        )];
        let procs = FakeProcs::new(list);
        let report = find_blockers(
            Path::new(DIR),
            &procs,
            &FakeRm(Ok(vec![RmProc {
                pid: 20,
                name: "Docker".into(),
                service: Some("DockerSvc".into()),
                kind: RmKind::Service,
            }])),
            &files(),
            false,
            999,
            &sys(),
        );
        let plan = plan_stop(&report, &[20], true, &procs, 999);
        assert_eq!(plan.steps[0].kind, StepKind::Service("DockerSvc".into()));
    }

    // ----- 执行停止 -----

    /// 模拟 taskkill：普通请求让 `graceful` 里的进程退出，/F 让所有进程退出。
    struct KillRunner<'a> {
        procs: &'a FakeProcs,
        graceful: Vec<u32>,
        calls: Mutex<Vec<String>>,
    }
    impl CommandRunner for KillRunner<'_> {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            if program == "taskkill.exe" {
                let pid: u32 = args[1].parse().unwrap();
                let forced = args.contains(&"/F");
                if forced || self.graceful.contains(&pid) {
                    self.procs.remove(pid);
                }
            }
            Ok(CmdOutput::default())
        }
    }

    fn fast() -> StopTiming {
        StopTiming {
            graceful_wait: Duration::from_millis(10),
            force_wait: Duration::from_millis(10),
            poll: Duration::from_millis(1),
        }
    }

    #[test]
    fn graceful_first_then_force_only_when_asked() {
        let (report, procs) = report_with_family();
        let plan = plan_stop(&report, &[10], true, &procs, 999);
        // 12 会礼貌退出；11、10 不理会礼貌请求。
        let runner = KillRunner {
            procs: &procs,
            graceful: vec![12],
            calls: Mutex::default(),
        };

        let no_force = execute_stop(&plan, false, &procs, &runner, fast());
        let status =
            |r: &[StopResult], pid| r.iter().find(|x| x.pid == pid).unwrap().status.clone();
        assert_eq!(status(&no_force, 12), StopStatus::Exited);
        assert_eq!(status(&no_force, 11), StopStatus::StillRunning);
        assert_eq!(status(&no_force, 10), StopStatus::StillRunning);
        assert!(
            !runner
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c.contains("/F")),
            "没要求强制就不能强制"
        );

        let forced = execute_stop(&plan, true, &procs, &runner, fast());
        assert_eq!(
            status(&forced, 12),
            StopStatus::AlreadyGone,
            "已退出的不再处理"
        );
        assert_eq!(status(&forced, 11), StopStatus::Forced);
        assert_eq!(status(&forced, 10), StopStatus::Forced);
    }

    #[test]
    fn a_reused_pid_is_never_killed() {
        let (report, procs) = report_with_family();
        let plan = plan_stop(&report, &[10], false, &procs, 999);
        // 计划之后，原进程 10 退出，PID 10 被一个无关的新进程复用（启动时间不同）。
        procs.remove(10);
        procs.0.lock().unwrap().push(ProcInfo {
            start_time: 99_999,
            ..p(10, Some(1), "innocent.exe", Some(r"C:\Q\i.exe"), None)
        });
        let runner = KillRunner {
            procs: &procs,
            graceful: vec![],
            calls: Mutex::default(),
        };
        let res = execute_stop(&plan, true, &procs, &runner, fast());
        assert_eq!(res[0].status, StopStatus::AlreadyGone);
        assert!(
            runner.calls.lock().unwrap().is_empty(),
            "不能对复用 PID 的无关进程发任何命令"
        );
        assert!(procs.list().iter().any(|x| x.name == "innocent.exe"));
    }

    #[test]
    fn service_steps_use_sc_not_taskkill() {
        let procs = FakeProcs::new(vec![p(
            20,
            Some(1),
            "svchost.exe",
            Some(r"C:\Windows\System32\svchost.exe"),
            None,
        )]);
        let plan = StopPlan {
            steps: vec![StopStep {
                pid: 20,
                name: "svchost.exe".into(),
                start_time: 1020,
                exe: None,
                kind: StepKind::Service("DockerSvc".into()),
            }],
            refused: vec![],
        };
        struct ScRunner(Mutex<Vec<String>>);
        impl CommandRunner for ScRunner {
            fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
                self.0
                    .lock()
                    .unwrap()
                    .push(format!("{program} {}", args.join(" ")));
                // query 先 RUNNING 再 STOPPED
                let n = self.0.lock().unwrap().len();
                let state = if n >= 3 { 1 } else { 4 };
                Ok(CmdOutput {
                    code: 0,
                    stdout: format!("        STATE              : {state}  X\n"),
                    stderr: String::new(),
                })
            }
        }
        let runner = ScRunner(Mutex::default());
        let res = execute_stop(&plan, true, &procs, &runner, fast());
        assert_eq!(res[0].status, StopStatus::ServiceStopped);
        let calls = runner.0.lock().unwrap().clone();
        assert!(calls.iter().any(|c| c == "sc.exe stop DockerSvc"));
        assert!(!calls.iter().any(|c| c.starts_with("taskkill")));
    }

    #[test]
    fn refused_entries_are_carried_into_the_results() {
        let (report, procs) = report_with_family();
        let plan = plan_stop(&report, &[40], false, &procs, 999);
        let runner = KillRunner {
            procs: &procs,
            graceful: vec![],
            calls: Mutex::default(),
        };
        let res = execute_stop(&plan, true, &procs, &runner, fast());
        assert_eq!(res.len(), 1);
        assert!(matches!(res[0].status, StopStatus::Refused(_)));
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    // ----- 文件收集 -----

    #[test]
    fn collect_files_skips_links_and_reports_truncation() {
        let d = std::env::temp_dir().join(format!("dc-procs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        std::fs::write(d.join("one"), b"1").unwrap();
        std::fs::write(d.join("a/two"), b"2").unwrap();
        std::fs::write(d.join("a/b/three"), b"3").unwrap();
        #[cfg(unix)]
        {
            let outside = std::env::temp_dir().join(format!("dc-procs-out-{}", std::process::id()));
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("secret"), b"x").unwrap();
            std::os::unix::fs::symlink(&outside, d.join("link")).unwrap();
        }
        let (files, truncated) = collect_files(&d);
        assert_eq!(files.len(), 3, "{files:?}");
        assert!(!truncated);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn real_process_listing_contains_this_process() {
        let me = std::process::id();
        let list = SysinfoProcesses.list();
        let mine = list
            .iter()
            .find(|p| p.pid == me)
            .expect("current process must be listed");
        assert!(mine.start_time > 0);
        assert!(mine.exe.is_some());
    }

    // ----- macOS -----

    #[test]
    fn lsof_output_is_parsed_and_deduplicated() {
        let out = "p501\ncSlack\np501\ncSlack\np733\ncXcode Helper\nn/x\n";
        let v = parse_lsof(out);
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].pid, v[0].name.as_str()), (501, "Slack"));
        assert_eq!((v[1].pid, v[1].name.as_str()), (733, "Xcode Helper"));
        assert!(parse_lsof("").is_empty());
        assert!(parse_lsof("pnotanumber\ncX\n").is_empty());
    }

    struct LsofFake(Mutex<Vec<String>>, i32, &'static str);
    impl CommandRunner for LsofFake {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
            self.0
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok(CmdOutput {
                code: self.1,
                stdout: self.2.into(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn lsof_finder_batches_files_and_treats_exit_1_as_nobody() {
        let fake = std::sync::Arc::new(LsofFake(Mutex::default(), 0, "p42\ncFoo\n"));
        let finder = LsofFinder(fake.clone());
        let files: Vec<PathBuf> = (0..450)
            .map(|i| PathBuf::from(format!("/d/f {i}")))
            .collect();
        let found = finder.processes_using(&files).unwrap();
        assert_eq!(found.len(), 1, "三批的结果按 PID 合并");
        let calls = fake.0.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].starts_with("/usr/sbin/lsof -F pc -- /d/f 0 "));

        let none = LsofFinder(std::sync::Arc::new(LsofFake(Mutex::default(), 1, "")));
        assert!(none.processes_using(&files[..1]).unwrap().is_empty());
        let bad = LsofFinder(std::sync::Arc::new(LsofFake(Mutex::default(), 2, "")));
        assert!(bad.processes_using(&files[..1]).is_err());
    }

    #[test]
    fn unix_stop_uses_kill_signals_and_finder_is_protected() {
        assert_eq!(
            StopCommands::Unix.graceful("42"),
            ("/bin/kill", vec!["-TERM".to_string(), "42".to_string()])
        );
        assert_eq!(
            StopCommands::Unix.force("42"),
            ("/bin/kill", vec!["-KILL".to_string(), "42".to_string()])
        );
        assert_eq!(StopCommands::Windows.graceful("7").0, "taskkill.exe");
        let finder = p(
            300,
            Some(1),
            "Finder",
            Some("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
            None,
        );
        assert_eq!(protection_of(&finder, 1), Some(Protection::Explorer));
        let launchd = p(1, None, "launchd", Some("/sbin/launchd"), None);
        assert_eq!(protection_of(&launchd, 999), Some(Protection::Critical));
        let window_server = p(150, Some(1), "WindowServer", None, None);
        assert_eq!(
            protection_of(&window_server, 999),
            Some(Protection::Critical)
        );
    }
}
