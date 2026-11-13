//! 需要调用 Windows 自带工具的"系统动作"，以及清理前后停启 Windows 服务。
//!
//! 所有外部命令都经过 [`CommandRunner`]，因此命令行的构造、执行顺序和错误处理
//! 都可以用假的执行器在任何平台上测试；真实执行只发生在 [`SystemRunner`]。
//!
//! 设计原则：**用系统官方工具做系统级的事**，不手动删除 `WinSxS` 等系统目录。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::rules::{Env, Risk};
use crate::scanner::{self, special_reason};

// ---------- 命令执行 ----------

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput>;

    /// 把整行命令交给命令解释器执行（Windows 下是 `cmd.exe /D /S /C "<命令行>"`）。
    /// 卸载程序登记的 `UninstallString` 是带引号和参数的整行命令，
    /// 不能拆成参数数组，否则引号会被转义破坏。
    fn run_shell(&self, _command_line: &str) -> io::Result<CmdOutput> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "run_shell is not supported",
        ))
    }
}

/// 真实执行外部程序。输出用有损 UTF-8 解码：我们只解析数字和英文关键字，
/// 本地化文字（如 GBK 的中文）乱码无碍，只用于给用户展示的错误详情。
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run_shell(&self, command_line: &str) -> io::Result<CmdOutput> {
        #[cfg(windows)]
        let mut cmd = {
            use std::os::windows::process::CommandExt;
            let mut c = std::process::Command::new("cmd.exe");
            // /S 让 cmd 只剥掉最外层的一对引号，里面的引号原样保留。
            c.raw_arg(format!("/D /S /C \"{command_line}\""));
            c.creation_flags(0x0800_0000);
            c
        };
        #[cfg(not(windows))]
        let mut cmd = {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", command_line]);
            c
        };
        let out = cmd.output()?;
        Ok(CmdOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: decode_console(&out.stdout),
            stderr: decode_console(&out.stderr),
        })
    }

    fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW：不弹出黑窗口
        }
        let out = cmd.output()?;
        Ok(CmdOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: decode_console(&out.stdout),
            stderr: decode_console(&out.stderr),
        })
    }
}

// ---------- 外部程序输出的解码 ----------

/// 解码外部程序的输出，避免中文变成乱码。
///
/// Windows 自带工具（`taskkill`、`sc`、`mklink`、`DISM`……）通过管道输出时用的是控制台的 OEM 代码页
/// （中文系统是 GBK/936），不是 UTF-8。所以：能按 UTF-8 解就按 UTF-8；否则按系统 OEM 代码页解码。
pub fn decode_console(bytes: &[u8]) -> String {
    decode_console_with(bytes, &decode_oem)
}

/// 与 [`decode_console`] 相同，但允许注入"旧代码页解码器"，便于在任何平台上测试。
pub fn decode_console_with(bytes: &[u8], legacy: &dyn Fn(&[u8]) -> String) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => legacy(bytes),
    }
}

/// 按系统 OEM 代码页解码（Windows）。其他平台没有这个概念，退回有损 UTF-8。
#[cfg(windows)]
fn decode_oem(bytes: &[u8]) -> String {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    const CP_OEMCP: u32 = 1;
    if bytes.is_empty() || bytes.len() > i32::MAX as usize {
        return String::new();
    }
    // SAFETY: 两次调用都只读 `bytes`；第二次的输出缓冲区大小来自第一次的返回值。
    unsafe {
        let n = MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if n <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        let mut wide = vec![0u16; n as usize];
        let m = MultiByteToWideChar(
            CP_OEMCP,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            wide.as_mut_ptr(),
            n,
        );
        if m <= 0 {
            return String::from_utf8_lossy(bytes).into_owned();
        }
        String::from_utf16_lossy(&wide[..m as usize])
    }
}

#[cfg(not(windows))]
fn decode_oem(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------- 服务控制 ----------

/// 清理前后停启服务的抽象，让执行器可以在测试中注入假实现。
pub trait ServiceControl {
    /// 停止服务。返回 `true` 表示它原本在运行、被我们停掉了（之后需要恢复）；
    /// 返回 `false` 表示本来就没在运行或服务不存在。
    fn stop(&self, name: &str) -> Result<bool, String>;
    fn start(&self, name: &str) -> Result<(), String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SvcState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    Other,
    NotInstalled,
}

/// 通过 `sc.exe` 控制服务。
pub struct ScServices<'a> {
    runner: &'a dyn CommandRunner,
    poll: Duration,
    timeout: Duration,
}

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;

impl<'a> ScServices<'a> {
    pub fn new(runner: &'a dyn CommandRunner) -> Self {
        Self {
            runner,
            poll: Duration::from_millis(500),
            timeout: Duration::from_secs(30),
        }
    }

    #[cfg(test)]
    fn with_timing(mut self, poll: Duration, timeout: Duration) -> Self {
        self.poll = poll;
        self.timeout = timeout;
        self
    }

    fn state(&self, name: &str) -> Result<SvcState, String> {
        let out = self
            .runner
            .run("sc.exe", &["query", name])
            .map_err(|e| e.to_string())?;
        if out.code == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(SvcState::NotInstalled);
        }
        if out.code != 0 {
            return Err(format!(
                "sc query {name} failed ({}): {}",
                out.code,
                out.stderr.trim()
            ));
        }
        // 形如 "        STATE              : 4  RUNNING"。数字代码与语言无关。
        let code = out
            .stdout
            .lines()
            .find(|l| l.trim_start().starts_with("STATE"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|r| r.split_whitespace().next())
            .and_then(|n| n.parse::<u32>().ok())
            .ok_or_else(|| format!("cannot parse state of {name}"))?;
        Ok(match code {
            1 => SvcState::Stopped,
            2 => SvcState::StartPending,
            3 => SvcState::StopPending,
            4 => SvcState::Running,
            _ => SvcState::Other,
        })
    }
}

impl ServiceControl for ScServices<'_> {
    fn stop(&self, name: &str) -> Result<bool, String> {
        match self.state(name)? {
            SvcState::Stopped | SvcState::NotInstalled => return Ok(false),
            SvcState::StopPending => {}
            _ => {
                let out = self
                    .runner
                    .run("sc.exe", &["stop", name])
                    .map_err(|e| e.to_string())?;
                if out.code != 0 {
                    return Err(format!(
                        "sc stop {name} failed ({}): {}",
                        out.code,
                        out.stdout.trim()
                    ));
                }
            }
        }
        let start = Instant::now();
        loop {
            if self.state(name)? == SvcState::Stopped {
                return Ok(true);
            }
            if start.elapsed() >= self.timeout {
                return Err(format!("timed out waiting for {name} to stop"));
            }
            thread::sleep(self.poll);
        }
    }

    fn start(&self, name: &str) -> Result<(), String> {
        let out = self
            .runner
            .run("sc.exe", &["start", name])
            .map_err(|e| e.to_string())?;
        if out.code == 0 || out.code == ERROR_SERVICE_ALREADY_RUNNING {
            Ok(())
        } else {
            Err(format!(
                "sc start {name} failed ({}): {}",
                out.code,
                out.stdout.trim()
            ))
        }
    }
}

// ---------- 系统动作 ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SysKind {
    /// 清空所有盘的回收站。
    EmptyRecycleBin,
    /// 关闭休眠并删除 `hiberfil.sys`（可随时用 `powercfg /h on` 恢复，但会失去休眠与快速启动）。
    DisableHibernation,
    /// 清理组件存储中被取代的旧版本（`DISM /StartComponentCleanup`，不加 `/ResetBase`）。
    ComponentCleanup,
    /// 删除上一次系统升级留下的 `Windows.old`（删除后无法回退到旧版本）。
    RemoveWindowsOld,
    /// 删除最早的一个卷影副本（还原点）。
    DeleteOldestShadowCopy,
    /// macOS：精简 Time Machine 的本地快照（需要管理员密码）。
    MacThinSnapshots,
    /// macOS：`brew cleanup --prune=all`，删除 Homebrew 的旧版本与下载缓存。
    MacBrewCleanup,
    /// macOS：`xcrun simctl delete unavailable`，删除已不可用的 iOS 模拟器。
    MacDeleteUnavailableSimulators,
}

#[derive(Debug, Clone, Copy)]
pub struct SysAction {
    pub id: &'static str,
    pub kind: SysKind,
    pub risk: Risk,
}

pub const SYSTEM_ACTIONS: &[SysAction] = &[
    SysAction {
        id: "recycle_bin",
        kind: SysKind::EmptyRecycleBin,
        risk: Risk::Medium,
    },
    SysAction {
        id: "hibernation",
        kind: SysKind::DisableHibernation,
        risk: Risk::Medium,
    },
    SysAction {
        id: "component_store",
        kind: SysKind::ComponentCleanup,
        risk: Risk::Low,
    },
    SysAction {
        id: "windows_old",
        kind: SysKind::RemoveWindowsOld,
        risk: Risk::High,
    },
    SysAction {
        id: "shadow_copy",
        kind: SysKind::DeleteOldestShadowCopy,
        risk: Risk::High,
    },
];

/// macOS 的系统动作：都交给系统或包管理器自己的工具，不手动删除系统文件。
pub const MAC_ACTIONS: &[SysAction] = &[
    SysAction {
        id: "mac_snapshots",
        kind: SysKind::MacThinSnapshots,
        risk: Risk::Medium,
    },
    SysAction {
        id: "mac_brew",
        kind: SysKind::MacBrewCleanup,
        risk: Risk::Low,
    },
    SysAction {
        id: "mac_simulators",
        kind: SysKind::MacDeleteUnavailableSimulators,
        risk: Risk::Low,
    },
];

/// 当前平台提供的系统动作。
pub fn platform_actions() -> &'static [SysAction] {
    if cfg!(target_os = "macos") {
        MAC_ACTIONS
    } else {
        SYSTEM_ACTIONS
    }
}

pub fn find_action(id: &str) -> Option<&'static SysAction> {
    SYSTEM_ACTIONS
        .iter()
        .chain(MAC_ACTIONS)
        .find(|a| a.id == id)
}

/// Homebrew 的可执行文件：Apple 芯片与 Intel 的默认安装位置。
/// 图形界面启动的程序 PATH 很短，不能靠 `brew` 这个名字查找。
fn find_brew() -> Option<&'static str> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
}

/// 经系统的授权对话框以管理员身份运行一条**固定**的命令（不拼接任何外部输入）。
fn run_as_admin(runner: &dyn CommandRunner, shell_command: &str) -> SysResult<String> {
    let script = format!("do shell script \"{shell_command}\" with administrator privileges");
    ok_or_fail(runner, "osascript", &["-e", &script])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysError {
    pub code: &'static str,
    pub detail: String,
}

impl SysError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

type SysResult<T> = Result<T, SysError>;

/// 系统盘根目录，如 `C:\`。取自 `SystemDrive`（形如 `C:`）。
fn system_root(env: &Env) -> SysResult<PathBuf> {
    let drive = env
        .get("SystemDrive")
        .ok_or_else(|| SysError::new("no_system_drive", "SystemDrive is not set"))?;
    // `C:` 后面补分隔符；测试里 SystemDrive 是一个普通目录路径，也能正常拼接。
    let mut p = PathBuf::from(drive);
    if drive.ends_with(':') {
        p.push(std::path::MAIN_SEPARATOR_STR);
    }
    Ok(p)
}

impl SysAction {
    /// 预计能释放的字节数；无法估算（或没有可清理内容）时为 `None`。
    pub fn estimate(&self, env: &Env) -> Option<u64> {
        if matches!(
            self.kind,
            SysKind::MacThinSnapshots
                | SysKind::MacBrewCleanup
                | SysKind::MacDeleteUnavailableSimulators
        ) {
            // 释放量由系统工具决定，输出随版本变化，不做不可靠的估算。
            return None;
        }
        let root = system_root(env).ok()?;
        match self.kind {
            SysKind::EmptyRecycleBin => dir_size(&root.join("$Recycle.Bin")),
            SysKind::DisableHibernation => fs::metadata(root.join("hiberfil.sys"))
                .ok()
                .map(|m| m.len()),
            SysKind::RemoveWindowsOld => dir_size(&root.join("Windows.old")),
            // 释放量取决于系统内部的分析结果，输出又随语言变化，不做不可靠的估算。
            _ => None,
        }
    }

    /// 执行动作，返回给用户看的简短说明。
    pub fn run(&self, env: &Env, runner: &dyn CommandRunner) -> SysResult<String> {
        match self.kind {
            SysKind::MacThinSnapshots => run_as_admin(
                runner,
                // 请求释放尽可能多的空间，紧急程度 4（最高）；只动本地快照，不碰外置备份。
                "/usr/bin/tmutil thinlocalsnapshots / 9999999999999 4",
            ),
            SysKind::MacBrewCleanup => {
                let brew = find_brew()
                    .ok_or_else(|| SysError::new("not_found", "Homebrew is not installed"))?;
                ok_or_fail(runner, brew, &["cleanup", "--prune=all"])
            }
            SysKind::MacDeleteUnavailableSimulators => ok_or_fail(
                runner,
                "/usr/bin/xcrun",
                &["simctl", "delete", "unavailable"],
            ),
            SysKind::EmptyRecycleBin => ok_or_fail(
                runner,
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
                ],
            ),
            SysKind::DisableHibernation => {
                ok_or_fail(runner, "powercfg.exe", &["/hibernate", "off"])
            }
            SysKind::ComponentCleanup => ok_or_fail(
                runner,
                "Dism.exe",
                &["/Online", "/Cleanup-Image", "/StartComponentCleanup"],
            ),
            SysKind::DeleteOldestShadowCopy => {
                let root = system_root(env)?;
                let drive = root
                    .to_string_lossy()
                    .trim_end_matches(['\\', '/'])
                    .to_string();
                let target = format!("/for={drive}");
                ok_or_fail(
                    runner,
                    "vssadmin.exe",
                    &["delete", "shadows", &target, "/oldest", "/quiet"],
                )
            }
            SysKind::RemoveWindowsOld => {
                remove_windows_old(&system_root(env)?.join("Windows.old"), runner)
            }
        }
    }
}

fn ok_or_fail(runner: &dyn CommandRunner, program: &str, args: &[&str]) -> SysResult<String> {
    let out = runner
        .run(program, args)
        .map_err(|e| SysError::new("spawn_failed", format!("{program}: {e}")))?;
    if out.code == 0 {
        Ok(out.stdout.trim().to_string())
    } else {
        let msg = if out.stderr.trim().is_empty() {
            &out.stdout
        } else {
            &out.stderr
        };
        Err(SysError::new(
            "command_failed",
            format!("{program} exited with {}: {}", out.code, msg.trim()),
        ))
    }
}

/// 递归统计目录大小；目录不存在返回 `None`。无法读取的部分（如权限）被忽略。
fn dir_size(path: &Path) -> Option<u64> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_dir() {
        return None;
    }
    let out = scanner::scan(path, &AtomicBool::new(false), &mut |_| {}).ok()?;
    Some(out.root.size)
}

/// `Windows.old` 由 TrustedInstaller 持有，必须先夺取所有权并授予管理员完全控制，再删除。
/// 管理员组用 SID `S-1-5-32-544` 指定，避免依赖界面语言。
fn remove_windows_old(path: &Path, runner: &dyn CommandRunner) -> SysResult<String> {
    // 只处理系统盘根目录下名为 Windows.old 的真实目录，不跟随链接。
    let name_ok = path
        .file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case("Windows.old"));
    let meta = fs::symlink_metadata(path)
        .map_err(|_| SysError::new("not_found", "Windows.old does not exist"))?;
    if !name_ok || !meta.is_dir() || special_reason(&meta).is_some() {
        return Err(SysError::new("unsafe_target", path.display().to_string()));
    }
    let p = path.to_string_lossy().into_owned();
    ok_or_fail(runner, "takeown.exe", &["/F", &p, "/R", "/A", "/D", "Y"])?;
    ok_or_fail(
        runner,
        "icacls.exe",
        &[&p, "/grant", "*S-1-5-32-544:F", "/T", "/C", "/Q"],
    )?;
    // 目录内的 junction 只会被删除链接本身，不会进入目标。
    fs::remove_dir_all(path).map_err(|e| SysError::new("delete_failed", e.to_string()))?;
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// 记录所有调用，并按顺序返回预设结果（用完后返回成功）。
    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        script: Mutex<VecDeque<CmdOutput>>,
    }

    impl Fake {
        fn with(outputs: Vec<CmdOutput>) -> Self {
            Fake {
                calls: Mutex::default(),
                script: Mutex::new(outputs.into()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandRunner for Fake {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CmdOutput> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            Ok(self.script.lock().unwrap().pop_front().unwrap_or_default())
        }
    }

    fn out(code: i32, stdout: &str) -> CmdOutput {
        CmdOutput {
            code,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn state_out(n: u32, name: &str) -> CmdOutput {
        out(0, &format!("SERVICE_NAME: x\n        TYPE               : 20  WIN32_SHARE_PROCESS\n        STATE              : {n}  {name}\n"))
    }

    fn svc(f: &Fake) -> ScServices<'_> {
        ScServices::new(f).with_timing(Duration::ZERO, Duration::from_millis(50))
    }

    // ----- 服务控制 -----

    #[test]
    fn mac_actions_use_system_tools_and_a_fixed_admin_prompt() {
        let env = Env::from_pairs([("HOME", "/Users/alice")]);
        let fake = Fake::with(vec![out(0, "Thinned local snapshots")]);
        let snap = find_action("mac_snapshots").unwrap();
        snap.run(&env, &fake).unwrap();
        assert_eq!(
            fake.calls(),
            ["osascript -e do shell script \"/usr/bin/tmutil thinlocalsnapshots / 9999999999999 4\" with administrator privileges"]
        );

        let fake = Fake::with(vec![out(0, "")]);
        find_action("mac_simulators")
            .unwrap()
            .run(&env, &fake)
            .unwrap();
        assert_eq!(fake.calls(), ["/usr/bin/xcrun simctl delete unavailable"]);

        // 取消管理员授权时 osascript 返回非零，应报告失败而不是当成功。
        let fake = Fake::with(vec![CmdOutput {
            code: 1,
            stdout: String::new(),
            stderr: "User canceled. (-128)".into(),
        }]);
        let err = snap.run(&env, &fake).unwrap_err();
        assert_eq!(err.code, "command_failed");
        assert!(err.detail.contains("User canceled"));
    }

    #[test]
    fn platform_actions_are_distinct_and_all_findable() {
        let win: Vec<_> = SYSTEM_ACTIONS.iter().map(|a| a.id).collect();
        for a in MAC_ACTIONS {
            assert!(!win.contains(&a.id));
            assert!(find_action(a.id).is_some());
        }
        assert!(MAC_ACTIONS
            .iter()
            .all(|a| a.estimate(&Env::default()).is_none()));
    }

    #[test]
    fn stops_a_running_service_and_waits_until_stopped() {
        let f = Fake::with(vec![
            state_out(4, "RUNNING"),      // query: 运行中
            out(0, ""),                   // stop
            state_out(3, "STOP_PENDING"), // 轮询
            state_out(1, "STOPPED"),
        ]);
        assert_eq!(svc(&f).stop("wuauserv"), Ok(true));
        assert_eq!(
            f.calls(),
            [
                "sc.exe query wuauserv",
                "sc.exe stop wuauserv",
                "sc.exe query wuauserv",
                "sc.exe query wuauserv"
            ]
        );
    }

    #[test]
    fn already_stopped_or_missing_service_is_left_alone() {
        let f = Fake::with(vec![state_out(1, "STOPPED")]);
        assert_eq!(svc(&f).stop("bits"), Ok(false));
        assert_eq!(f.calls(), ["sc.exe query bits"]);

        let g = Fake::with(vec![out(ERROR_SERVICE_DOES_NOT_EXIST, "")]);
        assert_eq!(svc(&g).stop("nope"), Ok(false));
    }

    #[test]
    fn stop_times_out_instead_of_hanging() {
        let mut script = vec![state_out(4, "RUNNING"), out(0, "")];
        script.extend((0..2000).map(|_| state_out(3, "STOP_PENDING")));
        let f = Fake::with(script);
        // 轮询间隔 2ms、超时 40ms：约 20 次轮询即超时，远少于预设的输出条数。
        let slow =
            ScServices::new(&f).with_timing(Duration::from_millis(2), Duration::from_millis(40));
        assert!(slow.stop("slow").unwrap_err().contains("timed out"));
    }

    #[test]
    fn stop_and_start_errors_are_reported() {
        let f = Fake::with(vec![state_out(4, "RUNNING"), out(5, "Access is denied.")]);
        assert!(svc(&f).stop("x").unwrap_err().contains("failed (5)"));

        let g = Fake::with(vec![out(1056, "")]);
        assert_eq!(svc(&g).start("x"), Ok(()), "already running is fine");
        let h = Fake::with(vec![out(1058, "disabled")]);
        assert!(svc(&h).start("x").unwrap_err().contains("1058"));
    }

    #[test]
    fn unparsable_state_is_an_error_not_a_guess() {
        let f = Fake::with(vec![out(0, "garbage")]);
        assert!(svc(&f).stop("x").is_err());
    }

    // ----- 系统动作 -----

    fn env_with_root(root: &Path) -> Env {
        Env::from_pairs([("SystemDrive", root.to_string_lossy())])
    }

    fn sandbox(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("dc-sys-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn action_ids_are_unique_and_none_is_low_risk_by_accident() {
        let mut ids: Vec<_> = SYSTEM_ACTIONS.iter().map(|a| a.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), SYSTEM_ACTIONS.len());
        assert_eq!(find_action("windows_old").unwrap().risk, Risk::High);
        assert_eq!(find_action("shadow_copy").unwrap().risk, Risk::High);
        assert!(find_action("nope").is_none());
    }

    #[test]
    fn builds_the_expected_command_lines() {
        let root = sandbox("cmds");
        let env = env_with_root(&root);
        let cases: &[(&str, &str)] = &[
            ("hibernation", "powercfg.exe /hibernate off"),
            (
                "component_store",
                "Dism.exe /Online /Cleanup-Image /StartComponentCleanup",
            ),
        ];
        for (id, expected) in cases {
            let f = Fake::default();
            find_action(id).unwrap().run(&env, &f).unwrap();
            assert_eq!(f.calls(), [*expected], "{id}");
        }
        let f = Fake::default();
        find_action("recycle_bin").unwrap().run(&env, &f).unwrap();
        assert!(f.calls()[0]
            .starts_with("powershell.exe -NoProfile -NonInteractive -Command Clear-RecycleBin"));

        let f = Fake::default();
        find_action("shadow_copy").unwrap().run(&env, &f).unwrap();
        let drive = root
            .to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_string();
        assert_eq!(
            f.calls(),
            [format!(
                "vssadmin.exe delete shadows /for={drive} /oldest /quiet"
            )]
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn command_failure_surfaces_exit_code_and_message() {
        let env = env_with_root(&sandbox("fail"));
        let f = Fake::with(vec![CmdOutput {
            code: 5,
            stdout: String::new(),
            stderr: "Access is denied.".into(),
        }]);
        let e = find_action("hibernation")
            .unwrap()
            .run(&env, &f)
            .unwrap_err();
        assert_eq!(e.code, "command_failed");
        assert!(
            e.detail.contains("5") && e.detail.contains("Access is denied"),
            "{e:?}"
        );
    }

    #[test]
    fn windows_old_takes_ownership_then_grants_then_deletes_in_order() {
        let root = sandbox("old");
        fs::create_dir_all(root.join("Windows.old/Windows/System32")).unwrap();
        fs::write(root.join("Windows.old/Windows/System32/x.dll"), b"x").unwrap();
        let env = env_with_root(&root);
        let f = Fake::default();
        find_action("windows_old").unwrap().run(&env, &f).unwrap();
        let calls = f.calls();
        let p = root.join("Windows.old").to_string_lossy().into_owned();
        assert_eq!(calls[0], format!("takeown.exe /F {p} /R /A /D Y"));
        assert_eq!(
            calls[1],
            format!("icacls.exe {p} /grant *S-1-5-32-544:F /T /C /Q")
        );
        assert_eq!(calls.len(), 2);
        assert!(!root.join("Windows.old").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn windows_old_is_not_deleted_if_taking_ownership_fails() {
        let root = sandbox("oldfail");
        fs::create_dir_all(root.join("Windows.old")).unwrap();
        let env = env_with_root(&root);
        let f = Fake::with(vec![out(1, "boom")]);
        assert!(find_action("windows_old").unwrap().run(&env, &f).is_err());
        assert_eq!(f.calls().len(), 1, "must stop after the first failure");
        assert!(root.join("Windows.old").exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn windows_old_missing_is_reported() {
        let root = sandbox("oldmissing");
        let f = Fake::default();
        let e = find_action("windows_old")
            .unwrap()
            .run(&env_with_root(&root), &f)
            .unwrap_err();
        assert_eq!(e.code, "not_found");
        assert!(f.calls().is_empty());
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn windows_old_that_is_a_symlink_is_refused() {
        let root = sandbox("oldlink");
        let elsewhere = sandbox("oldlink-target");
        fs::write(elsewhere.join("keep.txt"), b"keep").unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.join("Windows.old")).unwrap();
        let f = Fake::default();
        let e = find_action("windows_old")
            .unwrap()
            .run(&env_with_root(&root), &f)
            .unwrap_err();
        assert_eq!(e.code, "unsafe_target");
        assert!(f.calls().is_empty());
        assert!(elsewhere.join("keep.txt").exists());
        fs::remove_dir_all(&root).unwrap();
        fs::remove_dir_all(&elsewhere).unwrap();
    }

    #[test]
    fn estimates_use_real_sizes_and_none_when_absent() {
        let root = sandbox("est");
        let env = env_with_root(&root);
        assert_eq!(find_action("recycle_bin").unwrap().estimate(&env), None);
        assert_eq!(find_action("hibernation").unwrap().estimate(&env), None);

        fs::create_dir_all(root.join("$Recycle.Bin/S-1-5-21")).unwrap();
        fs::write(root.join("$Recycle.Bin/S-1-5-21/a"), vec![0u8; 700]).unwrap();
        fs::write(root.join("$Recycle.Bin/b"), vec![0u8; 300]).unwrap();
        fs::write(root.join("hiberfil.sys"), vec![0u8; 4096]).unwrap();
        fs::create_dir_all(root.join("Windows.old")).unwrap();
        fs::write(root.join("Windows.old/f"), vec![0u8; 50]).unwrap();

        assert_eq!(
            find_action("recycle_bin").unwrap().estimate(&env),
            Some(1000)
        );
        assert_eq!(
            find_action("hibernation").unwrap().estimate(&env),
            Some(4096)
        );
        assert_eq!(find_action("windows_old").unwrap().estimate(&env), Some(50));
        assert_eq!(find_action("component_store").unwrap().estimate(&env), None);
        assert_eq!(find_action("shadow_copy").unwrap().estimate(&env), None);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn missing_system_drive_is_an_error() {
        let f = Fake::default();
        let e = find_action("shadow_copy")
            .unwrap()
            .run(&Env::default(), &f)
            .unwrap_err();
        assert_eq!(e.code, "no_system_drive");
        assert!(f.calls().is_empty());
        assert_eq!(
            find_action("recycle_bin")
                .unwrap()
                .estimate(&Env::default()),
            None
        );
    }

    // ----- 输出解码 -----

    /// 用 encoding_rs 的 GBK 充当"系统 OEM 代码页"。
    fn gbk(bytes: &[u8]) -> String {
        encoding_rs::GBK.decode(bytes).0.into_owned()
    }

    #[test]
    fn utf8_output_is_kept_as_is() {
        let text = "ERROR: 拒绝访问。 Access is denied. 📄 ünïcödé";
        assert_eq!(decode_console_with(text.as_bytes(), &gbk), text);
        assert_eq!(
            decode_console_with(b"plain ascii 123", &gbk),
            "plain ascii 123"
        );
        assert_eq!(decode_console_with(b"", &gbk), "");
    }

    #[test]
    fn gbk_console_output_is_decoded_instead_of_turning_into_garbage() {
        // "错误: 拒绝访问。" 的 GBK 编码，按 UTF-8 解会得到乱码。
        let (bytes, _, _) = encoding_rs::GBK.encode("错误: 拒绝访问。 (os error 5)");
        assert!(
            std::str::from_utf8(&bytes).is_err(),
            "测试数据必须不是合法 UTF-8"
        );
        let lossy = String::from_utf8_lossy(&bytes);
        assert!(lossy.contains('\u{FFFD}'), "旧做法确实会乱码");
        assert_eq!(
            decode_console_with(&bytes, &gbk),
            "错误: 拒绝访问。 (os error 5)"
        );
    }

    #[test]
    fn mixed_ascii_and_gbk_is_decoded_as_a_whole() {
        let (bytes, _, _) = encoding_rs::GBK.encode("SUCCESS: 已终止进程 \"foo.exe\"，PID 1234。");
        assert_eq!(
            decode_console_with(&bytes, &gbk),
            "SUCCESS: 已终止进程 \"foo.exe\"，PID 1234。"
        );
    }

    #[test]
    fn the_default_decoder_never_panics_on_arbitrary_bytes() {
        let noise: Vec<u8> = (0..=255u8).collect();
        let _ = decode_console(&noise);
        assert_eq!(
            decode_console("正常 UTF-8 文本".as_bytes()),
            "正常 UTF-8 文本"
        );
    }
}
