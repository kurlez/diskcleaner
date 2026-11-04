#![cfg_attr(not(windows), allow(dead_code))]
//! 管理员权限：检测当前进程是否已提升，以及以管理员身份重新启动自己。

use std::ffi::OsString;

/// 当前进程是否以管理员身份（已提升令牌）运行。非 Windows 平台没有这个概念，按已具备处理。
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: 所有指针都指向本函数内的局部变量，令牌句柄在返回前关闭。
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

/// 按 Windows 命令行规则（`CommandLineToArgvW` 的逆运算）给单个参数加引号。
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // 引号前的反斜杠要加倍，再补一个反斜杠转义引号本身。
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // 结尾的反斜杠会紧挨着收尾引号，同样要加倍。
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// 把参数列表拼成传给新进程的命令行（不含程序名）。
pub fn join_args(args: &[OsString]) -> String {
    args.iter()
        .map(|a| quote_arg(&a.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, PartialEq, Eq)]
pub enum RelaunchError {
    /// 用户在 UAC 提示里点了"否"。
    Cancelled,
    Failed(String),
    #[cfg_attr(windows, allow(dead_code))]
    Unsupported,
}

/// 以管理员身份启动自己的一个新实例（弹出 UAC）。成功返回后，调用方应退出当前进程。
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<(), RelaunchError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;

    const SW_SHOWNORMAL: i32 = 1;
    const ERROR_CANCELLED: i32 = 1223;
    let wide =
        |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };

    let exe = std::env::current_exe().map_err(|e| RelaunchError::Failed(e.to_string()))?;
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let verb = wide("runas".as_ref());
    let file = wide(exe.as_os_str());
    let params = wide(join_args(&args).as_ref());
    // SAFETY: 所有字符串都以 NUL 结尾且在调用期间有效；其余参数允许为空。
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result > 32 {
        return Ok(());
    }
    // 用户拒绝 UAC：ShellExecute 返回 SE_ERR_ACCESSDENIED(5)，且最后错误为 ERROR_CANCELLED。
    if result == 5 || std::io::Error::last_os_error().raw_os_error() == Some(ERROR_CANCELLED) {
        return Err(RelaunchError::Cancelled);
    }
    Err(RelaunchError::Failed(format!(
        "ShellExecute returned {result}"
    )))
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), RelaunchError> {
    Err(RelaunchError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_arguments_are_left_alone() {
        assert_eq!(quote_arg("--flag"), "--flag");
        assert_eq!(quote_arg("C:\\x\\y.exe"), "C:\\x\\y.exe");
        assert_eq!(quote_arg("中文"), "中文");
    }

    #[test]
    fn arguments_with_spaces_or_quotes_are_quoted_per_windows_rules() {
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
        // 引号前的反斜杠要加倍。
        assert_eq!(quote_arg("a\\\"b"), "\"a\\\\\\\"b\"");
        // 结尾的反斜杠在收尾引号前要加倍，否则会把引号转义掉。
        assert_eq!(
            quote_arg("C:\\Program Files\\"),
            "\"C:\\Program Files\\\\\""
        );
        // 不在引号前的反斜杠保持原样。
        assert_eq!(quote_arg("a b\\c"), "\"a b\\c\"");
    }

    /// 用 `CommandLineToArgvW` 的解析规则把命令行拆回参数，验证往返无损。
    fn parse(cmdline: &str) -> Vec<String> {
        let chars: Vec<char> = cmdline.chars().collect();
        let (mut args, mut cur, mut in_q, mut started) = (Vec::new(), String::new(), false, false);
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\\' {
                let mut n = 0;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                started = true;
                if i < chars.len() && chars[i] == '"' {
                    cur.push_str(&"\\".repeat(n / 2));
                    if n % 2 == 1 {
                        cur.push('"');
                        i += 1;
                    }
                } else {
                    cur.push_str(&"\\".repeat(n));
                }
                continue;
            }
            if c == '"' {
                in_q = !in_q;
                started = true;
            } else if (c == ' ' || c == '\t') && !in_q {
                if started {
                    args.push(std::mem::take(&mut cur));
                    started = false;
                }
            } else {
                cur.push(c);
                started = true;
            }
            i += 1;
        }
        if started {
            args.push(cur);
        }
        args
    }

    #[test]
    fn quoting_roundtrips_through_the_windows_parser() {
        let cases: Vec<Vec<&str>> = vec![
            vec![
                "--a",
                "b c",
                "",
                "x\"y",
                "tail\\",
                "C:\\Program Files\\App\\",
                "back\\\\\"quote",
                "中文 路径\\📁",
            ],
            vec![],
            vec!["single"],
            vec!["\\", "\\\\", "\"", "\\\"", " "],
        ];
        for args in cases {
            let os: Vec<OsString> = args.iter().map(OsString::from).collect();
            assert_eq!(parse(&join_args(&os)), args, "{args:?}");
        }
    }

    #[test]
    fn non_windows_reports_unsupported_and_counts_as_elevated() {
        #[cfg(not(windows))]
        {
            assert!(is_elevated());
            assert_eq!(relaunch_elevated(), Err(RelaunchError::Unsupported));
        }
    }
}
