//! 路径安全策略：决定一个路径"能不能被删除"。
//!
//! 设计要点：
//! * 纯字符串逻辑，不访问文件系统，因此可在任意平台上单元测试。
//! * 按 Windows 语义规范化（大小写不敏感、`/` 与 `\` 等价、去掉末尾的点和空格）。
//! * 默认拒绝：受保护目录（系统目录、用户文档等）及其祖先、后代都不可删除，
//!   除非命中更具体的"允许根"（例如 `C:\Windows\Temp`）。
//!
//! **调用方责任**：传入前必须先用系统 API（`GetFinalPathNameByHandle`）取得
//! 规范长路径，本模块会拒绝可疑的 8.3 短名，但不会替你解析它们。

use std::fmt;

/// 无论位于何处，名称命中即拒绝删除的目录/文件名（小写）。
const PROTECTED_NAMES: &[&str] = &[".git", ".ssh", ".gnupg"];

/// 用户配置文件下默认受保护的目录。
const PROTECTED_PROFILE_DIRS: &[&str] = &[
    "Documents",
    "Desktop",
    "Pictures",
    "Videos",
    "Music",
    "Downloads",
    "OneDrive",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    /// 不是 `X:\...` 形式的绝对路径（相对路径、`C:foo`、空串）。
    NotAbsolute,
    /// 含 `..`。
    ContainsParentRef,
    /// UNC、设备路径、备用数据流、通配符或非法字符。
    UnsupportedPath,
    /// 疑似 8.3 短文件名（含 `~数字`），需先取规范长路径。
    ShortName,
    /// 盘符根目录。
    DriveRoot,
    /// 命中受保护目录（附带该保护根的展示形式）。
    Protected(String),
    /// 路径中含受保护名称（如 `.git`）。
    ProtectedName(String),
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Denied::NotAbsolute => write!(f, "path is not an absolute drive path"),
            Denied::ContainsParentRef => write!(f, "path contains '..'"),
            Denied::UnsupportedPath => write!(f, "unsupported path form"),
            Denied::ShortName => write!(f, "path looks like an 8.3 short name; canonicalize first"),
            Denied::DriveRoot => write!(f, "refusing to touch a drive root"),
            Denied::Protected(p) => write!(f, "protected location: {p}"),
            Denied::ProtectedName(n) => write!(f, "protected name in path: {n}"),
        }
    }
}

impl std::error::Error for Denied {}

/// 规范化后的路径：第一个分量是小写盘符（如 `c:`），其后为小写目录/文件名。
#[derive(Debug, Clone, PartialEq, Eq)]
struct NormPath(Vec<String>);

/// 路径语法。生产环境使用 `Windows`；`Posix` 仅用于在非 Windows 平台上
/// 对真实文件系统做集成测试，规则（受保护名称、前缀判断等）完全一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStyle {
    Windows,
    Posix,
}

impl NormPath {
    fn parse(input: &str, style: PathStyle) -> Result<Self, Denied> {
        match style {
            PathStyle::Windows => Self::parse_windows(input),
            PathStyle::Posix => Self::parse_posix(input),
        }
    }

    fn parse_posix(input: &str) -> Result<Self, Denied> {
        if !input.starts_with('/') {
            return Err(Denied::NotAbsolute);
        }
        let mut parts = vec!["/".to_string()];
        for raw in input.split('/') {
            if raw.is_empty() || raw == "." {
                continue;
            }
            if raw == ".." {
                return Err(Denied::ContainsParentRef);
            }
            if raw.chars().any(|c| c.is_control()) {
                return Err(Denied::UnsupportedPath);
            }
            parts.push(raw.to_string());
        }
        Ok(NormPath(parts))
    }

    fn parse_windows(input: &str) -> Result<Self, Denied> {
        let s = input.replace('/', "\\");

        // 仅接受 `\\?\X:\...` 扩展前缀；`\\?\UNC\`、`\\.\` 与普通 UNC 一律拒绝。
        let s = if let Some(rest) = s.strip_prefix("\\\\?\\") {
            if rest
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case("UNC\\"))
            {
                return Err(Denied::UnsupportedPath);
            }
            rest.to_string()
        } else if s.starts_with("\\\\") {
            return Err(Denied::UnsupportedPath);
        } else {
            s
        };

        let mut chars = s.chars();
        let drive = chars.next().ok_or(Denied::NotAbsolute)?;
        if !drive.is_ascii_alphabetic() || chars.next() != Some(':') {
            return Err(Denied::NotAbsolute);
        }
        if chars.next() != Some('\\') {
            // "C:" 或 "C:foo" 是相对于盘符当前目录的路径。
            return Err(Denied::NotAbsolute);
        }

        let mut parts = vec![format!("{}:", drive.to_ascii_lowercase())];
        for raw in s[3..].split('\\') {
            if raw.is_empty() || raw == "." {
                continue;
            }
            if raw == ".." {
                return Err(Denied::ContainsParentRef);
            }
            // Win32 会悄悄丢弃分量末尾的点和空格，"Windows. " 即 "Windows"。
            let comp = raw.trim_end_matches(['.', ' ']);
            if comp.is_empty() {
                // 例如 "..." —— Win32 视其为空分量，语义不明，直接拒绝。
                return Err(Denied::UnsupportedPath);
            }
            if comp
                .chars()
                .any(|c| matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') || c.is_control())
            {
                return Err(Denied::UnsupportedPath);
            }
            if has_short_name_marker(comp) {
                return Err(Denied::ShortName);
            }
            parts.push(comp.to_lowercase());
        }
        Ok(NormPath(parts))
    }

    fn display(&self) -> String {
        if self.0[0] == "/" {
            format!("/{}", self.0[1..].join("/"))
        } else {
            self.0.join("\\")
        }
    }
}

/// 8.3 短名形如 `PROGRA~1`：波浪线后紧跟数字。
fn has_short_name_marker(name: &str) -> bool {
    let b = name.as_bytes();
    b.windows(2).any(|w| w[0] == b'~' && w[1].is_ascii_digit())
}

/// 名称是否属于"无论在哪都不能删"的受保护名称（不区分大小写）。
pub fn is_protected_name(name: &str) -> bool {
    PROTECTED_NAMES.contains(&name.to_lowercase().as_str())
}

/// `a` 是否为 `b` 的前缀（含相等）。
fn is_prefix(a: &[String], b: &[String]) -> bool {
    a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

/// 系统已知目录，由环境变量或测试数据提供。
#[derive(Debug, Clone)]
pub struct KnownDirs {
    pub system_root: String,
    pub program_files: String,
    pub program_files_x86: String,
    pub program_data: String,
    pub user_profile: String,
}

impl KnownDirs {
    /// 从环境变量读取（Windows 下的正常路径）。任一缺失则返回 `None`。
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Some(Self {
            system_root: get("SystemRoot")?,
            program_files: get("ProgramFiles")?,
            program_files_x86: get("ProgramFiles(x86)")
                .unwrap_or_else(|| get("ProgramFiles").unwrap()),
            program_data: get("ProgramData")?,
            user_profile: get("USERPROFILE")?,
        })
    }

    /// 典型布局（系统装在 C 盘），用于测试和兜底。
    pub fn typical(user: &str) -> Self {
        Self {
            system_root: r"C:\Windows".into(),
            program_files: r"C:\Program Files".into(),
            program_files_x86: r"C:\Program Files (x86)".into(),
            program_data: r"C:\ProgramData".into(),
            user_profile: format!(r"C:\Users\{user}"),
        }
    }
}

/// 删除安全策略。
#[derive(Debug, Clone)]
pub struct SafetyPolicy {
    style: PathStyle,
    protected: Vec<NormPath>,
    allow: Vec<NormPath>,
    /// 用户排除项：优先级最高，即使位于允许根之内也拒绝（含其祖先）。
    hard: Vec<NormPath>,
    /// 精确允许的单个路径（用于 `MEMORY.DMP` 这类位于受保护目录下的单文件）。
    allow_exact: Vec<NormPath>,
}

impl SafetyPolicy {
    /// 用默认保护名单构建策略。已知目录若无法解析则返回 `Err`，
    /// 避免在保护缺失的情况下悄悄继续。
    pub fn new(dirs: &KnownDirs) -> Result<Self, Denied> {
        let mut p = SafetyPolicy::empty(PathStyle::Windows);
        for d in [
            &dirs.system_root,
            &dirs.program_files,
            &dirs.program_files_x86,
            &dirs.program_data,
            &dirs.user_profile,
        ] {
            p.protect(d)?;
        }
        let drive = NormPath::parse(&dirs.system_root, PathStyle::Windows)?.0[0].clone();
        for special in [
            "System Volume Information",
            "$Recycle.Bin",
            "Recovery",
            "Boot",
        ] {
            p.protect(&format!("{drive}\\{special}"))?;
        }
        for d in PROTECTED_PROFILE_DIRS {
            p.protect(&format!(
                "{}\\{}",
                dirs.user_profile.trim_end_matches('\\'),
                d
            ))?;
        }
        Ok(p)
    }

    /// 用户亲自选中具体文件时使用的策略（如删除重复文件）。
    ///
    /// 与 [`SafetyPolicy::new`] 的区别：不保护用户自己的文档、桌面、下载等目录——
    /// 那些文件正是用户明确要处理的对象；但系统目录、程序目录、回收站内部、
    /// 应用数据（`AppData`）仍然一律拒绝。`.git`、`.ssh` 等受保护名称规则照常生效。
    pub fn for_user_selected(dirs: &KnownDirs) -> Result<Self, Denied> {
        let mut p = SafetyPolicy::empty(PathStyle::Windows);
        for d in [
            &dirs.system_root,
            &dirs.program_files,
            &dirs.program_files_x86,
            &dirs.program_data,
        ] {
            p.protect(d)?;
        }
        let drive = NormPath::parse(&dirs.system_root, PathStyle::Windows)?.0[0].clone();
        for special in [
            "System Volume Information",
            "$Recycle.Bin",
            "Recovery",
            "Boot",
        ] {
            p.protect(&format!("{drive}\\{special}"))?;
        }
        p.protect(&format!(
            "{}\\AppData",
            dirs.user_profile.trim_end_matches('\\')
        ))?;
        Ok(p)
    }

    /// 不带任何默认保护的空策略（仅用于测试或自行配置）。
    pub fn empty(style: PathStyle) -> Self {
        SafetyPolicy {
            style,
            protected: Vec::new(),
            hard: Vec::new(),
            allow: Vec::new(),
            allow_exact: Vec::new(),
        }
    }

    /// 添加用户排除路径：任何规则、允许根都无法覆盖它。
    pub fn exclude(&mut self, path: &str) -> Result<(), Denied> {
        self.hard.push(NormPath::parse(path, self.style)?);
        Ok(())
    }

    /// 追加受保护路径（例如用户在设置里配置的排除目录）。
    pub fn protect(&mut self, path: &str) -> Result<(), Denied> {
        self.protected.push(NormPath::parse(path, self.style)?);
        Ok(())
    }

    /// 精确允许删除某一个路径本身（不含其父目录的其它内容）。
    pub fn allow_exact(&mut self, path: &str) -> Result<(), Denied> {
        self.allow_exact.push(NormPath::parse(path, self.style)?);
        Ok(())
    }

    /// 追加允许根：其**内部**的内容可删除（根本身不算）。
    /// 允许根比保护根更具体时生效，例如 `C:\Windows\Temp`。
    pub fn allow_root(&mut self, path: &str) -> Result<(), Denied> {
        self.allow.push(NormPath::parse(path, self.style)?);
        Ok(())
    }

    /// 判断 `path` 是否允许被删除。
    pub fn check_delete(&self, path: &str) -> Result<(), Denied> {
        let target = NormPath::parse(path, self.style)?;

        if target.0.len() == 1 {
            return Err(Denied::DriveRoot);
        }
        for part in &target.0[1..] {
            if PROTECTED_NAMES.contains(&part.as_str()) {
                return Err(Denied::ProtectedName(part.clone()));
            }
        }

        for h in &self.hard {
            if is_prefix(&h.0, &target.0) || is_prefix(&target.0, &h.0) {
                return Err(Denied::Protected(h.display()));
            }
        }

        if self.allow_exact.contains(&target) {
            return Ok(());
        }

        // 最具体（最长）且严格包含目标的允许根。
        let allow_len = self
            .allow
            .iter()
            .filter(|a| a.0.len() < target.0.len() && is_prefix(&a.0, &target.0))
            .map(|a| a.0.len())
            .max()
            .unwrap_or(0);

        // 保护根与目标"相交"（互为前缀）即拒绝，除非允许根更具体。
        for prot in &self.protected {
            let intersects = is_prefix(&prot.0, &target.0) || is_prefix(&target.0, &prot.0);
            if intersects && prot.0.len() > allow_len {
                return Err(Denied::Protected(prot.display()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SafetyPolicy {
        let mut p = SafetyPolicy::new(&KnownDirs::typical("alice")).unwrap();
        p.allow_root(r"C:\Windows\Temp").unwrap();
        p.allow_root(r"C:\Users\alice\AppData\Local\Temp").unwrap();
        p
    }

    #[test]
    fn allows_contents_of_allow_roots() {
        let p = policy();
        assert!(p.check_delete(r"C:\Windows\Temp\foo.tmp").is_ok());
        assert!(p.check_delete(r"c:/windows/temp/a/b/c").is_ok());
        assert!(p
            .check_delete(r"\\?\C:\Users\alice\AppData\Local\Temp\x")
            .is_ok());
    }

    #[test]
    fn denies_allow_root_itself_when_parent_protected() {
        let p = policy();
        assert!(matches!(
            p.check_delete(r"C:\Windows\Temp"),
            Err(Denied::Protected(_))
        ));
        assert!(matches!(
            p.check_delete(r"C:\Users\alice\AppData\Local\Temp"),
            Err(Denied::Protected(_))
        ));
    }

    #[test]
    fn denies_system_and_ancestors() {
        let p = policy();
        for path in [
            r"C:\Windows",
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Program Files\App\a.exe",
            r"C:\Program Files (x86)",
            r"C:\Users\alice",
            r"C:\Users\alice\Documents\thesis.docx",
            r"C:\Users\alice\Desktop",
            r"C:\System Volume Information",
            // 祖先：删除它会连带删除受保护内容
            r"C:\Users",
        ] {
            assert!(p.check_delete(path).is_err(), "{path} should be denied");
        }
        assert_eq!(p.check_delete(r"C:\"), Err(Denied::DriveRoot));
    }

    #[test]
    fn unprotected_locations_are_allowed() {
        let p = policy();
        assert!(p.check_delete(r"D:\Games\old.bin").is_ok());
        assert!(p.check_delete(r"C:\Temp\foo").is_ok());
    }

    #[test]
    fn case_and_separator_insensitive() {
        let p = policy();
        assert!(p.check_delete(r"c:\WINDOWS\system32").is_err());
        assert!(p.check_delete("C:/Users/ALICE/documents/x").is_err());
    }

    #[test]
    fn trailing_dots_and_spaces_cannot_bypass() {
        let p = policy();
        assert!(p.check_delete(r"C:\Windows. \System32").is_err());
        assert!(p.check_delete(r"C:\Windows.\System32").is_err());
    }

    #[test]
    fn rejects_malformed_paths() {
        let p = policy();
        assert_eq!(p.check_delete(""), Err(Denied::NotAbsolute));
        assert_eq!(p.check_delete(r"foo\bar"), Err(Denied::NotAbsolute));
        assert_eq!(p.check_delete("C:foo"), Err(Denied::NotAbsolute));
        assert_eq!(p.check_delete(r"\Windows\Temp\x"), Err(Denied::NotAbsolute));
        assert_eq!(
            p.check_delete(r"C:\Windows\Temp\..\System32"),
            Err(Denied::ContainsParentRef)
        );
        assert_eq!(
            p.check_delete(r"\\server\share\x"),
            Err(Denied::UnsupportedPath)
        );
        assert_eq!(
            p.check_delete(r"\\?\UNC\server\share\x"),
            Err(Denied::UnsupportedPath)
        );
        assert_eq!(
            p.check_delete(r"C:\Windows\Temp\a:stream"),
            Err(Denied::UnsupportedPath)
        );
        assert_eq!(
            p.check_delete(r"C:\Windows\Temp\*.tmp"),
            Err(Denied::UnsupportedPath)
        );
        assert_eq!(p.check_delete(r"C:\PROGRA~1\App"), Err(Denied::ShortName));
    }

    #[test]
    fn protected_names_denied_anywhere() {
        let p = policy();
        assert!(matches!(
            p.check_delete(r"D:\work\repo\.git\objects"),
            Err(Denied::ProtectedName(_))
        ));
        assert!(matches!(
            p.check_delete(r"C:\Windows\Temp\.ssh\id_rsa"),
            Err(Denied::ProtectedName(_))
        ));
    }

    #[test]
    fn user_protection_overrides_unprotected_location() {
        let mut p = policy();
        p.protect(r"D:\Photos").unwrap();
        assert!(p.check_delete(r"D:\Photos\2024\a.jpg").is_err());
        assert!(p.check_delete(r"D:").is_err());
    }

    #[test]
    fn protected_deeper_than_allow_root_still_wins() {
        let mut p = policy();
        p.allow_root(r"D:\cache").unwrap();
        p.protect(r"D:\cache\keep").unwrap();
        assert!(p.check_delete(r"D:\cache\junk").is_ok());
        assert!(p.check_delete(r"D:\cache\keep\x").is_err());
        // 删除 D:\cache 本身会连带删掉 keep
        assert!(p.check_delete(r"D:\cache").is_err());
    }
}

#[cfg(test)]
mod user_selected_tests {
    use super::*;

    #[test]
    fn user_files_are_allowed_but_system_and_app_data_are_not() {
        let p = SafetyPolicy::for_user_selected(&KnownDirs::typical("alice")).unwrap();
        for ok in [
            r"C:\Users\alice\Documents\old\copy (1).docx",
            r"C:\Users\alice\Downloads\movie.mkv",
            r"C:\Users\alice\Desktop\a.txt",
            r"D:\Backup\photo.jpg",
        ] {
            assert!(p.check_delete(ok).is_ok(), "{ok}");
        }
        for bad in [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Program Files\App\a.dll",
            r"C:\ProgramData\x",
            r"C:\Users\alice\AppData\Roaming\app\settings.json",
            r"C:\$Recycle.Bin\S-1\x",
            r"C:\Users\alice\Documents\repo\.git\config",
        ] {
            assert!(p.check_delete(bad).is_err(), "{bad}");
        }
        // 用户排除项依旧优先。
        let mut q = p.clone();
        q.exclude(r"C:\Users\alice\Documents\keep").unwrap();
        assert!(q
            .check_delete(r"C:\Users\alice\Documents\keep\a.txt")
            .is_err());
        assert!(q
            .check_delete(r"C:\Users\alice\Documents\other\a.txt")
            .is_ok());
    }
}

#[cfg(test)]
mod exclude_tests {
    use super::*;

    #[test]
    fn user_exclusion_beats_allow_root() {
        let mut p = SafetyPolicy::empty(PathStyle::Posix);
        p.allow_root("/cache").unwrap();
        p.exclude("/cache/keep").unwrap();
        assert!(p.check_delete("/cache/a").is_ok());
        assert!(p.check_delete("/cache/keep/x").is_err());
        assert!(p.check_delete("/cache/keep").is_err());
        // 祖先也不行，否则会连带删掉被排除的内容
        let mut q = SafetyPolicy::empty(PathStyle::Posix);
        q.exclude("/a/b/c").unwrap();
        assert!(q.check_delete("/a/b").is_err());
    }
}

#[cfg(test)]
mod posix_tests {
    use super::*;

    #[test]
    fn posix_style_follows_same_rules() {
        let mut p = SafetyPolicy::empty(PathStyle::Posix);
        p.protect("/home/u").unwrap();
        p.allow_root("/home/u/.cache/tmp").unwrap();
        p.allow_exact("/home/u/one.dmp").unwrap();
        assert!(p.check_delete("/home/u/.cache/tmp/x").is_ok());
        assert!(p.check_delete("/home/u/one.dmp").is_ok());
        assert!(p.check_delete("/home/u/other").is_err());
        assert!(p.check_delete("/home").is_err());
        assert_eq!(p.check_delete("/"), Err(Denied::DriveRoot));
        assert_eq!(p.check_delete("rel/x"), Err(Denied::NotAbsolute));
        assert!(matches!(
            p.check_delete("/data/repo/.git/x"),
            Err(Denied::ProtectedName(_))
        ));
    }
}
