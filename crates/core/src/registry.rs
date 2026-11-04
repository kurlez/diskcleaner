//! 注册表访问抽象、删除白名单，以及标准 `.reg` 备份导出。
//!
//! * [`Registry`] 把真实注册表藏在接口后面：生产环境用 [`WinRegistry`]（仅 Windows），
//!   测试用 [`MemRegistry`]，因此所有扫描/删除逻辑都能在任何平台上验证。
//! * 值以**原始字节 + 类型**保存，备份时逐字节还原，不会因类型转换丢信息。
//! * 删除只允许白名单内的几类位置（见 [`check_delete_key`]），其余一律拒绝。
//! * 备份用标准 `.reg` 文本（UTF-16LE），可以直接双击导入恢复。

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hive {
    LocalMachine,
    CurrentUser,
}

impl Hive {
    /// `.reg` 文件里使用的全名。
    pub fn full_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKEY_LOCAL_MACHINE",
            Hive::CurrentUser => "HKEY_CURRENT_USER",
        }
    }

    /// 给用户看的缩写。
    pub fn short_name(self) -> &'static str {
        match self {
            Hive::LocalMachine => "HKLM",
            Hive::CurrentUser => "HKCU",
        }
    }
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// 注册表值：类型代码 + 原始字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegValue {
    pub ty: u32,
    pub data: Vec<u8>,
}

fn utf16_bytes(s: &str, nul: bool) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    if nul {
        v.extend([0, 0]);
    }
    v
}

fn decode_utf16(data: &[u8]) -> Option<String> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16(&units).ok()
}

impl RegValue {
    pub fn sz(s: &str) -> Self {
        Self {
            ty: REG_SZ,
            data: utf16_bytes(s, true),
        }
    }

    pub fn expand_sz(s: &str) -> Self {
        Self {
            ty: REG_EXPAND_SZ,
            data: utf16_bytes(s, true),
        }
    }

    pub fn dword(v: u32) -> Self {
        Self {
            ty: REG_DWORD,
            data: v.to_le_bytes().to_vec(),
        }
    }

    pub fn qword(v: u64) -> Self {
        Self {
            ty: REG_QWORD,
            data: v.to_le_bytes().to_vec(),
        }
    }

    pub fn binary(b: &[u8]) -> Self {
        Self {
            ty: REG_BINARY,
            data: b.to_vec(),
        }
    }

    pub fn multi_sz(items: &[&str]) -> Self {
        let mut data = Vec::new();
        for i in items {
            data.extend(utf16_bytes(i, true));
        }
        data.extend([0, 0]);
        Self {
            ty: REG_MULTI_SZ,
            data,
        }
    }

    /// `REG_SZ` / `REG_EXPAND_SZ` 的文本（去掉结尾的 NUL）。
    pub fn as_string(&self) -> Option<String> {
        if self.ty != REG_SZ && self.ty != REG_EXPAND_SZ {
            return None;
        }
        decode_utf16(&self.data).map(|s| s.trim_end_matches('\0').to_string())
    }

    pub fn as_dword(&self) -> Option<u32> {
        (self.ty == REG_DWORD && self.data.len() >= 4)
            .then(|| u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]))
    }
}

/// 注册表接口。路径用 `\` 分隔、不带前导 `\`，大小写不敏感。
pub trait Registry: Send + Sync {
    /// 子键名（保持原大小写）。键不存在返回 `NotFound`。
    fn subkeys(&self, hive: Hive, path: &str) -> io::Result<Vec<String>>;
    /// 键下的所有值（默认值的名字是空串）。键不存在返回 `NotFound`。
    fn values(&self, hive: Hive, path: &str) -> io::Result<Vec<(String, RegValue)>>;
    /// 递归删除整个键。
    fn delete_key(&self, hive: Hive, path: &str) -> io::Result<()>;
    fn delete_value(&self, hive: Hive, path: &str, name: &str) -> io::Result<()>;

    fn key_exists(&self, hive: Hive, path: &str) -> bool {
        self.subkeys(hive, path).is_ok()
    }

    /// 读取某个值；键或值不存在返回 `None`。
    fn value(&self, hive: Hive, path: &str, name: &str) -> Option<RegValue> {
        self.values(hive, path)
            .ok()?
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    }
}

/// 不支持注册表的平台（非 Windows）。
pub struct NoRegistry;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "registry is not available on this platform",
    )
}

impl Registry for NoRegistry {
    fn subkeys(&self, _: Hive, _: &str) -> io::Result<Vec<String>> {
        Err(unsupported())
    }
    fn values(&self, _: Hive, _: &str) -> io::Result<Vec<(String, RegValue)>> {
        Err(unsupported())
    }
    fn delete_key(&self, _: Hive, _: &str) -> io::Result<()> {
        Err(unsupported())
    }
    fn delete_value(&self, _: Hive, _: &str, _: &str) -> io::Result<()> {
        Err(unsupported())
    }
}

// ---------- 内存实现（测试用） ----------

struct MemKey {
    /// 原大小写的完整路径。
    path: String,
    values: Vec<(String, RegValue)>,
}

/// 内存注册表，用于在任何平台上测试。
#[derive(Default)]
pub struct MemRegistry {
    /// 键：(根, 小写路径)。
    keys: Mutex<BTreeMap<(Hive, String), MemKey>>,
}

fn norm(path: &str) -> String {
    path.trim_matches('\\').to_lowercase()
}

fn not_found() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "registry key not found")
}

impl MemRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 创建键（连同所有祖先）。
    pub fn add_key(&self, hive: Hive, path: &str) {
        let mut keys = self.keys.lock().unwrap();
        let mut acc = String::new();
        for part in path
            .trim_matches('\\')
            .split('\\')
            .filter(|p| !p.is_empty())
        {
            if !acc.is_empty() {
                acc.push('\\');
            }
            acc.push_str(part);
            keys.entry((hive, acc.to_lowercase()))
                .or_insert_with(|| MemKey {
                    path: acc.clone(),
                    values: Vec::new(),
                });
        }
    }

    pub fn set(&self, hive: Hive, path: &str, name: &str, v: RegValue) {
        self.add_key(hive, path);
        let mut keys = self.keys.lock().unwrap();
        let k = keys.get_mut(&(hive, norm(path))).unwrap();
        k.values.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        k.values.push((name.to_string(), v));
    }

    pub fn set_sz(&self, hive: Hive, path: &str, name: &str, s: &str) {
        self.set(hive, path, name, RegValue::sz(s));
    }

    pub fn set_dword(&self, hive: Hive, path: &str, name: &str, v: u32) {
        self.set(hive, path, name, RegValue::dword(v));
    }

    /// 内存里还有多少个键（含祖先），便于断言"没有多删"。
    pub fn key_count(&self) -> usize {
        self.keys.lock().unwrap().len()
    }
}

impl Registry for MemRegistry {
    fn subkeys(&self, hive: Hive, path: &str) -> io::Result<Vec<String>> {
        let keys = self.keys.lock().unwrap();
        let base = norm(path);
        if !base.is_empty() && !keys.contains_key(&(hive, base.clone())) {
            return Err(not_found());
        }
        let prefix = if base.is_empty() {
            String::new()
        } else {
            format!("{base}\\")
        };
        Ok(keys
            .iter()
            .filter(|((h, p), _)| {
                *h == hive
                    && p.starts_with(&prefix)
                    && !p[prefix.len()..].contains('\\')
                    && p.len() > prefix.len()
            })
            .map(|(_, k)| k.path.rsplit('\\').next().unwrap().to_string())
            .collect())
    }

    fn values(&self, hive: Hive, path: &str) -> io::Result<Vec<(String, RegValue)>> {
        let keys = self.keys.lock().unwrap();
        keys.get(&(hive, norm(path)))
            .map(|k| k.values.clone())
            .ok_or_else(not_found)
    }

    fn delete_key(&self, hive: Hive, path: &str) -> io::Result<()> {
        let mut keys = self.keys.lock().unwrap();
        let base = norm(path);
        if !keys.contains_key(&(hive, base.clone())) {
            return Err(not_found());
        }
        let prefix = format!("{base}\\");
        keys.retain(|(h, p), _| !(*h == hive && (*p == base || p.starts_with(&prefix))));
        Ok(())
    }

    fn delete_value(&self, hive: Hive, path: &str, name: &str) -> io::Result<()> {
        let mut keys = self.keys.lock().unwrap();
        let k = keys.get_mut(&(hive, norm(path))).ok_or_else(not_found)?;
        let before = k.values.len();
        k.values.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        if k.values.len() == before {
            return Err(not_found());
        }
        Ok(())
    }
}

// ---------- 真实注册表（仅 Windows） ----------

#[cfg(windows)]
pub use win::WinRegistry;

#[cfg(windows)]
mod win {
    use super::*;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
    use winreg::RegKey;

    /// 通过 `winreg` 访问真实注册表。
    pub struct WinRegistry;

    fn root(h: Hive) -> RegKey {
        RegKey::predef(match h {
            Hive::LocalMachine => HKEY_LOCAL_MACHINE,
            Hive::CurrentUser => HKEY_CURRENT_USER,
        })
    }

    impl Registry for WinRegistry {
        fn subkeys(&self, hive: Hive, path: &str) -> io::Result<Vec<String>> {
            let key = if path.is_empty() {
                root(hive)
            } else {
                root(hive).open_subkey(path)?
            };
            key.enum_keys().collect()
        }

        fn values(&self, hive: Hive, path: &str) -> io::Result<Vec<(String, RegValue)>> {
            let key = root(hive).open_subkey(path)?;
            let mut out = Vec::new();
            for item in key.enum_values() {
                let (name, v) = item?;
                out.push((
                    name,
                    RegValue {
                        ty: v.vtype as u32,
                        data: v.bytes.to_vec(),
                    },
                ));
            }
            Ok(out)
        }

        fn delete_key(&self, hive: Hive, path: &str) -> io::Result<()> {
            root(hive).delete_subkey_all(path)
        }

        fn delete_value(&self, hive: Hive, path: &str, name: &str) -> io::Result<()> {
            root(hive)
                .open_subkey_with_flags(path, KEY_SET_VALUE)?
                .delete_value(name)
        }
    }
}

// ---------- 删除白名单 ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegDenied {
    /// 路径为空或含非法分量。
    Invalid,
    /// 不在允许删除的范围内。
    NotWhitelisted,
    /// 属于系统/微软自己的厂商键，永不允许。
    ReservedVendor(String),
}

impl std::fmt::Display for RegDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegDenied::Invalid => write!(f, "invalid registry path"),
            RegDenied::NotWhitelisted => {
                write!(f, "registry location is not on the deletion whitelist")
            }
            RegDenied::ReservedVendor(v) => write!(f, "reserved registry vendor key: {v}"),
        }
    }
}

impl std::error::Error for RegDenied {}

/// `SOFTWARE` 下永不允许当作"应用残留"删除的厂商键（小写）。
const RESERVED_VENDORS: &[&str] = &[
    "microsoft",
    "classes",
    "policies",
    "windows",
    "wow6432node",
    "clients",
    "registeredapplications",
    "odbc",
    "intel",
    "amd",
    "nvidia corporation",
];

fn parts(path: &str) -> Result<Vec<String>, RegDenied> {
    let p: Vec<String> = path
        .split('\\')
        .filter(|c| !c.is_empty())
        .map(str::to_lowercase)
        .collect();
    if p.is_empty()
        || p.iter()
            .any(|c| c == "." || c == ".." || c.chars().any(char::is_control))
    {
        return Err(RegDenied::Invalid);
    }
    Ok(p)
}

/// 去掉 `WOW6432Node` 前缀；返回 `SOFTWARE` 之后的分量。
fn software_rest(p: &[String]) -> Option<&[String]> {
    if p.first().map(String::as_str) != Some("software") {
        return None;
    }
    let rest = &p[1..];
    Some(if rest.first().map(String::as_str) == Some("wow6432node") {
        &rest[1..]
    } else {
        rest
    })
}

fn is_guid(s: &str) -> bool {
    s.len() >= 3 && s.starts_with('{') && s.ends_with('}')
}

fn vendor_ok(v: &str) -> Result<(), RegDenied> {
    if RESERVED_VENDORS.contains(&v) {
        Err(RegDenied::ReservedVendor(v.to_string()))
    } else {
        Ok(())
    }
}

/// 允许删除的键：
///
/// * `…\CurrentVersion\Uninstall\<某项>`、`…\CurrentVersion\App Paths\<某项>`
/// * `SOFTWARE\Classes\CLSID\{GUID}`（含 WOW6432Node 变体）
/// * `SOFTWARE\<厂商>\<产品>…`（至少两级，厂商不在保留名单内；只删厂商根键见 [`check_delete_vendor_root`]）
/// * `SYSTEM\CurrentControlSet\Services\<服务名>`
pub fn check_delete_key(hive: Hive, path: &str) -> Result<(), RegDenied> {
    let p = parts(path)?;
    if p[0] == "system" {
        // 服务键只在 HKLM 下存在。
        return if hive == Hive::LocalMachine
            && p.len() == 4
            && p[1] == "currentcontrolset"
            && p[2] == "services"
        {
            Ok(())
        } else {
            Err(RegDenied::NotWhitelisted)
        };
    }
    let rest = software_rest(&p).ok_or(RegDenied::NotWhitelisted)?;
    if rest.is_empty() {
        return Err(RegDenied::NotWhitelisted);
    }
    // Microsoft\Windows\CurrentVersion\{Uninstall|App Paths}\<某项>
    if rest.len() == 5
        && rest[0] == "microsoft"
        && rest[1] == "windows"
        && rest[2] == "currentversion"
        && (rest[3] == "uninstall" || rest[3] == "app paths")
    {
        return Ok(());
    }
    // Classes\CLSID\{GUID}（以及 Classes\WOW6432Node\CLSID\{GUID}）
    if rest[0] == "classes" {
        let r = if rest.get(1).map(String::as_str) == Some("wow6432node") {
            &rest[2..]
        } else {
            &rest[1..]
        };
        return if r.len() == 2 && r[0] == "clsid" && is_guid(&r[1]) {
            Ok(())
        } else {
            Err(RegDenied::NotWhitelisted)
        };
    }
    vendor_ok(&rest[0])?;
    if rest.len() >= 2 {
        Ok(())
    } else {
        Err(RegDenied::NotWhitelisted)
    }
}

/// 厂商根键（`SOFTWARE\<厂商>`）。仅当它**已经没有其他内容**时才可删除，
/// 这个"为空"的判断由调用方在执行时确认，这里只检查路径形状。
pub fn check_delete_vendor_root(_hive: Hive, path: &str) -> Result<(), RegDenied> {
    let p = parts(path)?;
    let rest = software_rest(&p).ok_or(RegDenied::NotWhitelisted)?;
    if rest.len() != 1 {
        return Err(RegDenied::NotWhitelisted);
    }
    vendor_ok(&rest[0])
}

/// 允许删除的值：只限自启动项（`Run` / `RunOnce`）里的条目。
pub fn check_delete_value(_hive: Hive, path: &str, name: &str) -> Result<(), RegDenied> {
    if name.is_empty() {
        return Err(RegDenied::NotWhitelisted);
    }
    let p = parts(path)?;
    let rest = software_rest(&p).ok_or(RegDenied::NotWhitelisted)?;
    if rest.len() == 4
        && rest[0] == "microsoft"
        && rest[1] == "windows"
        && rest[2] == "currentversion"
        && (rest[3] == "run" || rest[3] == "runonce")
    {
        Ok(())
    } else {
        Err(RegDenied::NotWhitelisted)
    }
}

// ---------- .reg 备份导出 ----------

/// 导出文件用的编码：UTF-16LE，带 BOM（regedit 的标准格式）。
pub fn to_utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    out.extend(utf16_bytes(s, false));
    out
}

pub const REG_FILE_HEADER: &str = "Windows Registry Editor Version 5.00\r\n\r\n";

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn hex_bytes(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 一个值对应的 `.reg` 行（不含换行）。
pub fn reg_value_line(name: &str, v: &RegValue) -> String {
    let n = if name.is_empty() {
        "@".to_string()
    } else {
        format!("\"{}\"", escape(name))
    };
    let body = match v.ty {
        REG_DWORD if v.data.len() == 4 => {
            format!(
                "dword:{:08x}",
                u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]])
            )
        }
        REG_SZ => match plain_sz(&v.data) {
            Some(s) => format!("\"{}\"", escape(&s)),
            None => format!("hex(1):{}", hex_bytes(&v.data)),
        },
        REG_BINARY => format!("hex:{}", hex_bytes(&v.data)),
        ty => format!("hex({ty:x}):{}", hex_bytes(&v.data)),
    };
    format!("{n}={body}")
}

/// 只有能无损往返的纯文本 `REG_SZ` 才写成带引号的形式，否则退回十六进制。
fn plain_sz(data: &[u8]) -> Option<String> {
    let s = decode_utf16(data)?;
    let text = s.strip_suffix('\0')?;
    if text.contains('\0') || text.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(text.to_string())
}

/// 导出若干个键（含全部子键）。键不存在会返回错误，宁可备份失败也不能漏备份。
pub fn export_keys(reg: &dyn Registry, keys: &[(Hive, String)]) -> io::Result<String> {
    let mut out = String::from(REG_FILE_HEADER);
    for (hive, path) in keys {
        export_one(reg, *hive, path.trim_matches('\\'), &mut out)?;
    }
    Ok(out)
}

fn export_one(reg: &dyn Registry, hive: Hive, path: &str, out: &mut String) -> io::Result<()> {
    let values = reg.values(hive, path)?;
    let subkeys = reg.subkeys(hive, path)?;
    let _ = write!(out, "[{}\\{}]\r\n", hive.full_name(), path);
    for (n, v) in &values {
        out.push_str(&reg_value_line(n, v));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    let mut subs = subkeys;
    subs.sort_by_key(|s| s.to_lowercase());
    for s in subs {
        export_one(reg, hive, &format!("{path}\\{s}"), out)?;
    }
    Ok(())
}

/// 只导出某个键下的指定值（用于备份将被删除的 `Run` 条目）。
pub fn export_values(hive: Hive, path: &str, values: &[(String, RegValue)]) -> String {
    let mut out = String::new();
    let _ = write!(
        out,
        "[{}\\{}]\r\n",
        hive.full_name(),
        path.trim_matches('\\')
    );
    for (n, v) in values {
        out.push_str(&reg_value_line(n, v));
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use Hive::{CurrentUser, LocalMachine};

    // ----- 内存注册表 -----

    fn sample() -> MemRegistry {
        let r = MemRegistry::new();
        r.set_sz(LocalMachine, r"SOFTWARE\Acme\Tool", "Version", "1.2");
        r.set_dword(LocalMachine, r"SOFTWARE\Acme\Tool", "Count", 7);
        r.set_sz(LocalMachine, r"SOFTWARE\Acme\Tool\Sub", "", "default");
        r.add_key(LocalMachine, r"SOFTWARE\Other");
        r.add_key(CurrentUser, r"Software\Acme");
        r
    }

    #[test]
    fn lookup_is_case_insensitive_and_keeps_original_case() {
        let r = sample();
        assert!(r.key_exists(LocalMachine, r"software\ACME\tool"));
        assert!(
            !r.key_exists(CurrentUser, r"SOFTWARE\Acme\Tool"),
            "不同的根互不影响"
        );
        let mut subs = r.subkeys(LocalMachine, "SOFTWARE").unwrap();
        subs.sort();
        assert_eq!(subs, ["Acme", "Other"]);
        assert_eq!(r.subkeys(LocalMachine, r"SOFTWARE\Acme").unwrap(), ["Tool"]);
        assert_eq!(
            r.value(LocalMachine, r"software\acme\tool", "version")
                .unwrap()
                .as_string()
                .unwrap(),
            "1.2"
        );
        assert_eq!(
            r.value(LocalMachine, r"SOFTWARE\Acme\Tool", "Count")
                .unwrap()
                .as_dword(),
            Some(7)
        );
        assert!(r
            .value(LocalMachine, r"SOFTWARE\Acme\Tool", "nope")
            .is_none());
        assert_eq!(
            r.subkeys(LocalMachine, r"SOFTWARE\Missing")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn delete_key_is_recursive_and_exact() {
        let r = sample();
        let before = r.key_count();
        r.delete_key(LocalMachine, r"software\acme\tool").unwrap();
        assert!(!r.key_exists(LocalMachine, r"SOFTWARE\Acme\Tool\Sub"));
        assert!(r.key_exists(LocalMachine, r"SOFTWARE\Acme"), "父键保留");
        assert!(r.key_exists(LocalMachine, r"SOFTWARE\Other"));
        assert!(r.key_exists(CurrentUser, r"Software\Acme"));
        assert_eq!(r.key_count(), before - 2);
        assert!(r.delete_key(LocalMachine, r"SOFTWARE\Acme\Tool").is_err());
    }

    #[test]
    fn delete_value_removes_only_that_value() {
        let r = sample();
        r.delete_value(LocalMachine, r"SOFTWARE\Acme\Tool", "version")
            .unwrap();
        assert!(r
            .value(LocalMachine, r"SOFTWARE\Acme\Tool", "Version")
            .is_none());
        assert!(r
            .value(LocalMachine, r"SOFTWARE\Acme\Tool", "Count")
            .is_some());
        assert!(r
            .delete_value(LocalMachine, r"SOFTWARE\Acme\Tool", "Version")
            .is_err());
    }

    #[test]
    fn typed_value_helpers_roundtrip() {
        assert_eq!(RegValue::sz("héllo").as_string().unwrap(), "héllo");
        assert_eq!(RegValue::expand_sz("%PATH%").as_string().unwrap(), "%PATH%");
        assert_eq!(RegValue::dword(0xDEADBEEF).as_dword(), Some(0xDEADBEEF));
        assert_eq!(RegValue::dword(1).as_string(), None);
        assert_eq!(RegValue::sz("x").as_dword(), None);
    }

    // ----- 删除白名单 -----

    #[test]
    fn whitelist_allows_the_expected_locations() {
        let ok = [
            (
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{ABC-123}",
            ),
            (
                LocalMachine,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Foo",
            ),
            (
                CurrentUser,
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Foo",
            ),
            (
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\foo.exe",
            ),
            (
                LocalMachine,
                r"SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}",
            ),
            (LocalMachine, r"SOFTWARE\Classes\WOW6432Node\CLSID\{1-2}"),
            (LocalMachine, r"SOFTWARE\Acme\Tool"),
            (LocalMachine, r"SOFTWARE\WOW6432Node\Acme\Tool\Sub"),
            (CurrentUser, r"Software\Acme\Tool"),
            (LocalMachine, r"SYSTEM\CurrentControlSet\Services\AcmeSvc"),
            (LocalMachine, r"software\acme\tool"),
        ];
        for (h, p) in ok {
            assert_eq!(check_delete_key(h, p), Ok(()), "{p}");
        }
    }

    #[test]
    fn whitelist_rejects_everything_else() {
        let bad = [
            (LocalMachine, ""),
            (LocalMachine, r"SOFTWARE"),
            (LocalMachine, r"SOFTWARE\Acme"), // 厂商根键走专门的检查
            (LocalMachine, r"SOFTWARE\Microsoft"),
            (LocalMachine, r"SOFTWARE\Microsoft\Windows\CurrentVersion"),
            (
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ), // 整个 Uninstall 键
            (
                LocalMachine,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            ),
            (LocalMachine, r"SOFTWARE\Microsoft\Office\16.0"),
            (LocalMachine, r"SOFTWARE\Classes"),
            (LocalMachine, r"SOFTWARE\Classes\CLSID"),
            (LocalMachine, r"SOFTWARE\Classes\.txt"),
            (LocalMachine, r"SOFTWARE\Classes\CLSID\notaguid"),
            (LocalMachine, r"SOFTWARE\Policies\Acme"),
            (LocalMachine, r"SOFTWARE\Intel\Driver"),
            (LocalMachine, r"SYSTEM"),
            (LocalMachine, r"SYSTEM\CurrentControlSet"),
            (LocalMachine, r"SYSTEM\CurrentControlSet\Services"),
            (
                LocalMachine,
                r"SYSTEM\CurrentControlSet\Services\Svc\Parameters",
            ),
            (
                LocalMachine,
                r"SYSTEM\CurrentControlSet\Control\Session Manager",
            ),
            (CurrentUser, r"SYSTEM\CurrentControlSet\Services\Svc"),
            (LocalMachine, r"HARDWARE\DESCRIPTION"),
            (LocalMachine, r"SAM\SAM"),
            (LocalMachine, r"SOFTWARE\Acme\..\Microsoft"),
        ];
        for (h, p) in bad {
            assert!(check_delete_key(h, p).is_err(), "{p:?} should be denied");
        }
        assert_eq!(
            check_delete_key(LocalMachine, r"SOFTWARE\Microsoft\Tool"),
            Err(RegDenied::ReservedVendor("microsoft".into()))
        );
    }

    #[test]
    fn vendor_root_is_a_separate_narrow_check() {
        assert_eq!(
            check_delete_vendor_root(LocalMachine, r"SOFTWARE\Acme"),
            Ok(())
        );
        assert_eq!(
            check_delete_vendor_root(LocalMachine, r"SOFTWARE\WOW6432Node\Acme"),
            Ok(())
        );
        assert!(check_delete_vendor_root(LocalMachine, r"SOFTWARE\Acme\Tool").is_err());
        assert!(check_delete_vendor_root(LocalMachine, "SOFTWARE").is_err());
        assert!(check_delete_vendor_root(LocalMachine, r"SOFTWARE\Microsoft").is_err());
        assert!(check_delete_vendor_root(LocalMachine, r"SOFTWARE\WOW6432Node").is_err());
        assert!(check_delete_vendor_root(LocalMachine, r"SYSTEM\Acme").is_err());
    }

    #[test]
    fn only_autorun_values_may_be_deleted() {
        let run = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        assert_eq!(check_delete_value(CurrentUser, run, "Acme"), Ok(()));
        assert_eq!(
            check_delete_value(
                LocalMachine,
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
                "x"
            ),
            Ok(())
        );
        assert!(
            check_delete_value(CurrentUser, run, "").is_err(),
            "默认值不删"
        );
        assert!(check_delete_value(CurrentUser, r"SOFTWARE\Acme", "x").is_err());
        assert!(check_delete_value(
            CurrentUser,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "x"
        )
        .is_err());
        assert!(check_delete_value(
            CurrentUser,
            r"SYSTEM\CurrentControlSet\Services\X",
            "ImagePath"
        )
        .is_err());
    }

    // ----- .reg 导出 -----

    #[test]
    fn value_lines_match_regedit_format() {
        assert_eq!(
            reg_value_line("Name", &RegValue::sz("a b")),
            r#""Name"="a b""#
        );
        assert_eq!(reg_value_line("", &RegValue::sz("dflt")), r#"@="dflt""#);
        assert_eq!(
            reg_value_line("P", &RegValue::sz(r#"C:\x "q""#)),
            r#""P"="C:\\x \"q\"""#
        );
        assert_eq!(
            reg_value_line("N", &RegValue::dword(255)),
            r#""N"=dword:000000ff"#
        );
        assert_eq!(
            reg_value_line("B", &RegValue::binary(&[1, 0xab, 0])),
            r#""B"=hex:01,ab,00"#
        );
        assert_eq!(reg_value_line("E", &RegValue::binary(&[])), r#""E"=hex:"#);
        assert_eq!(
            reg_value_line("Q", &RegValue::qword(1)),
            r#""Q"=hex(b):01,00,00,00,00,00,00,00"#
        );
        assert_eq!(
            reg_value_line("X", &RegValue::expand_sz("%A%")),
            r#""X"=hex(2):25,00,41,00,25,00,00,00"#
        );
        assert_eq!(
            reg_value_line("M", &RegValue::multi_sz(&["a", "b"])),
            r#""M"=hex(7):61,00,00,00,62,00,00,00,00,00"#
        );
    }

    #[test]
    fn strings_that_cannot_roundtrip_fall_back_to_hex() {
        // 没有结尾 NUL 的 REG_SZ、含控制字符、奇数长度，都不能写成带引号的文本。
        let no_nul = RegValue {
            ty: REG_SZ,
            data: vec![0x61, 0x00],
        };
        assert!(reg_value_line("a", &no_nul).contains("hex(1):61,00"));
        let ctrl = RegValue::sz("a\r\nb");
        assert!(reg_value_line("a", &ctrl).contains("hex(1):"));
        let odd = RegValue {
            ty: REG_SZ,
            data: vec![1, 2, 3],
        };
        assert!(reg_value_line("a", &odd).contains("hex(1):01,02,03"));
    }

    #[test]
    fn exports_keys_recursively_with_original_case() {
        let r = sample();
        let text = export_keys(&r, &[(LocalMachine, r"SOFTWARE\Acme\Tool".to_string())]).unwrap();
        let expected = "Windows Registry Editor Version 5.00\r\n\r\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\Tool]\r\n\
            \"Version\"=\"1.2\"\r\n\
            \"Count\"=dword:00000007\r\n\
            \r\n\
            [HKEY_LOCAL_MACHINE\\SOFTWARE\\Acme\\Tool\\Sub]\r\n\
            @=\"default\"\r\n\
            \r\n";
        assert_eq!(text, expected);
    }

    #[test]
    fn exporting_a_missing_key_fails_instead_of_producing_a_partial_backup() {
        let r = sample();
        let err = export_keys(
            &r,
            &[
                (LocalMachine, r"SOFTWARE\Acme\Tool".into()),
                (LocalMachine, r"SOFTWARE\Nope".into()),
            ],
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn exports_selected_values_only() {
        let text = export_values(
            CurrentUser,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            &[("Acme".to_string(), RegValue::sz(r"C:\Acme\a.exe"))],
        );
        assert_eq!(
            text,
            "[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\r\n\"Acme\"=\"C:\\\\Acme\\\\a.exe\"\r\n\r\n"
        );
    }

    #[test]
    fn file_encoding_is_utf16le_with_bom() {
        let b = to_utf16le_with_bom("A中");
        assert_eq!(b, [0xFF, 0xFE, 0x41, 0x00, 0x2D, 0x4E]);
    }
}
