//! 规则定义、环境变量展开与通配符解析。

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scanner::special_reason;

/// 路径本身是链接 / junction / 云占位文件。不存在或无法读取时视为否。
fn is_link(p: &std::path::Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| special_reason(&m).is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

/// 删除方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposal {
    /// 移入回收站（可恢复，但**不会立即释放空间**）。
    Recycle,
    /// 直接删除（立即释放空间，不可恢复）。
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    /// 删除目录下的内容（目录本身保留）。
    Contents,
    /// 删除单个文件。
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// 路径模板：以 `/` 分隔，可含 `%VAR%`，目录名分量可含 `*` `?` 通配符。
    pub path: String,
    pub kind: TargetKind,
    /// 仅 `Contents` 有效：只匹配这些名称模式的直接子项；空表示全部。
    #[serde(default)]
    pub name_globs: Vec<String>,
    /// 子树内最新修改时间距今不足该天数的项目会被保留。0 表示不限制。
    #[serde(default)]
    pub min_age_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// 稳定 ID，界面据此查找翻译：`rule.<id>.name` / `rule.<id>.desc`。
    pub id: String,
    pub risk: Risk,
    pub default_selected: bool,
    pub disposal: Disposal,
    pub targets: Vec<Target>,
    /// 清理该规则的文件前需要停止的 Windows 服务；清理结束后会恢复运行。
    #[serde(default)]
    pub services: Vec<String>,
}

/// 环境变量表（键大写，查询不区分大小写）。
#[derive(Debug, Clone, Default)]
pub struct Env(HashMap<String, String>);

impl Env {
    pub fn from_process() -> Self {
        Self::from_pairs(std::env::vars_os().map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        }))
    }

    pub fn from_pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Env(pairs
            .into_iter()
            .map(|(k, v)| (k.as_ref().to_uppercase(), v.as_ref().to_string()))
            .collect())
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(&name.to_uppercase())
            .map(String::as_str)
            .filter(|v| !v.is_empty())
    }

    /// 展开 `%VAR%`。变量未定义（或格式错误）返回 `None`。
    pub fn expand(&self, tpl: &str) -> Option<String> {
        let mut out = String::new();
        let mut rest = tpl;
        while let Some(i) = rest.find('%') {
            out.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            let j = after.find('%')?;
            let name = &after[..j];
            if name.is_empty() {
                return None;
            }
            out.push_str(self.get(name)?);
            rest = &after[j + 1..];
        }
        out.push_str(rest);
        Some(out)
    }
}

/// 不区分大小写的通配符匹配，支持 `*` 与 `?`。
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn has_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

impl Target {
    /// 把模板解析成磁盘上真实存在的路径列表。变量缺失或路径不存在时返回空。
    ///
    /// 第一个分量展开后作为基路径（通常是 `%VAR%` 的绝对路径），会先取规范路径
    /// （环境变量里常见 8.3 短名，如 `ALICE~1`，安全校验会拒绝短名）。
    /// 其后的每个分量要么直接拼接，要么对含通配符的目录名做一层展开；
    /// 途中任何一级是链接/junction 的路径都会被丢弃，防止被重定向到别处。
    pub fn resolve(&self, env: &Env) -> Vec<PathBuf> {
        let mut segs = self.path.split('/');
        let Some(first) = segs.next().and_then(|f| env.expand(f)) else {
            return Vec::new();
        };
        if first.is_empty() || has_wildcard(&first) {
            return Vec::new();
        }
        let Ok(base) = crate::safety::canonical_plain(std::path::Path::new(&first)) else {
            return Vec::new();
        };
        let mut current = vec![base];
        for seg in segs {
            if seg.is_empty() {
                continue;
            }
            let Some(seg) = env.expand(seg) else {
                return Vec::new();
            };
            let mut next = Vec::new();
            for base in &current {
                if has_wildcard(&seg) {
                    let Ok(rd) = fs::read_dir(base) else { continue };
                    for e in rd.flatten() {
                        if e.file_type().is_ok_and(|t| t.is_dir())
                            && glob_match(&seg, &e.file_name().to_string_lossy())
                            && !is_link(&e.path())
                        {
                            next.push(e.path());
                        }
                    }
                } else {
                    let joined = base.join(&seg);
                    if !is_link(&joined) {
                        next.push(joined);
                    }
                }
            }
            current = next;
        }
        current.retain(|p| fs::symlink_metadata(p).is_ok());
        current.sort();
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("thumbcache_*.db", "ThumbCache_256.DB"));
        assert!(glob_match("*.log", "a.b.log"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("*.log", "a.log.txt"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*a*b*", "xxaYYbzz"));
        assert!(!glob_match("*a*b*", "xxbYYazz"));
    }

    #[test]
    fn env_expand() {
        let env = Env::from_pairs([("Temp", "C:/T"), ("EMPTY", "")]);
        assert_eq!(env.expand("%temp%/x").as_deref(), Some("C:/T/x"));
        assert_eq!(env.expand("plain").as_deref(), Some("plain"));
        assert_eq!(env.expand("%NOPE%/x"), None);
        assert_eq!(env.expand("%EMPTY%/x"), None);
        assert_eq!(env.expand("50%"), None);
        assert_eq!(env.expand("%%"), None);
    }

    #[test]
    fn resolve_with_wildcard_segments() {
        let base = std::env::temp_dir().join(format!("dc-rules-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("Profiles/abc.default/cache2")).unwrap();
        fs::create_dir_all(base.join("Profiles/xyz.work/cache2")).unwrap();
        fs::create_dir_all(base.join("Profiles/nocache")).unwrap();
        let env = Env::from_pairs([("B", base.to_string_lossy())]);
        let t = Target {
            path: "%B%/Profiles/*/cache2".into(),
            kind: TargetKind::Contents,
            name_globs: vec![],
            min_age_days: 0,
        };
        let got = t.resolve(&env);
        assert_eq!(got.len(), 2);
        assert!(got.iter().all(|p| p.ends_with("cache2")));

        #[cfg(unix)]
        {
            let outside = base.join("outside");
            fs::create_dir_all(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, base.join("Profiles/linked")).unwrap();
            let via_link = Target {
                path: "%B%/Profiles/linked".into(),
                ..t.clone()
            };
            assert!(via_link.resolve(&env).is_empty(), "links must be dropped");
        }

        let missing = Target {
            path: "%NOPE%/x".into(),
            ..t.clone()
        };
        assert!(missing.resolve(&env).is_empty());
        let absent = Target {
            path: "%B%/does/not/exist".into(),
            ..t
        };
        assert!(absent.resolve(&env).is_empty());
        fs::remove_dir_all(&base).unwrap();
    }
}
