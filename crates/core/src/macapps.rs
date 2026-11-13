//! macOS 的应用管理：枚举 `.app`、卸载（移入废纸篓）、扫描 `~/Library` 里的残留。
//!
//! 与 Windows 的区别：没有注册表和卸载器，应用就是一个 `.app` 目录；它的数据散落在
//! `~/Library` 的固定子目录里，文件名通常是 Bundle ID（如 `com.foo.Bar`）或应用名。
//! 所以匹配规则很明确：**文件名等于 Bundle ID（高置信度）或应用名（中置信度）**，不做模糊匹配。

use std::fs;
use std::path::{Path, PathBuf};

use rayon::prelude::*;

use crate::safety::{Denied, SafetyPolicy};
use crate::scanner::special_reason;
use crate::uninstall::{
    format_timestamp, name_variants, normalize, AppSource, Confidence, InstalledApp, Leftover,
    LeftoverScan, Reason, Target,
};

/// 枚举应用的位置：系统级与用户级的 `Applications`。
pub fn app_roots(home: &str) -> Vec<PathBuf> {
    vec![
        PathBuf::from("/Applications"),
        PathBuf::from(format!("{}/Applications", home.trim_end_matches('/'))),
    ]
}

/// 应用包里我们关心的几个字段。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BundleInfo {
    pub name: Option<String>,
    pub bundle_id: Option<String>,
    pub version: Option<String>,
}

/// 读取 `<bundle>/Contents/Info.plist`（XML 或二进制都支持）。读不到返回默认值。
pub fn read_bundle_info(bundle: &Path) -> BundleInfo {
    let Ok(value) = plist::Value::from_file(bundle.join("Contents/Info.plist")) else {
        return BundleInfo::default();
    };
    let Some(dict) = value.as_dictionary() else {
        return BundleInfo::default();
    };
    let get = |k: &str| {
        dict.get(k)
            .and_then(|v| v.as_string())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    BundleInfo {
        name: get("CFBundleDisplayName").or_else(|| get("CFBundleName")),
        bundle_id: get("CFBundleIdentifier"),
        version: get("CFBundleShortVersionString").or_else(|| get("CFBundleVersion")),
    }
}

fn is_app_bundle(name: &str) -> bool {
    name.len() > 4 && name[name.len() - 4..].eq_ignore_ascii_case(".app")
}

/// 列出 `roots` 下的应用（深入一层子文件夹，如 `/Applications/Utilities`、厂商文件夹）。
/// 符号链接指向的应用（迁移到别的磁盘后的样子）也会列出。
pub fn enumerate_mac_apps(roots: &[PathBuf]) -> Vec<InstalledApp> {
    let mut found: Vec<PathBuf> = Vec::new();
    for root in roots {
        let Ok(rd) = fs::read_dir(root) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let path = e.path();
            if is_app_bundle(&name) {
                found.push(path);
            } else if e
                .metadata()
                .is_ok_and(|m| m.is_dir() && !name.starts_with('.'))
            {
                if let Ok(sub) = fs::read_dir(&path) {
                    found.extend(
                        sub.flatten()
                            .filter(|s| is_app_bundle(&s.file_name().to_string_lossy()))
                            .map(|s| s.path()),
                    );
                }
            }
        }
    }
    found.sort();
    found.dedup();
    let mut apps: Vec<InstalledApp> = found
        .par_iter()
        .filter_map(|p| app_from_bundle(p))
        .collect();
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

fn app_from_bundle(path: &Path) -> Option<InstalledApp> {
    let info = read_bundle_info(path);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    // 符号链接的应用：大小按链接指向的真实位置统计，安装时间取链接目标的创建时间。
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let size = crate::plan::measure_path(&real).ok().map(|s| s.size);
    let created = fs::metadata(&real)
        .and_then(|m| m.created())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| format_timestamp(d.as_secs())[..8].to_string());
    Some(InstalledApp {
        source: AppSource::MacBundle {
            path: path.to_path_buf(),
            bundle_id: info.bundle_id.unwrap_or_default(),
        },
        name: info.name.unwrap_or(stem),
        version: info.version,
        publisher: None,
        install_location: Some(path.to_string_lossy().into_owned()),
        install_date: created,
        size_kb: size.map(|b| b / 1024),
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: None,
        windows_installer: false,
    })
}

/// 移入废纸篓（可在访达里恢复）。
pub fn move_to_trash(path: &Path) -> std::io::Result<()> {
    trash::delete(path).map_err(std::io::Error::other)
}

#[derive(Debug, PartialEq, Eq)]
pub enum MacUninstallError {
    /// 不是 `Applications` 里的 `.app`，或在受保护位置。
    Refused(String),
    Failed(String),
}

/// 卸载一个应用：把 `.app` 移入废纸篓（可恢复）。`remove` 负责真正的移动，便于测试注入。
/// 只接受 `roots` 之下、名为 `*.app` 的条目；`/System` 与 `/Library` 里的一律拒绝。
pub fn uninstall_mac_bundle(
    app: &InstalledApp,
    roots: &[PathBuf],
    remove: &dyn Fn(&Path) -> std::io::Result<()>,
) -> Result<(), MacUninstallError> {
    let AppSource::MacBundle { path, .. } = &app.source else {
        return Err(MacUninstallError::Refused("not a macOS app".into()));
    };
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let inside = roots.iter().any(|r| {
        path.parent()
            .is_some_and(|p| p == r || p.parent().is_some_and(|pp| pp == r))
    });
    if !is_app_bundle(&name) || !inside {
        return Err(MacUninstallError::Refused(path.display().to_string()));
    }
    let meta = fs::symlink_metadata(path)
        .map_err(|_| MacUninstallError::Failed("the app no longer exists".into()))?;
    // 链接（迁移过的应用）只移走链接本身，真正的应用留在目标磁盘，由用户决定。
    if !meta.is_dir() && special_reason(&meta).is_none() {
        return Err(MacUninstallError::Refused(path.display().to_string()));
    }
    remove(path).map_err(|e| MacUninstallError::Failed(e.to_string()))
}

/// `~/Library` 下应用常驻的子目录，以及里面的条目可能的命名方式。
const LIBRARY_DIRS: &[&str] = &[
    "Application Support",
    "Caches",
    "Preferences",
    "Preferences/ByHost",
    "Containers",
    "Group Containers",
    "Saved Application State",
    "Logs",
    "HTTPStorages",
    "WebKit",
    "Cookies",
    "LaunchAgents",
    "Application Scripts",
];

/// 条目名与 Bundle ID 的关系。
fn matches_bundle_id(entry: &str, id: &str) -> bool {
    let e = entry.to_lowercase();
    let id = id.to_lowercase();
    // `com.foo.Bar`、`com.foo.Bar.plist`、`com.foo.Bar.savedState`、`com.foo.Bar.ShipIt`，
    // 以及 Group Containers 的 `TEAMID.com.foo.Bar` / `group.com.foo.Bar`。
    e == id
        || e.starts_with(&format!("{id}."))
        || e.ends_with(&format!(".{id}"))
        || e.contains(&format!(".{id}."))
}

/// 删除残留时使用的安全策略：默认保护名单之上，只放开 `~/Library` 里应用常驻的几个子目录**内部**。
pub fn mac_leftover_policy(home: &str) -> Result<SafetyPolicy, Denied> {
    leftover_policy_on(SafetyPolicy::new_mac(home)?, home)
}

/// 在给定的基础策略上叠加"残留清理"的放开与保护（测试可以换用不含 `/private` 等系统位置的基础策略，
/// 因为 macOS 的临时目录就在 `/private/var` 下）。
pub fn leftover_policy_on(mut p: SafetyPolicy, home: &str) -> Result<SafetyPolicy, Denied> {
    let home = home.trim_end_matches('/');
    for d in LIBRARY_DIRS {
        p.allow_root(&format!("{home}/Library/{d}"))?;
    }
    // 这些目录属于系统或同步服务，里面的内容即使文件名恰好相似也不能删。
    for protected in [
        "Application Support/Apple",
        "Application Support/AddressBook",
        "Application Support/CloudDocs",
        "Application Support/com.apple.TCC",
        "Application Support/MobileSync",
        "Application Support/iCloud",
    ] {
        p.protect(&format!("{home}/Library/{protected}"))?;
    }
    Ok(p)
}

/// 扫描一个应用的残留。应用本体仍在（且不是强制扫描）时不给出任何结果。
pub fn scan_mac_leftovers(
    app: &InstalledApp,
    home: &str,
    policy: &SafetyPolicy,
    forced: bool,
) -> LeftoverScan {
    let mut scan = LeftoverScan::default();
    let AppSource::MacBundle { path, bundle_id } = &app.source else {
        return scan;
    };
    if fs::symlink_metadata(path).is_ok() && !forced {
        scan.still_registered = true;
        return scan;
    }
    // 苹果自己的应用（`com.apple.*`）的数据与系统共用，不提供清理。
    if bundle_id.to_lowercase().starts_with("com.apple.") {
        return scan;
    }
    let variants = name_variants(&app.name);
    let stem = path
        .file_stem()
        .map(|s| normalize(&s.to_string_lossy()))
        .unwrap_or_default();
    let home = home.trim_end_matches('/');
    let mut seen = std::collections::HashSet::new();

    for dir in LIBRARY_DIRS {
        let root = PathBuf::from(format!("{home}/Library/{dir}"));
        let Ok(rd) = fs::read_dir(&root) else {
            continue;
        };
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let by_id = !bundle_id.is_empty() && matches_bundle_id(&name, bundle_id);
            // 应用名只匹配"程序自己命名的数据目录"，且不用于偏好设置与 Cookie 这类固定以 ID 命名的位置。
            let by_name = !by_id && matches!(*dir, "Application Support" | "Caches" | "Logs") && {
                let n = normalize(
                    Path::new(&name)
                        .file_stem()
                        .map_or(&*name, |s| s.to_str().unwrap_or(&name)),
                );
                (n.chars().count() >= 3 && (variants.contains(&n) || n == stem))
                    || normalize(&name) == stem && stem.chars().count() >= 3
            };
            if !by_id && !by_name {
                continue;
            }
            let p = e.path();
            let Ok(meta) = fs::symlink_metadata(&p) else {
                continue;
            };
            if special_reason(&meta).is_some() {
                continue;
            }
            if policy.check_delete(&p.to_string_lossy()).is_err() {
                continue;
            }
            if !seen.insert(p.clone()) {
                continue;
            }
            let (size, files) = crate::plan::measure_path(&p)
                .map(|s| (s.size, s.files))
                .unwrap_or((0, 0));
            scan.items.push(Leftover {
                target: Target::Path {
                    path: p,
                    is_dir: meta.is_dir(),
                    size,
                    files,
                },
                confidence: if by_id {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                reason: if by_id {
                    Reason::BundleId
                } else {
                    Reason::NameMatch
                },
            });
        }
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    struct Sb(PathBuf);
    impl Sb {
        fn new() -> Self {
            let d = std::env::temp_dir().join(format!(
                "dc-macapps-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Sb(crate::safety::canonical_plain(&d).unwrap())
        }
        fn p(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
        fn write(&self, rel: &str, n: usize) {
            let p = self.p(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, vec![1u8; n]).unwrap();
        }
        fn home(&self) -> String {
            self.p("Users/alice").to_string_lossy().into_owned()
        }
        fn app(&self, rel: &str, name: &str, id: &str) {
            let plist = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleName</key><string>{name}</string>
<key>CFBundleIdentifier</key><string>{id}</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>"#
            );
            let p = self.p(&format!("{rel}/Contents/Info.plist"));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, plist).unwrap();
            self.write(&format!("{rel}/Contents/MacOS/bin"), 4096);
        }
    }
    impl Drop for Sb {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn policy(sb: &Sb) -> SafetyPolicy {
        // 沙盒在系统临时目录下（macOS 上是受保护的 /private/var）：用只保护家目录的基础策略。
        let home = sb.home();
        let mut base = SafetyPolicy::empty(crate::safety::native_style());
        for d in ["", "/Library", "/Documents"] {
            base.protect(&format!("{home}{d}")).unwrap();
        }
        leftover_policy_on(base, &home).unwrap()
    }

    #[test]
    fn enumerates_apps_with_name_version_and_bundle_id() {
        let sb = Sb::new();
        sb.app(
            "Applications/Slack.app",
            "Slack",
            "com.tinyspeck.slackmacgap",
        );
        sb.app("Applications/Utilities/Tool.app", "Tool", "com.x.tool");
        sb.app("Users/alice/Applications/Mine.app", "Mine", "com.me.mine");
        sb.write("Applications/NotAnApp/readme.txt", 5);
        fs::create_dir_all(sb.p("Applications/Broken.app")).unwrap();
        let roots = vec![sb.p("Applications"), sb.p("Users/alice/Applications")];
        let apps = enumerate_mac_apps(&roots);
        let names: Vec<_> = apps.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["Broken", "Mine", "Slack", "Tool"]);
        let slack = apps.iter().find(|a| a.name == "Slack").unwrap();
        assert_eq!(slack.version.as_deref(), Some("1.2.3"));
        assert!(
            matches!(&slack.source, AppSource::MacBundle { bundle_id, .. } if bundle_id == "com.tinyspeck.slackmacgap")
        );
        assert!(slack.size_kb.unwrap() >= 4);
    }

    #[test]
    fn leftovers_are_matched_by_bundle_id_first_and_name_second() {
        let sb = Sb::new();
        let home = sb.home();
        let lib = |p: &str| format!("Users/alice/Library/{p}");
        sb.write(&lib("Application Support/Slack/data.db"), 3000);
        sb.write(&lib("Caches/com.tinyspeck.slackmacgap/c.bin"), 2000);
        sb.write(&lib("Caches/com.tinyspeck.slackmacgap.ShipIt/u.bin"), 100);
        sb.write(&lib("Preferences/com.tinyspeck.slackmacgap.plist"), 50);
        sb.write(&lib("Containers/com.tinyspeck.slackmacgap/x"), 10);
        sb.write(
            &lib("Group Containers/ABCDE12345.com.tinyspeck.slackmacgap/y"),
            10,
        );
        sb.write(
            &lib("Saved Application State/com.tinyspeck.slackmacgap.savedState/z"),
            10,
        );
        sb.write(&lib("Logs/Slack/log.txt"), 10);
        // 不该碰的：别的应用、名字相近的、系统位置。
        sb.write(&lib("Application Support/SlackBot/x"), 10);
        sb.write(&lib("Caches/com.tinyspeck.slackmacgapX/x"), 10);
        sb.write(&lib("Preferences/com.other.app.plist"), 10);
        sb.write(&lib("Application Support/Apple/x"), 10);
        let app = InstalledApp {
            source: AppSource::MacBundle {
                path: sb.p("Applications/Slack.app"),
                bundle_id: "com.tinyspeck.slackmacgap".into(),
            },
            name: "Slack".into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            windows_installer: false,
        };
        let scan = scan_mac_leftovers(&app, &home, &policy(&sb), false);
        assert!(!scan.still_registered);
        let found: Vec<(String, Confidence, Reason)> = scan
            .items
            .iter()
            .map(|l| match &l.target {
                Target::Path { path, .. } => (
                    path.strip_prefix(sb.p("Users/alice/Library"))
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/"),
                    l.confidence,
                    l.reason,
                ),
                _ => panic!(),
            })
            .collect();
        let mut names: Vec<&str> = found.iter().map(|f| f.0.as_str()).collect();
        names.sort();
        assert_eq!(
            names,
            [
                "Application Support/Slack",
                "Caches/com.tinyspeck.slackmacgap",
                "Caches/com.tinyspeck.slackmacgap.ShipIt",
                "Containers/com.tinyspeck.slackmacgap",
                "Group Containers/ABCDE12345.com.tinyspeck.slackmacgap",
                "Logs/Slack",
                "Preferences/com.tinyspeck.slackmacgap.plist",
                "Saved Application State/com.tinyspeck.slackmacgap.savedState",
            ]
        );
        let by = |n: &str| found.iter().find(|f| f.0 == n).unwrap();
        assert_eq!(by("Application Support/Slack").1, Confidence::Medium);
        assert_eq!(by("Application Support/Slack").2, Reason::NameMatch);
        assert_eq!(
            by("Preferences/com.tinyspeck.slackmacgap.plist").1,
            Confidence::High
        );
        assert_eq!(
            by("Preferences/com.tinyspeck.slackmacgap.plist").2,
            Reason::BundleId
        );
    }

    fn app_at(path: PathBuf, name: &str, id: &str) -> InstalledApp {
        InstalledApp {
            source: AppSource::MacBundle {
                path,
                bundle_id: id.into(),
            },
            name: name.into(),
            version: None,
            publisher: None,
            install_location: None,
            install_date: None,
            size_kb: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            windows_installer: false,
        }
    }

    #[test]
    fn nothing_is_proposed_while_the_app_is_installed_unless_forced_and_never_for_apple_apps() {
        let sb = Sb::new();
        sb.app("Applications/Foo.app", "Foo", "com.foo.app");
        sb.write("Users/alice/Library/Caches/com.foo.app/x", 10);
        let app = app_at(sb.p("Applications/Foo.app"), "Foo", "com.foo.app");
        let p = policy(&sb);
        let s = scan_mac_leftovers(&app, &sb.home(), &p, false);
        assert!(s.still_registered && s.items.is_empty());
        let forced = scan_mac_leftovers(&app, &sb.home(), &p, true);
        assert_eq!(forced.items.len(), 1);

        sb.write("Users/alice/Library/Caches/com.apple.Notes/x", 10);
        let apple = app_at(sb.p("Applications/Notes.app"), "Notes", "com.apple.Notes");
        assert!(scan_mac_leftovers(&apple, &sb.home(), &p, false)
            .items
            .is_empty());
    }

    #[test]
    fn uninstall_moves_only_real_apps_inside_the_application_folders() {
        let sb = Sb::new();
        sb.app("Applications/Foo.app", "Foo", "com.foo.app");
        sb.app("Library/Evil.app", "Evil", "com.evil");
        let roots = vec![sb.p("Applications")];
        let moved = std::sync::Mutex::new(Vec::new());
        let remove = |p: &Path| {
            moved.lock().unwrap().push(p.to_path_buf());
            Ok(())
        };
        let ok = app_at(sb.p("Applications/Foo.app"), "Foo", "com.foo.app");
        uninstall_mac_bundle(&ok, &roots, &remove).unwrap();
        assert_eq!(*moved.lock().unwrap(), [sb.p("Applications/Foo.app")]);

        for bad in [
            sb.p("Library/Evil.app"),
            sb.p("Applications/Foo.app/Contents"),
            sb.p("Applications"),
            sb.p("Applications/../Library/Evil.app"),
        ] {
            let a = app_at(bad.clone(), "x", "x");
            assert!(
                matches!(
                    uninstall_mac_bundle(&a, &roots, &remove),
                    Err(MacUninstallError::Refused(_) | MacUninstallError::Failed(_))
                ),
                "{bad:?}"
            );
        }
        assert_eq!(moved.lock().unwrap().len(), 1, "被拒绝的不会到达移动函数");

        let win = InstalledApp {
            source: AppSource::Appx {
                package_full_name: "x".into(),
            },
            ..ok.clone()
        };
        assert!(uninstall_mac_bundle(&win, &roots, &remove).is_err());
    }

    #[test]
    fn leftover_policy_only_opens_the_app_data_folders() {
        let sb = Sb::new();
        let p = policy(&sb);
        let lib = |x: &str| format!("{}/Library/{x}", sb.home());
        assert!(p.check_delete(&lib("Caches/com.foo/x")).is_ok());
        assert!(p.check_delete(&lib("Preferences/com.foo.plist")).is_ok());
        assert!(p.check_delete(&lib("Caches")).is_err());
        assert!(p.check_delete(&lib("Keychains/login.keychain-db")).is_err());
        assert!(p.check_delete(&lib("Application Support/Apple/x")).is_err());
        assert!(p
            .check_delete(&lib("Application Support/MobileSync/Backup"))
            .is_err());
        assert!(p
            .check_delete(&format!("{}/Documents/a", sb.home()))
            .is_err());
    }

    #[test]
    fn bundle_id_matching_is_exact_not_substring() {
        assert!(matches_bundle_id("com.foo.app", "com.foo.app"));
        assert!(matches_bundle_id("com.foo.app.plist", "com.foo.app"));
        assert!(matches_bundle_id("COM.FOO.APP", "com.foo.app"));
        assert!(matches_bundle_id("group.com.foo.app", "com.foo.app"));
        assert!(matches_bundle_id(
            "TEAM123.com.foo.app.helper",
            "com.foo.app"
        ));
        assert!(!matches_bundle_id("com.foo.apple", "com.foo.app"));
        assert!(!matches_bundle_id("xcom.foo.app", "com.foo.app"));
        assert!(!matches_bundle_id("com.foo", "com.foo.app"));
    }
}
