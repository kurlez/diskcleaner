//! 识别云端硬盘与云同步目录，让它们不参与磁盘分析。
//!
//! 为什么要排除：云盘里的内容大多不占本机磁盘空间（"仅在线"的占位文件），
//! 或者是同步副本，把它们混进"谁占了我的磁盘"只会误导；遍历虚拟盘符还很慢，甚至会触发网络访问。
//!
//! 识别依据（宁可少排除，也不要把普通目录误当成云盘）：
//! * **目录名**：`Google Drive`、`OneDrive*`、`Dropbox*`、`iCloudDrive`、`SynologyDrive*` 等已知的同步目录名；
//! * **环境变量**：`OneDrive`、`OneDriveConsumer`、`OneDriveCommercial` 给出的精确路径；
//! * **磁盘卷标**：Google Drive 桌面版会挂载一个叫 `Google Drive` 的虚拟盘符；网络驱动器一律视为云/远程；
//! * **用户自定义**：在设置里手动添加的要跳过的路径。

use std::path::{Path, PathBuf};

use crate::rules::Env;

/// 已知的云同步目录名：(服务名, 完全匹配的名字, 前缀匹配的名字)，名字均为小写。
const PROVIDERS: &[(&str, &[&str], &[&str])] = &[
    (
        "Google Drive",
        &["googledrive", "google drive"],
        &["google drive", "googledrive"],
    ),
    ("OneDrive", &[], &["onedrive"]),
    ("Dropbox", &[], &["dropbox"]),
    (
        "iCloud Drive",
        &["iclouddrive", "icloud drive"],
        &["icloud"],
    ),
    ("Box", &["box sync"], &["box sync"]),
    ("MEGA", &["megasync"], &["megasync"]),
    ("pCloud", &[], &["pcloud"]),
    (
        "Yandex Disk",
        &["yandexdisk", "yandex.disk"],
        &["yandexdisk"],
    ),
    ("Synology Drive", &[], &["synologydrive", "synology drive"]),
    (
        "Baidu Netdisk",
        &["baidunetdisk", "百度网盘", "baidusyncdisk", "百度同步盘"],
        &[],
    ),
    ("Aliyun Drive", &["aliyundrive", "阿里云盘"], &[]),
    ("Nutstore", &["nutstore", "坚果云", "nutstore files"], &[]),
];

/// 目录名是不是已知的云同步目录。返回服务名。
pub fn provider_of_name(name: &str) -> Option<&'static str> {
    let n = name.trim().to_lowercase();
    PROVIDERS
        .iter()
        .find(|(_, exact, prefix)| {
            exact.contains(&n.as_str()) || prefix.iter().any(|p| n.starts_with(p))
        })
        .map(|(p, _, _)| *p)
}

/// 磁盘卷标是不是云端虚拟盘（如 Google Drive 桌面版挂载的盘符）。
pub fn provider_of_label(label: &str) -> Option<&'static str> {
    let l = label.trim().to_lowercase();
    if l.is_empty() {
        return None;
    }
    PROVIDERS
        .iter()
        .find(|(_, exact, prefix)| {
            exact.contains(&l.as_str()) || prefix.iter().any(|p| l.contains(p))
        })
        .map(|(p, _, _)| *p)
}

/// 规范化路径用于比较：按分量用 `\` 连接并转小写（忽略大小写、分隔符种类、首尾多余的分隔符）。
fn norm(p: &Path) -> String {
    comps(p).join("\\").to_lowercase()
}

/// 路径所在的磁盘是不是云端虚拟盘或网络驱动器。返回服务名（网络驱动器返回 `Network`）。
pub fn drive_provider(volumes: &dyn crate::migrate::Volumes, path: &Path) -> Option<String> {
    let v = volumes.volume_of(path)?;
    if v.remote {
        return Some("Network".into());
    }
    provider_of_label(&v.label).map(str::to_string)
}

/// 判断目录该不该跳过的规则。
#[derive(Debug, Clone, Default)]
pub struct CloudRules {
    /// 为真时不排除云目录（只剩用户自定义的跳过路径）。
    analyze_cloud: bool,
    /// 用户在设置里添加的、要跳过的路径（规范化后）。
    skip_paths: Vec<String>,
    /// 由环境变量得到的精确云同步根目录。
    cloud_roots: Vec<(String, &'static str)>,
}

/// 被排除的目录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excluded {
    pub path: PathBuf,
    /// 服务名（如 `OneDrive`），或 `custom`（用户自定义）。
    pub reason: String,
    /// 它在被排除之前的大小；遍历时未统计则为 0。
    pub size: u64,
}

impl CloudRules {
    /// `analyze_cloud` 为假（默认）时排除云同步目录；`skip_paths` 总是被跳过。
    pub fn new(analyze_cloud: bool, skip_paths: &[String], env: &Env) -> Self {
        let cloud_roots = ["OneDrive", "OneDriveConsumer", "OneDriveCommercial"]
            .iter()
            .filter_map(|k| env.get(k))
            .map(|p| (norm(Path::new(p)), "OneDrive"))
            .collect();
        Self {
            analyze_cloud,
            skip_paths: skip_paths
                .iter()
                .map(|s| norm(Path::new(s)))
                .filter(|s| !s.is_empty())
                .collect(),
            cloud_roots,
        }
    }

    /// 什么都不排除。
    pub fn none() -> Self {
        Self {
            analyze_cloud: true,
            ..Self::default()
        }
    }

    /// 这个目录本身是否应当跳过。返回原因（服务名或 `custom`）。
    pub fn excluded_dir(&self, path: &Path) -> Option<String> {
        self.excluded_comps(&comps(path))
    }

    /// 该路径本身或它的任一祖先目录是否在被排除的位置里。
    pub fn location_excluded(&self, path: &Path) -> Option<String> {
        let c = comps(path);
        (1..=c.len())
            .rev()
            .find_map(|n| self.excluded_comps(&c[..n]))
    }

    fn excluded_comps(&self, c: &[String]) -> Option<String> {
        let n = c.join("\\").to_lowercase();
        if self.skip_paths.contains(&n) {
            return Some("custom".into());
        }
        if self.analyze_cloud {
            return None;
        }
        if let Some((_, p)) = self.cloud_roots.iter().find(|(r, _)| *r == n) {
            return Some((*p).to_string());
        }
        c.last()
            .and_then(|name| provider_of_name(name))
            .map(str::to_string)
    }
}

/// 把路径拆成分量，同时兼容 `\` 与 `/`（与当前平台无关，测试和实际行为一致）。
fn comps(p: &Path) -> Vec<String> {
    p.to_string_lossy()
        .replace('/', "\\")
        .split('\\')
        .filter(|c| !c.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(analyze: bool, skip: &[&str], env: &[(&str, &str)]) -> CloudRules {
        CloudRules::new(
            analyze,
            &skip.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            &Env::from_pairs(env.iter().copied()),
        )
    }

    #[test]
    fn recognizes_known_sync_folder_names() {
        for (name, provider) in [
            ("Google Drive", "Google Drive"),
            ("GoogleDrive", "Google Drive"),
            ("OneDrive", "OneDrive"),
            ("OneDrive - Contoso Ltd", "OneDrive"),
            ("OneDrive - 某公司", "OneDrive"),
            ("Dropbox", "Dropbox"),
            ("Dropbox (Personal)", "Dropbox"),
            ("iCloudDrive", "iCloud Drive"),
            ("SynologyDrive", "Synology Drive"),
            ("SynologyDrive-Team", "Synology Drive"),
            ("Box Sync", "Box"),
            ("MEGAsync", "MEGA"),
            ("pCloudDrive", "pCloud"),
            ("百度网盘", "Baidu Netdisk"),
            ("坚果云", "Nutstore"),
            ("阿里云盘", "Aliyun Drive"),
            ("onedrive", "OneDrive"),
        ] {
            assert_eq!(provider_of_name(name), Some(provider), "{name}");
        }
    }

    #[test]
    fn does_not_mistake_ordinary_folders_for_cloud_storage() {
        for name in [
            "Documents",
            "Box",
            "Boxes",
            "Mega Games",
            "Drive",
            "My Drive Backup Notes",
            "Projects",
            "Users",
            "Windows",
            "OnePlus",
            "",
            "Cloud",
        ] {
            assert_eq!(provider_of_name(name), None, "{name}");
        }
    }

    #[test]
    fn posix_style_paths_compare_the_same_way_as_windows_ones() {
        let r = rules(true, &["/data/games"], &[]);
        assert_eq!(
            r.excluded_dir(Path::new("/data/games")).as_deref(),
            Some("custom")
        );
        assert_eq!(
            r.excluded_dir(Path::new("/data/games/")).as_deref(),
            Some("custom")
        );
        assert_eq!(r.excluded_dir(Path::new("/data/games2")), None);
    }

    #[test]
    fn recognizes_virtual_cloud_drives_by_label() {
        assert_eq!(provider_of_label("Google Drive"), Some("Google Drive"));
        assert_eq!(provider_of_label("GoogleDriveFS"), Some("Google Drive"));
        assert_eq!(provider_of_label("OneDrive"), Some("OneDrive"));
        assert_eq!(provider_of_label("Data"), None);
        assert_eq!(provider_of_label("系统"), None);
        assert_eq!(provider_of_label(""), None);
        assert_eq!(provider_of_label("   "), None);
    }

    #[test]
    fn virtual_cloud_drives_and_network_drives_are_detected_from_volume_info() {
        use crate::migrate::{VolumeInfo, Volumes};
        struct V(&'static str, bool);
        impl Volumes for V {
            fn volume_of(&self, _: &Path) -> Option<VolumeInfo> {
                Some(VolumeInfo {
                    mount: "G:\\".into(),
                    label: self.0.into(),
                    fs: "NTFS".into(),
                    free: 1,
                    total: 2,
                    removable: false,
                    remote: self.1,
                })
            }
        }
        let p = Path::new(r"G:\My Drive\x");
        assert_eq!(
            drive_provider(&V("Google Drive", false), p).as_deref(),
            Some("Google Drive")
        );
        assert_eq!(
            drive_provider(&V("Data", true), p).as_deref(),
            Some("Network")
        );
        assert_eq!(drive_provider(&V("Data", false), p), None);
        struct None_;
        impl Volumes for None_ {
            fn volume_of(&self, _: &Path) -> Option<VolumeInfo> {
                None
            }
        }
        assert_eq!(drive_provider(&None_, p), None);
    }

    #[test]
    fn cloud_folders_are_excluded_by_default_and_included_when_asked() {
        let r = rules(false, &[], &[]);
        assert_eq!(
            r.excluded_dir(Path::new(r"D:\Google Drive")).as_deref(),
            Some("Google Drive")
        );
        assert_eq!(
            r.excluded_dir(Path::new(r"C:\Users\a\Dropbox")).as_deref(),
            Some("Dropbox")
        );
        assert_eq!(r.excluded_dir(Path::new(r"C:\Users\a\Documents")), None);
        let on = rules(true, &[], &[]);
        assert_eq!(on.excluded_dir(Path::new(r"D:\Google Drive")), None);
        assert_eq!(
            CloudRules::none().excluded_dir(Path::new(r"D:\OneDrive")),
            None
        );
    }

    #[test]
    fn custom_skip_paths_always_apply_and_ignore_case_and_separators() {
        for analyze in [false, true] {
            let r = rules(analyze, &[r"D:\Games\Steam Library\"], &[]);
            assert_eq!(
                r.excluded_dir(Path::new("d:/games/steam library"))
                    .as_deref(),
                Some("custom")
            );
            assert_eq!(r.excluded_dir(Path::new(r"D:\Games")), None);
            assert_eq!(
                r.excluded_dir(Path::new(r"D:\Games\Steam Library2")),
                None,
                "不能按前缀误伤"
            );
        }
    }

    #[test]
    fn onedrive_environment_variables_give_exact_roots() {
        let r = rules(
            false,
            &[],
            &[
                ("OneDrive", r"C:\Users\a\我的云盘"),
                ("OneDriveCommercial", r"C:\Users\a\Work Files"),
            ],
        );
        assert_eq!(
            r.excluded_dir(Path::new(r"C:\Users\a\我的云盘")).as_deref(),
            Some("OneDrive")
        );
        assert_eq!(
            r.excluded_dir(Path::new(r"c:/users/a/work files/"))
                .as_deref(),
            Some("OneDrive")
        );
        assert_eq!(
            r.excluded_dir(Path::new(r"C:\Users\a\我的云盘\子目录")),
            None,
            "只排除根，子目录由遍历时的父级判断"
        );
    }

    #[test]
    fn a_location_inside_a_cloud_folder_is_excluded() {
        let r = rules(false, &[], &[]);
        assert_eq!(
            r.location_excluded(Path::new(r"D:\Google Drive\Projects\x"))
                .as_deref(),
            Some("Google Drive")
        );
        assert_eq!(
            r.location_excluded(Path::new(r"D:\Google Drive"))
                .as_deref(),
            Some("Google Drive")
        );
        assert_eq!(r.location_excluded(Path::new(r"D:\Projects\x")), None);
        assert_eq!(
            CloudRules::none().location_excluded(Path::new(r"D:\Google Drive\x")),
            None
        );
    }
}
