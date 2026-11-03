//! 内置 Windows 规则集（仅包含"纯路径删除"类规则）。
//!
//! 需要调用系统工具的项（清空回收站、`Windows.old`、`DISM`、休眠文件、
//! 卷影副本等）不在此处，计划在 M5 以专用动作实现。
//! 路径模板统一使用 `/` 分隔；Windows API 同样接受。

use crate::rules::{Disposal, Risk, Rule, Target, TargetKind};

fn contents(path: &str) -> Target {
    Target {
        path: path.into(),
        kind: TargetKind::Contents,
        name_globs: Vec::new(),
        min_age_days: 0,
    }
}

fn aged(path: &str, days: u32) -> Target {
    Target {
        min_age_days: days,
        ..contents(path)
    }
}

fn files(path: &str, globs: &[&str], days: u32) -> Target {
    Target {
        name_globs: globs.iter().map(|s| s.to_string()).collect(),
        min_age_days: days,
        ..contents(path)
    }
}

fn file(path: &str) -> Target {
    Target {
        kind: TargetKind::File,
        ..contents(path)
    }
}

fn rule(id: &str, risk: Risk, default_selected: bool, targets: Vec<Target>) -> Rule {
    Rule {
        id: id.into(),
        risk,
        default_selected,
        // 内置规则清理的都是可再生数据，直接删除才能真正释放空间。
        disposal: Disposal::Permanent,
        targets,
        services: Vec::new(),
    }
}

fn with_services(mut r: Rule, services: &[&str]) -> Rule {
    r.services = services.iter().map(|s| s.to_string()).collect();
    r
}

pub fn windows_rules() -> Vec<Rule> {
    use Risk::{Low, Medium};
    vec![
        rule(
            "user_temp",
            Low,
            true,
            // 保留最近一天内修改过的，避免动到正在使用的临时文件。
            vec![aged("%TEMP%", 1), aged("%LOCALAPPDATA%/Temp", 1)],
        ),
        rule("system_temp", Low, true, vec![aged("%SystemRoot%/Temp", 1)]),
        rule(
            "thumbnail_cache",
            Low,
            true,
            vec![files(
                "%LOCALAPPDATA%/Microsoft/Windows/Explorer",
                &["thumbcache_*.db", "iconcache_*.db"],
                0,
            )],
        ),
        rule(
            "crash_dumps",
            Low,
            true,
            vec![
                contents("%LOCALAPPDATA%/CrashDumps"),
                contents("%SystemRoot%/Minidump"),
                file("%SystemRoot%/MEMORY.DMP"),
                contents("%ProgramData%/Microsoft/Windows/WER/ReportArchive"),
                contents("%ProgramData%/Microsoft/Windows/WER/ReportQueue"),
            ],
        ),
        rule(
            "delivery_optimization",
            Low,
            true,
            vec![contents(
                "%SystemRoot%/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache",
            )],
        ),
        rule(
            "old_logs",
            Low,
            true,
            vec![files("%SystemRoot%/Logs/CBS", &["*.log", "*.cab"], 30)],
        ),
        rule(
            "browser_cache",
            Low,
            true,
            vec![
                // Chromium 系：Default 与 Profile N。仅缓存，不含 Cookie/密码/历史。
                contents("%LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Cache/Cache_Data"),
                contents("%LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Code Cache"),
                contents("%LOCALAPPDATA%/Microsoft/Edge/User Data/Profile */Cache/Cache_Data"),
                contents("%LOCALAPPDATA%/Google/Chrome/User Data/Default/Cache/Cache_Data"),
                contents("%LOCALAPPDATA%/Google/Chrome/User Data/Default/Code Cache"),
                contents("%LOCALAPPDATA%/Google/Chrome/User Data/Profile */Cache/Cache_Data"),
                contents("%LOCALAPPDATA%/Mozilla/Firefox/Profiles/*/cache2"),
            ],
        ),
        // 更新下载缓存：清理前先停止 Windows Update 与后台传输服务，结束后恢复。
        with_services(
            rule(
                "windows_update_cache",
                Medium,
                false,
                vec![contents("%SystemRoot%/SoftwareDistribution/Download")],
            ),
            &["wuauserv", "bits"],
        ),
        // 开发者缓存：可再生，但会增加下次构建/安装时间，默认不勾选。
        rule(
            "dev_caches",
            Medium,
            false,
            vec![
                contents("%LOCALAPPDATA%/npm-cache"),
                contents("%LOCALAPPDATA%/pip/Cache"),
                contents("%LOCALAPPDATA%/Yarn/Cache"),
                contents("%LOCALAPPDATA%/NuGet/v3-cache"),
                contents("%USERPROFILE%/.cargo/registry/cache"),
                contents("%USERPROFILE%/.cargo/registry/src"),
                contents("%USERPROFILE%/.gradle/caches"),
            ],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_unique_and_defaults_are_low_risk() {
        let rules = windows_rules();
        let ids: HashSet<_> = rules.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids.len(), rules.len());
        for r in &rules {
            assert!(!r.targets.is_empty());
            if r.default_selected {
                assert_eq!(
                    r.risk,
                    Risk::Low,
                    "{} is default-selected but not low risk",
                    r.id
                );
            }
        }
    }

    #[test]
    fn update_cache_rule_stops_update_services() {
        let rules = windows_rules();
        let r = rules
            .iter()
            .find(|r| r.id == "windows_update_cache")
            .unwrap();
        assert_eq!(r.services, ["wuauserv", "bits"]);
        assert!(rules
            .iter()
            .filter(|r| r.id != "windows_update_cache")
            .all(|r| r.services.is_empty()));
    }

    #[test]
    fn templates_are_well_formed() {
        for r in windows_rules() {
            for t in &r.targets {
                assert!(!t.path.contains('\\'), "{}: use '/' in templates", t.path);
                assert!(
                    t.path.starts_with('%'),
                    "{}: must start with an env var",
                    t.path
                );
            }
        }
    }
}
