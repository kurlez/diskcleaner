//! 与 Tauri 无关的应用服务层：持有扫描结果和清理计划，向界面提供可序列化的 DTO。
//!
//! 安全要点：界面**只能**提交规则 ID；真正要删除的路径始终来自后端保存的计划，
//! 前端无法注入任意路径。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use diskclean_core::cleaner::{execute, ExecOptions, Status};
use diskclean_core::plan::{build_plan, Plan, PlanSkipReason};
use diskclean_core::rules::{Disposal, Env, Risk, Rule};
use diskclean_core::safety::SafetyPolicy;
use diskclean_core::scanner::{self, Node, Progress, ScanOutcome};
use serde::Serialize;

const MAX_CHILDREN: usize = 1000;
const TOP_FILES: usize = 50;
const MAX_PLAN_ITEMS: usize = 300;
const MAX_PROBLEMS: usize = 200;

/// 返回给界面的错误：`code` 供界面翻译，`detail` 是附带的原始信息。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub detail: Option<String>,
}

impl ApiError {
    pub fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }
    pub fn with(code: &'static str, detail: impl ToString) -> Self {
        Self {
            code,
            detail: Some(detail.to_string()),
        }
    }
}

type Result<T> = std::result::Result<T, ApiError>;

/// 去掉 `\\?\` 前缀，仅用于展示。
pub fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
}

// ---------- DTO ----------

#[derive(Debug, Serialize)]
pub struct DriveDto {
    pub mount: String,
    pub name: String,
    pub fs: String,
    pub total: u64,
    pub free: u64,
}

#[derive(Debug, Serialize)]
pub struct FileDto {
    pub path: String,
    pub size: u64,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    /// `mft`（NTFS 快速扫描，大小为占用空间）或 `walk`（逐目录遍历，大小为逻辑大小）。
    pub method: &'static str,
    /// 想用快速扫描却回退到遍历时的原因代码（`access_denied`、`not_ntfs` 等）。
    pub fallback: Option<&'static str>,
    pub root: String,
    pub total_size: u64,
    pub file_count: u64,
    pub skipped: usize,
    pub cancelled: bool,
    pub top_files: Vec<FileDto>,
}

#[derive(Debug, Serialize)]
pub struct ChildDto {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub file_count: u64,
}

#[derive(Debug, Serialize)]
pub struct ChildrenDto {
    pub items: Vec<ChildDto>,
    /// 因数量上限而未返回的子项个数。
    pub hidden: usize,
}

#[derive(Debug, Serialize)]
pub struct RuleDto {
    pub id: String,
    pub risk: Risk,
    pub default_selected: bool,
    pub disposal: Disposal,
}

#[derive(Debug, Serialize)]
pub struct RuleTotal {
    pub rule_id: String,
    pub size: u64,
    pub files: u64,
}

#[derive(Debug, Serialize)]
pub struct SkipCount {
    pub reason: &'static str,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct PlanItemDto {
    pub rule_id: String,
    pub path: String,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Serialize)]
pub struct PlanSummary {
    pub by_rule: Vec<RuleTotal>,
    pub total_size: u64,
    pub total_files: u64,
    pub item_count: usize,
    pub skipped: Vec<SkipCount>,
    /// 按大小降序的前若干项，仅供预览。
    pub items: Vec<PlanItemDto>,
    pub cancelled: bool,
}

#[derive(Debug, Serialize)]
pub struct Problem {
    pub rule_id: String,
    pub path: String,
    /// `failed` 或 `refused`。
    pub status: &'static str,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct ReportDto {
    pub dry_run: bool,
    pub freed_bytes: u64,
    pub recycled_bytes: u64,
    pub deleted: usize,
    pub recycled: usize,
    pub would_delete: usize,
    pub failed: usize,
    pub refused: usize,
    pub cancelled: bool,
    pub problems: Vec<Problem>,
    pub journal_path: String,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct ProgressDto {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub struct CleanProgressDto {
    pub done: usize,
    pub total: usize,
}

#[derive(Clone, Copy)]
pub struct ExecRequest {
    pub dry_run: bool,
    pub recycle: bool,
}

// ---------- Service ----------

pub type PolicyFactory = dyn Fn(&[String]) -> Result<SafetyPolicy> + Send + Sync;

/// 快速扫描器：成功返回目录树，失败返回 (原因代码, 详情) 让服务层回退到遍历。
pub type FastScanFn = dyn Fn(
        &Path,
        &AtomicBool,
        &mut dyn FnMut(&Progress),
    ) -> std::result::Result<ScanOutcome, (&'static str, String)>
    + Send
    + Sync;

struct ScanState {
    root_path: PathBuf,
    root: Node,
}

pub struct Service {
    rules: Vec<Rule>,
    env: Env,
    policy_factory: Box<PolicyFactory>,
    fast_scan: Option<Box<FastScanFn>>,
    scan: Mutex<Option<ScanState>>,
    plan: Mutex<Option<Plan>>,
    scan_cancel: Arc<AtomicBool>,
    clean_cancel: Arc<AtomicBool>,
}

impl Service {
    pub fn new(
        rules: Vec<Rule>,
        env: Env,
        policy_factory: Box<PolicyFactory>,
        fast_scan: Option<Box<FastScanFn>>,
    ) -> Self {
        Self {
            rules,
            env,
            policy_factory,
            fast_scan,
            scan: Mutex::new(None),
            plan: Mutex::new(None),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            clean_cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn drives(&self) -> Vec<DriveDto> {
        let disks = sysinfo::Disks::new_with_refreshed_list();
        let mut v: Vec<DriveDto> = disks
            .list()
            .iter()
            .filter(|d| d.total_space() > 0)
            .map(|d| DriveDto {
                mount: display_path(d.mount_point()),
                name: d.name().to_string_lossy().into_owned(),
                fs: d.file_system().to_string_lossy().into_owned(),
                total: d.total_space(),
                free: d.available_space(),
            })
            .collect();
        v.sort_by(|a, b| a.mount.cmp(&b.mount));
        v
    }

    // ----- 扫描 -----

    pub fn scan(
        &self,
        path: &str,
        on_progress: &mut dyn FnMut(ProgressDto),
    ) -> Result<ScanSummary> {
        let root_path = PathBuf::from(path);
        if path.trim().is_empty() || !root_path.is_dir() {
            return Err(ApiError::with("invalid_path", path));
        }
        self.scan_cancel.store(false, Ordering::Relaxed);

        let mut method = "walk";
        let mut fallback = None;
        let mut fast = None;
        if let Some(f) = &self.fast_scan {
            match f(&root_path, &self.scan_cancel, &mut |p: &Progress| {
                on_progress(ProgressDto {
                    files: p.files,
                    dirs: p.dirs,
                    bytes: p.bytes,
                });
            }) {
                Ok(out) => {
                    method = "mft";
                    fast = Some(out);
                }
                Err((code, _detail)) => fallback = Some(code),
            }
        }
        let out = match fast {
            Some(out) => out,
            None => scanner::scan(&root_path, &self.scan_cancel, &mut |p: &Progress| {
                on_progress(ProgressDto {
                    files: p.files,
                    dirs: p.dirs,
                    bytes: p.bytes,
                });
            })
            .map_err(|e| ApiError::with("scan_failed", e))?,
        };

        let top_files = scanner::top_files(&root_path, &out.root, TOP_FILES)
            .into_iter()
            .map(|(p, size)| FileDto {
                path: display_path(&p),
                size,
            })
            .collect();
        let summary = ScanSummary {
            method,
            fallback,
            root: display_path(&root_path),
            total_size: out.root.size,
            file_count: out.root.file_count,
            skipped: out.skipped.len(),
            cancelled: out.cancelled,
            top_files,
        };
        *self.scan.lock().unwrap() = Some(ScanState {
            root_path,
            root: out.root,
        });
        Ok(summary)
    }

    pub fn cancel_scan(&self) {
        self.scan_cancel.store(true, Ordering::Relaxed);
    }

    /// `parts` 是从扫描根开始的目录名序列；空序列表示根本身。
    pub fn children(&self, parts: &[String]) -> Result<ChildrenDto> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut node = &state.root;
        for part in parts {
            node = node
                .children
                .iter()
                .find(|c| c.is_dir && &c.name == part)
                .ok_or_else(|| ApiError::with("invalid_path", part))?;
        }
        let items = node
            .children
            .iter()
            .take(MAX_CHILDREN)
            .map(|c| ChildDto {
                name: c.name.clone(),
                size: c.size,
                is_dir: c.is_dir,
                file_count: c.file_count,
            })
            .collect();
        Ok(ChildrenDto {
            items,
            hidden: node.children.len().saturating_sub(MAX_CHILDREN),
        })
    }

    /// 把"根 + 目录名序列"还原成真实路径，供"在资源管理器中显示"使用。
    /// 只接受扫描结果中确实存在的路径。
    pub fn resolve_in_scan(&self, parts: &[String]) -> Result<PathBuf> {
        let guard = self.scan.lock().unwrap();
        let state = guard.as_ref().ok_or(ApiError::new("no_scan"))?;
        let mut node = &state.root;
        let mut path = state.root_path.clone();
        for part in parts {
            node = node
                .children
                .iter()
                .find(|c| &c.name == part)
                .ok_or_else(|| ApiError::with("invalid_path", part))?;
            path.push(part);
        }
        Ok(path)
    }

    // ----- 规则 / 计划 / 执行 -----

    pub fn rules(&self) -> Vec<RuleDto> {
        self.rules
            .iter()
            .map(|r| RuleDto {
                id: r.id.clone(),
                risk: r.risk,
                default_selected: r.default_selected,
                disposal: r.disposal,
            })
            .collect()
    }

    pub fn validate_exclusion(&self, path: &str) -> Result<()> {
        if path.trim().is_empty() {
            return Err(ApiError::with("invalid_exclusion", path));
        }
        (self.policy_factory)(&[path.to_string()]).map(|_| ())
    }

    pub fn build_plan(&self, rule_ids: &[String], exclusions: &[String]) -> Result<PlanSummary> {
        for id in rule_ids {
            if !self.rules.iter().any(|r| &r.id == id) {
                return Err(ApiError::with("unknown_rule", id));
            }
        }
        let policy = (self.policy_factory)(exclusions)?;
        let ids: Vec<&str> = rule_ids.iter().map(String::as_str).collect();
        let cancel = AtomicBool::new(false);
        let plan = build_plan(
            &self.rules,
            &ids,
            &self.env,
            &policy,
            SystemTime::now(),
            &cancel,
        );

        let mut items: Vec<_> = plan.items.iter().collect();
        items.sort_by_key(|c| std::cmp::Reverse(c.size));
        let summary = PlanSummary {
            by_rule: plan
                .by_rule()
                .into_iter()
                .map(|(rule_id, size, files)| RuleTotal {
                    rule_id,
                    size,
                    files,
                })
                .collect(),
            total_size: plan.total_size(),
            total_files: plan.total_files(),
            item_count: plan.items.len(),
            skipped: skip_counts(&plan),
            items: items
                .into_iter()
                .take(MAX_PLAN_ITEMS)
                .map(|c| PlanItemDto {
                    rule_id: c.rule_id.clone(),
                    path: display_path(&c.path),
                    size: c.size,
                    is_dir: c.is_dir,
                })
                .collect(),
            cancelled: plan.cancelled,
        };
        *self.plan.lock().unwrap() = Some(plan);
        Ok(summary)
    }

    pub fn discard_plan(&self) {
        *self.plan.lock().unwrap() = None;
    }

    pub fn cancel_clean(&self) {
        self.clean_cancel.store(true, Ordering::Relaxed);
    }

    /// 执行当前保存的计划。计划一经取出即作废（无论成败），要再清理必须重新分析。
    pub fn execute(
        &self,
        req: ExecRequest,
        journal_path: &Path,
        on_progress: &mut dyn FnMut(CleanProgressDto),
    ) -> Result<ReportDto> {
        let plan = self
            .plan
            .lock()
            .unwrap()
            .take()
            .ok_or(ApiError::new("no_plan"))?;
        self.clean_cancel.store(false, Ordering::Relaxed);

        if let Some(dir) = journal_path.parent() {
            fs::create_dir_all(dir).map_err(|e| ApiError::with("journal_failed", e))?;
        }
        let mut journal = OpenOptions::new()
            .create(true)
            .append(true)
            .open(journal_path)
            .map_err(|e| ApiError::with("journal_failed", e))?;

        let opts = ExecOptions {
            dry_run: req.dry_run,
            override_disposal: req.recycle.then_some(Disposal::Recycle),
        };
        let report = execute(
            &plan,
            opts,
            Some(&mut journal as &mut dyn Write),
            &self.clean_cancel,
            &mut |done, total| on_progress(CleanProgressDto { done, total }),
        );

        let mut problems = Vec::new();
        for e in &report.entries {
            let (status, detail) = match &e.status {
                Status::Failed(d) => ("failed", d.clone()),
                Status::Refused(d) => ("refused", d.clone()),
                _ => continue,
            };
            if problems.len() < MAX_PROBLEMS {
                problems.push(Problem {
                    rule_id: e.rule_id.clone(),
                    path: display_path(Path::new(&e.path)),
                    status,
                    detail,
                });
            }
        }
        Ok(ReportDto {
            dry_run: req.dry_run,
            freed_bytes: report.freed_bytes,
            recycled_bytes: report.recycled_bytes,
            deleted: report.count(|s| matches!(s, Status::Deleted)),
            recycled: report.count(|s| matches!(s, Status::Recycled)),
            would_delete: report.count(|s| matches!(s, Status::WouldDelete)),
            failed: report.failed(),
            refused: report.refused(),
            cancelled: report.cancelled,
            problems,
            journal_path: display_path(journal_path),
        })
    }
}

fn skip_counts(plan: &Plan) -> Vec<SkipCount> {
    let mut counts: Vec<SkipCount> = Vec::new();
    for s in &plan.skipped {
        let reason = match s.reason {
            PlanSkipReason::Denied(_) => "denied",
            PlanSkipReason::ReparsePoint => "reparse_point",
            PlanSkipReason::CloudPlaceholder => "cloud_placeholder",
            PlanSkipReason::TooNew => "too_new",
            PlanSkipReason::ProtectedInside(_) => "protected_inside",
            PlanSkipReason::NonUtf8Path => "non_utf8",
            PlanSkipReason::Io(_) => "io",
        };
        match counts.iter_mut().find(|c| c.reason == reason) {
            Some(c) => c.count += 1,
            None => counts.push(SkipCount { reason, count: 1 }),
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskclean_core::rules::{Target, TargetKind};
    use diskclean_core::safety::PathStyle;
    use std::sync::atomic::AtomicU64;

    static N: AtomicU64 = AtomicU64::new(0);

    fn sandbox() -> PathBuf {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("dc-svc-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::canonicalize(d).unwrap()
    }

    fn service(base: &Path) -> Service {
        service_fast(base, None)
    }

    fn service_fast(base: &Path, fast: Option<Box<FastScanFn>>) -> Service {
        let rule = Rule {
            id: "r".into(),
            risk: Risk::Low,
            default_selected: true,
            disposal: Disposal::Permanent,
            targets: vec![Target {
                path: "%BASE%/cache".into(),
                kind: TargetKind::Contents,
                name_globs: vec![],
                min_age_days: 0,
            }],
        };
        let base_s = base.to_string_lossy().into_owned();
        let factory: Box<PolicyFactory> = Box::new(move |excl: &[String]| {
            let mut p = SafetyPolicy::empty(PathStyle::Posix);
            p.protect(&base_s)
                .map_err(|e| ApiError::with("policy", e))?;
            for x in excl {
                p.exclude(x)
                    .map_err(|e| ApiError::with("invalid_exclusion", format!("{x}: {e}")))?;
            }
            Ok(p)
        });
        Service::new(
            vec![rule],
            Env::from_pairs([("BASE", base.to_string_lossy())]),
            factory,
            fast,
        )
    }

    fn write(p: &Path, n: usize) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, vec![0u8; n]).unwrap();
    }

    #[test]
    fn scan_then_browse_children() {
        let d = sandbox();
        write(&d.join("a/big.bin"), 500);
        write(&d.join("a/small.bin"), 5);
        write(&d.join("b.bin"), 50);
        let svc = service(&d);
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.total_size, 555);
        assert_eq!(s.top_files[0].size, 500);

        let root = svc.children(&[]).unwrap();
        assert_eq!(root.items[0].name, "a");
        assert!(root.items[0].is_dir);
        let a = svc.children(&["a".into()]).unwrap();
        assert_eq!(a.items.len(), 2);
        assert_eq!(
            svc.children(&["nope".into()]).unwrap_err().code,
            "invalid_path"
        );
        assert_eq!(
            svc.resolve_in_scan(&["a".into(), "big.bin".into()])
                .unwrap(),
            d.join("a/big.bin")
        );
        fs::remove_dir_all(&d).unwrap();
    }

    fn fake_tree() -> ScanOutcome {
        let file = |n: &str, size| Node {
            name: n.into(),
            is_dir: false,
            size,
            file_count: 1,
            children: vec![],
        };
        ScanOutcome {
            root: Node {
                name: "root".into(),
                is_dir: true,
                size: 30,
                file_count: 2,
                children: vec![file("x.bin", 20), file("y.bin", 10)],
            },
            skipped: vec![],
            cancelled: false,
        }
    }

    #[test]
    fn fast_scan_is_preferred_and_serves_children() {
        let d = sandbox();
        write(&d.join("walk-only.bin"), 999);
        let svc = service_fast(&d, Some(Box::new(|_, _, _| Ok(fake_tree()))));
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.method, "mft");
        assert_eq!(s.fallback, None);
        assert_eq!(s.total_size, 30);
        let kids = svc.children(&[]).unwrap();
        assert_eq!(kids.items[0].name, "x.bin");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn failed_fast_scan_falls_back_to_walking() {
        let d = sandbox();
        write(&d.join("a.bin"), 500);
        let svc = service_fast(
            &d,
            Some(Box::new(|_, _, _| Err(("access_denied", "denied".into())))),
        );
        let s = svc.scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!(s.method, "walk");
        assert_eq!(s.fallback, Some("access_denied"));
        assert_eq!(s.total_size, 500);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn no_fast_scanner_means_plain_walk_without_fallback_note() {
        let d = sandbox();
        write(&d.join("a.bin"), 1);
        let s = service(&d).scan(d.to_str().unwrap(), &mut |_| {}).unwrap();
        assert_eq!((s.method, s.fallback), ("walk", None));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn children_before_scan_is_an_error() {
        let d = sandbox();
        assert_eq!(service(&d).children(&[]).unwrap_err().code, "no_scan");
        assert_eq!(
            service(&d)
                .scan("/definitely/missing", &mut |_| {})
                .unwrap_err()
                .code,
            "invalid_path"
        );
    }

    #[test]
    fn plan_then_execute_and_plan_is_single_use() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        write(&d.join("cache/sub/b.bin"), 20);
        let svc = service(&d);

        let plan = svc.build_plan(&["r".into()], &[]).unwrap();
        assert_eq!(plan.total_size, 120);
        assert_eq!(plan.item_count, 2);
        assert_eq!(plan.items[0].size, 100, "largest first");

        let journal = d.join("logs/journal.jsonl");
        let mut ticks = 0;
        let rep = svc
            .execute(
                ExecRequest {
                    dry_run: false,
                    recycle: false,
                },
                &journal,
                &mut |_| ticks += 1,
            )
            .unwrap();
        assert_eq!(rep.freed_bytes, 120);
        assert_eq!(rep.deleted, 2);
        assert_eq!(ticks, 2);
        assert!(fs::read_to_string(&journal).unwrap().contains("\"intent\""));
        assert_eq!(fs::read_dir(d.join("cache")).unwrap().count(), 0);

        let again = svc.execute(
            ExecRequest {
                dry_run: false,
                recycle: false,
            },
            &journal,
            &mut |_| {},
        );
        assert_eq!(again.unwrap_err().code, "no_plan");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn dry_run_reports_without_deleting() {
        let d = sandbox();
        write(&d.join("cache/a.bin"), 100);
        let svc = service(&d);
        svc.build_plan(&["r".into()], &[]).unwrap();
        let rep = svc
            .execute(
                ExecRequest {
                    dry_run: true,
                    recycle: false,
                },
                &d.join("j.jsonl"),
                &mut |_| {},
            )
            .unwrap();
        assert!(rep.dry_run);
        assert_eq!(rep.would_delete, 1);
        assert_eq!(rep.freed_bytes, 0);
        assert!(d.join("cache/a.bin").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn unknown_rule_and_bad_exclusion_are_rejected() {
        let d = sandbox();
        let svc = service(&d);
        assert_eq!(
            svc.build_plan(&["nope".into()], &[]).unwrap_err().code,
            "unknown_rule"
        );
        assert_eq!(
            svc.build_plan(&["r".into()], &["relative/path".into()])
                .unwrap_err()
                .code,
            "invalid_exclusion"
        );
        assert_eq!(
            svc.validate_exclusion("  ").unwrap_err().code,
            "invalid_exclusion"
        );
        assert!(svc.validate_exclusion(d.to_str().unwrap()).is_ok());
    }

    #[test]
    fn exclusions_apply_to_plan() {
        let d = sandbox();
        write(&d.join("cache/keep/x"), 1);
        write(&d.join("cache/drop/y"), 1);
        let svc = service(&d);
        let plan = svc
            .build_plan(
                &["r".into()],
                &[d.join("cache/keep").to_string_lossy().into_owned()],
            )
            .unwrap();
        assert_eq!(plan.item_count, 1);
        assert!(plan.items[0].path.ends_with("drop"));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn display_path_strips_extended_prefix() {
        assert_eq!(display_path(Path::new(r"\\?\C:\Users\a")), r"C:\Users\a");
        assert_eq!(display_path(Path::new("/tmp/x")), "/tmp/x");
    }
}
