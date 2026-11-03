//! 在真实临时目录上做规划 + 执行的集成测试（Posix 路径风格，规则与 Windows 一致）。

use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use std::cell::RefCell;

use diskclean_core::cleaner::{execute, execute_with, ExecOptions, Status};
use diskclean_core::plan::{build_plan, PlanSkipReason};
use diskclean_core::rules::{Disposal, Env, Risk, Rule, Target, TargetKind};
use diskclean_core::safety::{PathStyle, SafetyPolicy};
use diskclean_core::sysaction::ServiceControl;

static N: AtomicU64 = AtomicU64::new(0);

struct Sandbox {
    base: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let raw = std::env::temp_dir().join(format!("dc-flow-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&raw);
        fs::create_dir_all(&raw).unwrap();
        Sandbox {
            base: fs::canonicalize(raw).unwrap(),
        }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.base.join(rel)
    }
    fn write(&self, rel: &str, len: usize) -> PathBuf {
        let p = self.p(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, vec![1u8; len]).unwrap();
        p
    }
    fn env(&self) -> Env {
        Env::from_pairs([("BASE", self.base.to_string_lossy())])
    }
    fn policy(&self) -> SafetyPolicy {
        let mut p = SafetyPolicy::empty(PathStyle::Posix);
        // 整个沙箱默认受保护，只有规则目标会被放开。
        p.protect(self.base.to_str().unwrap()).unwrap();
        p
    }
    fn age(&self, rel: &str, days: u64) {
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        File::options()
            .write(true)
            .open(self.p(rel))
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn rule(id: &str, targets: Vec<Target>) -> Rule {
    Rule {
        id: id.into(),
        risk: Risk::Low,
        default_selected: true,
        disposal: Disposal::Permanent,
        targets,
        services: vec![],
    }
}

fn contents(path: &str) -> Target {
    Target {
        path: path.into(),
        kind: TargetKind::Contents,
        name_globs: vec![],
        min_age_days: 0,
    }
}

fn run_plan(sb: &Sandbox, rules: &[Rule], policy: &SafetyPolicy) -> diskclean_core::plan::Plan {
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    build_plan(
        rules,
        &ids,
        &sb.env(),
        policy,
        SystemTime::now(),
        &AtomicBool::new(false),
    )
}

fn run_exec(
    plan: &diskclean_core::plan::Plan,
    opts: ExecOptions,
) -> diskclean_core::cleaner::Report {
    execute(plan, opts, None, &AtomicBool::new(false), &mut |_, _| {})
}

#[test]
fn deletes_contents_but_keeps_root_and_neighbours() {
    let sb = Sandbox::new();
    sb.write("cache/a.bin", 100);
    sb.write("cache/sub/b.bin", 50);
    let keep = sb.write("other/keep.txt", 10);
    let rules = vec![rule("r", vec![contents("%BASE%/cache")])];

    let plan = run_plan(&sb, &rules, &sb.policy());
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.total_size(), 150);
    assert_eq!(plan.total_files(), 2);

    let report = run_exec(&plan, ExecOptions::default());
    assert_eq!(report.freed_bytes, 150);
    assert_eq!(report.failed() + report.refused(), 0);
    assert!(sb.p("cache").is_dir(), "target root must remain");
    assert_eq!(fs::read_dir(sb.p("cache")).unwrap().count(), 0);
    assert!(keep.exists());
}

#[test]
fn dry_run_touches_nothing() {
    let sb = Sandbox::new();
    let f = sb.write("cache/a.bin", 100);
    let rules = vec![rule("r", vec![contents("%BASE%/cache")])];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let report = run_exec(
        &plan,
        ExecOptions {
            dry_run: true,
            ..Default::default()
        },
    );
    assert!(f.exists());
    assert_eq!(report.freed_bytes, 0);
    assert!(report
        .entries
        .iter()
        .all(|e| e.status == Status::WouldDelete));
}

#[test]
fn name_globs_and_age_filter() {
    let sb = Sandbox::new();
    sb.write("logs/old.log", 10);
    sb.write("logs/new.log", 20);
    sb.write("logs/old.txt", 30);
    sb.age("logs/old.log", 60);
    sb.age("logs/old.txt", 60);
    let t = Target {
        name_globs: vec!["*.log".into()],
        min_age_days: 30,
        ..contents("%BASE%/logs")
    };
    let plan = run_plan(&sb, &[rule("r", vec![t])], &sb.policy());
    assert_eq!(plan.items.len(), 1);
    assert!(plan.items[0].path.ends_with("old.log"));
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.reason == PlanSkipReason::TooNew));
    run_exec(&plan, ExecOptions::default());
    assert!(!sb.p("logs/old.log").exists());
    assert!(sb.p("logs/new.log").exists());
    assert!(sb.p("logs/old.txt").exists());
}

#[test]
fn directory_age_uses_newest_file_inside() {
    let sb = Sandbox::new();
    sb.write("c/proj/old.bin", 1);
    sb.write("c/proj/fresh.bin", 1);
    sb.age("c/proj/old.bin", 90);
    let t = Target {
        min_age_days: 30,
        ..contents("%BASE%/c")
    };
    let plan = run_plan(&sb, &[rule("r", vec![t])], &sb.policy());
    assert!(plan.items.is_empty());
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.reason == PlanSkipReason::TooNew));
}

#[test]
fn protected_name_inside_blocks_whole_item() {
    let sb = Sandbox::new();
    sb.write("cache/repo/.git/HEAD", 5);
    sb.write("cache/plain/x", 5);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    assert_eq!(plan.items.len(), 1);
    assert!(plan.items[0].path.ends_with("plain"));
    assert!(plan
        .skipped
        .iter()
        .any(|s| matches!(&s.reason, PlanSkipReason::ProtectedInside(n) if n == ".git")));
    run_exec(&plan, ExecOptions::default());
    assert!(sb.p("cache/repo/.git/HEAD").exists());
}

#[test]
fn user_exclusion_wins_over_rule() {
    let sb = Sandbox::new();
    sb.write("cache/a", 1);
    sb.write("cache/keep/b", 1);
    let mut policy = sb.policy();
    policy
        .exclude(sb.p("cache/keep").to_str().unwrap())
        .unwrap();
    let plan = run_plan(&sb, &[rule("r", vec![contents("%BASE%/cache")])], &policy);
    assert_eq!(plan.items.len(), 1);
    assert!(plan.items[0].path.ends_with("a"));
    run_exec(&plan, ExecOptions::default());
    assert!(sb.p("cache/keep/b").exists());
}

#[test]
fn exact_file_target_only_removes_that_file() {
    let sb = Sandbox::new();
    let dump = sb.write("win/MEMORY.DMP", 500);
    let neighbour = sb.write("win/other.sys", 7);
    let t = Target {
        kind: TargetKind::File,
        ..contents("%BASE%/win/MEMORY.DMP")
    };
    let plan = run_plan(&sb, &[rule("r", vec![t])], &sb.policy());
    assert_eq!(plan.items.len(), 1);
    run_exec(&plan, ExecOptions::default());
    assert!(!dump.exists());
    assert!(neighbour.exists());
}

#[test]
fn overlapping_targets_are_deduplicated() {
    let sb = Sandbox::new();
    sb.write("cache/a", 10);
    let rules = vec![
        rule("r1", vec![contents("%BASE%/cache")]),
        rule("r2", vec![contents("%BASE%/cache")]),
    ];
    let plan = run_plan(&sb, &rules, &sb.policy());
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.total_size(), 10);
}

#[test]
fn missing_env_or_path_yields_empty_plan() {
    let sb = Sandbox::new();
    let rules = vec![
        rule("a", vec![contents("%NOPE%/x")]),
        rule("b", vec![contents("%BASE%/absent")]),
    ];
    let plan = run_plan(&sb, &rules, &sb.policy());
    assert!(plan.items.is_empty() && plan.skipped.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinks_are_skipped_and_never_followed() {
    let sb = Sandbox::new();
    let precious = sb.write("precious/doc.txt", 1000);
    sb.write("cache/a", 1);
    std::os::unix::fs::symlink(sb.p("precious"), sb.p("cache/link")).unwrap();
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.reason == PlanSkipReason::ReparsePoint));
    run_exec(&plan, ExecOptions::default());
    assert!(precious.exists());
    assert!(sb.p("cache/link").exists(), "link itself is left alone too");
}

#[cfg(unix)]
#[test]
fn item_swapped_for_symlink_after_planning_is_refused() {
    let sb = Sandbox::new();
    let precious = sb.write("precious/doc.txt", 1000);
    sb.write("cache/victim/x", 1);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    assert_eq!(plan.items.len(), 1);

    // 计划生成之后，攻击者把目录换成指向别处的链接。
    fs::remove_dir_all(sb.p("cache/victim")).unwrap();
    std::os::unix::fs::symlink(sb.p("precious"), sb.p("cache/victim")).unwrap();

    let report = run_exec(&plan, ExecOptions::default());
    assert_eq!(report.refused(), 1);
    assert!(precious.exists());
}

#[test]
fn item_already_gone_is_not_a_failure() {
    let sb = Sandbox::new();
    let f = sb.write("cache/a", 3);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    fs::remove_file(f).unwrap();
    let report = run_exec(&plan, ExecOptions::default());
    assert_eq!(report.failed(), 0);
}

#[test]
fn journal_records_intent_before_result() {
    let sb = Sandbox::new();
    sb.write("cache/a", 10);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    let mut buf: Vec<u8> = Vec::new();
    let report = execute(
        &plan,
        ExecOptions::default(),
        Some(&mut buf),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(report.freed_bytes, 10);
    let lines: Vec<serde_json::Value> = String::from_utf8(buf)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["op"], "intent");
    assert_eq!(lines[0]["action"], "delete");
    assert_eq!(lines[1]["op"], "result");
    assert_eq!(lines[1]["status"], "deleted");
}

struct FailingWriter;
impl std::io::Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk full"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn journal_failure_aborts_before_deleting() {
    let sb = Sandbox::new();
    let f = sb.write("cache/a", 10);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    let report = execute(
        &plan,
        ExecOptions::default(),
        Some(&mut FailingWriter),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert!(f.exists(), "must not delete without a journal");
    assert_eq!(report.failed(), 1);
}

#[test]
fn cancel_stops_execution() {
    let sb = Sandbox::new();
    let f = sb.write("cache/a", 10);
    let plan = run_plan(
        &sb,
        &[rule("r", vec![contents("%BASE%/cache")])],
        &sb.policy(),
    );
    let report = execute(
        &plan,
        ExecOptions::default(),
        None,
        &AtomicBool::new(true),
        &mut |_, _| {},
    );
    assert!(report.cancelled);
    assert!(f.exists());
}

// ---------- 服务停启 ----------

/// 记录调用顺序；`fail_stop` 中的服务停止时报错。
struct FakeServices {
    log: RefCell<Vec<String>>,
    running: Vec<&'static str>,
    fail_stop: Vec<&'static str>,
}

impl FakeServices {
    fn new(running: &[&'static str], fail_stop: &[&'static str]) -> Self {
        Self {
            log: RefCell::new(vec![]),
            running: running.to_vec(),
            fail_stop: fail_stop.to_vec(),
        }
    }
}

impl ServiceControl for FakeServices {
    fn stop(&self, name: &str) -> Result<bool, String> {
        self.log.borrow_mut().push(format!("stop {name}"));
        if self.fail_stop.contains(&name) {
            return Err("access denied".into());
        }
        Ok(self.running.contains(&name))
    }
    fn start(&self, name: &str) -> Result<(), String> {
        self.log.borrow_mut().push(format!("start {name}"));
        Ok(())
    }
}

fn rule_with_services(id: &str, target: &str, services: &[&str]) -> Rule {
    let mut r = rule(id, vec![contents(target)]);
    r.services = services.iter().map(|s| s.to_string()).collect();
    r
}

#[test]
fn services_are_stopped_before_and_restored_after_their_rule() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    sb.write("tmp/b.tmp", 10);
    let rules = vec![
        rule_with_services("upd", "%BASE%/upd", &["wuauserv", "bits"]),
        rule("tmp", vec![contents("%BASE%/tmp")]),
    ];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let svc = FakeServices::new(&["wuauserv", "bits"], &[]);
    let report = execute_with(
        &plan,
        ExecOptions::default(),
        None,
        Some(&svc),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(report.freed_bytes, 20);
    assert!(report.service_errors.is_empty());
    // 先停，处理完 upd 规则的文件后立即按相反顺序恢复，之后才轮到无服务的规则。
    assert_eq!(
        *svc.log.borrow(),
        ["stop wuauserv", "stop bits", "start bits", "start wuauserv"]
    );
}

#[test]
fn only_services_we_stopped_are_restarted() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    let rules = vec![rule_with_services(
        "upd",
        "%BASE%/upd",
        &["wuauserv", "bits"],
    )];
    let plan = run_plan(&sb, &rules, &sb.policy());
    // bits 本来就没运行：不应被我们启动。
    let svc = FakeServices::new(&["wuauserv"], &[]);
    execute_with(
        &plan,
        ExecOptions::default(),
        None,
        Some(&svc),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(
        *svc.log.borrow(),
        ["stop wuauserv", "stop bits", "start wuauserv"]
    );
}

#[test]
fn services_are_restored_even_when_cancelled_midway() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    sb.write("upd/b.cab", 10);
    let rules = vec![rule_with_services("upd", "%BASE%/upd", &["wuauserv"])];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let svc = FakeServices::new(&["wuauserv"], &[]);
    let cancel = AtomicBool::new(false);
    // 处理完第一项后触发取消。
    let report = execute_with(
        &plan,
        ExecOptions::default(),
        None,
        Some(&svc),
        &cancel,
        &mut |done, _| {
            if done == 1 {
                cancel.store(true, Ordering::Relaxed);
            }
        },
    );
    assert!(report.cancelled);
    assert_eq!(*svc.log.borrow(), ["stop wuauserv", "start wuauserv"]);
}

#[test]
fn service_failure_is_reported_but_files_are_still_processed() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    let rules = vec![rule_with_services("upd", "%BASE%/upd", &["wuauserv"])];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let svc = FakeServices::new(&["wuauserv"], &["wuauserv"]);
    let report = execute_with(
        &plan,
        ExecOptions::default(),
        None,
        Some(&svc),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(report.service_errors.len(), 1);
    assert!(report.service_errors[0].contains("wuauserv"));
    assert_eq!(report.freed_bytes, 10);
    assert_eq!(
        *svc.log.borrow(),
        ["stop wuauserv"],
        "没停成功就不应尝试恢复"
    );
}

#[test]
fn dry_run_never_touches_services() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    let rules = vec![rule_with_services("upd", "%BASE%/upd", &["wuauserv"])];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let svc = FakeServices::new(&["wuauserv"], &[]);
    let opts = ExecOptions {
        dry_run: true,
        ..Default::default()
    };
    execute_with(
        &plan,
        opts,
        None,
        Some(&svc),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert!(svc.log.borrow().is_empty());
}

#[test]
fn service_actions_are_journaled() {
    let sb = Sandbox::new();
    sb.write("upd/a.cab", 10);
    let rules = vec![rule_with_services("upd", "%BASE%/upd", &["wuauserv"])];
    let plan = run_plan(&sb, &rules, &sb.policy());
    let svc = FakeServices::new(&["wuauserv"], &[]);
    let mut buf: Vec<u8> = Vec::new();
    execute_with(
        &plan,
        ExecOptions::default(),
        Some(&mut buf),
        Some(&svc),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    let ops: Vec<String> = String::from_utf8(buf)
        .unwrap()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            match v["op"].as_str().unwrap() {
                "service" => format!(
                    "service:{}:{}",
                    v["action"].as_str().unwrap(),
                    v["name"].as_str().unwrap()
                ),
                other => other.to_string(),
            }
        })
        .collect();
    assert_eq!(
        ops,
        [
            "service:stop:wuauserv",
            "intent",
            "result",
            "service:start:wuauserv"
        ]
    );
}
