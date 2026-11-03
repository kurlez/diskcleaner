//! 清理计划：把规则展开成"将要删除什么"的清单，只读，不修改任何文件。

use std::collections::{HashMap, HashSet};
use std::fs::{self, Metadata};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use crate::rules::{glob_match, Disposal, Env, Rule, Target, TargetKind};
use crate::safety::{is_protected_name, Denied, SafetyPolicy};
use crate::scanner::{special_reason, SkipReason};

const MAX_DEPTH: usize = 256;

#[derive(Debug, Clone)]
pub struct Candidate {
    pub rule_id: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub file_count: u64,
    pub disposal: Disposal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanSkipReason {
    /// 被安全策略拒绝。
    Denied(Denied),
    /// 符号链接 / junction / 挂载点。
    ReparsePoint,
    /// 云占位文件。
    CloudPlaceholder,
    /// 子树内有文件修改时间太新。
    TooNew,
    /// 子树内含受保护名称（如 `.git`）。
    ProtectedInside(String),
    /// 路径不是合法 UTF-8，无法做安全校验。
    NonUtf8Path,
    Io(String),
}

#[derive(Debug, Clone)]
pub struct PlanSkip {
    pub rule_id: String,
    pub path: PathBuf,
    pub reason: PlanSkipReason,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub items: Vec<Candidate>,
    pub skipped: Vec<PlanSkip>,
    /// 为本计划扩展过允许根的策略；执行器用同一份策略做二次校验。
    pub policy: SafetyPolicy,
    pub cancelled: bool,
    /// 规则 ID → 清理其文件前需要停止的服务。
    pub rule_services: HashMap<String, Vec<String>>,
    /// 已纳入计划的路径，避免多条规则/目标重复处理同一路径。
    seen: HashSet<PathBuf>,
}

impl Plan {
    /// 由调用方直接给出清单的计划（如用户亲自勾选的重复文件）。
    /// 执行时仍会用 `policy` 逐项二次校验。
    pub fn from_items(items: Vec<Candidate>, policy: SafetyPolicy) -> Plan {
        Plan {
            seen: items.iter().map(|c| c.path.clone()).collect(),
            items,
            skipped: Vec::new(),
            policy,
            cancelled: false,
            rule_services: HashMap::new(),
        }
    }

    pub fn total_size(&self) -> u64 {
        self.items.iter().map(|c| c.size).sum()
    }

    pub fn total_files(&self) -> u64 {
        self.items.iter().map(|c| c.file_count).sum()
    }

    /// 按规则汇总：`(rule_id, 大小, 文件数)`。
    pub fn by_rule(&self) -> Vec<(String, u64, u64)> {
        let mut out: Vec<(String, u64, u64)> = Vec::new();
        for c in &self.items {
            match out.iter_mut().find(|(id, _, _)| *id == c.rule_id) {
                Some(e) => {
                    e.1 += c.size;
                    e.2 += c.file_count;
                }
                None => out.push((c.rule_id.clone(), c.size, c.file_count)),
            }
        }
        out
    }
}

/// 构建清理计划。
///
/// * `selected`：要执行的规则 ID。
/// * `base_policy`：带全局保护名单与用户排除项的策略；本函数克隆后为每个目标追加允许根。
/// * `now`：当前时间（注入以便测试年龄过滤）。
pub fn build_plan(
    rules: &[Rule],
    selected: &[&str],
    env: &Env,
    base_policy: &SafetyPolicy,
    now: SystemTime,
    cancel: &AtomicBool,
) -> Plan {
    let mut plan = Plan {
        items: Vec::new(),
        skipped: Vec::new(),
        policy: base_policy.clone(),
        cancelled: false,
        rule_services: HashMap::new(),
        seen: HashSet::new(),
    };

    for rule in rules.iter().filter(|r| selected.contains(&r.id.as_str())) {
        if !rule.services.is_empty() {
            plan.rule_services
                .insert(rule.id.clone(), rule.services.clone());
        }
        for target in &rule.targets {
            for root in target.resolve(env) {
                if cancel.load(Ordering::Relaxed) {
                    plan.cancelled = true;
                    return plan;
                }
                plan_target(rule, target, &root, now, cancel, &mut plan);
            }
        }
    }
    plan
}

fn plan_target(
    rule: &Rule,
    target: &Target,
    root: &Path,
    now: SystemTime,
    cancel: &AtomicBool,
    plan: &mut Plan,
) {
    let Some(root_str) = root.to_str() else {
        plan.skipped
            .push(skip(rule, root, PlanSkipReason::NonUtf8Path));
        return;
    };
    // 目标本身是链接则整个目标不碰。
    if let Ok(meta) = fs::symlink_metadata(root) {
        if let Some(r) = special_reason(&meta) {
            plan.skipped.push(skip(rule, root, reason_of(r)));
            return;
        }
    }

    match target.kind {
        TargetKind::File => {
            let registered = plan.policy.allow_exact(root_str);
            if let Err(d) = registered {
                plan.skipped
                    .push(skip(rule, root, PlanSkipReason::Denied(d)));
                return;
            }
            consider(rule, target, root, now, plan);
        }
        TargetKind::Contents => {
            if let Err(d) = plan.policy.allow_root(root_str) {
                plan.skipped
                    .push(skip(rule, root, PlanSkipReason::Denied(d)));
                return;
            }
            let rd = match fs::read_dir(root) {
                Ok(rd) => rd,
                Err(e) => {
                    plan.skipped
                        .push(skip(rule, root, PlanSkipReason::Io(e.to_string())));
                    return;
                }
            };
            let mut entries: Vec<_> = rd.flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                if cancel.load(Ordering::Relaxed) {
                    plan.cancelled = true;
                    return;
                }
                let name = e.file_name().to_string_lossy().into_owned();
                if !target.name_globs.is_empty()
                    && !target.name_globs.iter().any(|g| glob_match(g, &name))
                {
                    continue;
                }
                consider(rule, target, &e.path(), now, plan);
            }
        }
    }
}

/// 评估单个候选项，通过则加入计划，否则记录跳过原因。
fn consider(rule: &Rule, target: &Target, path: &Path, now: SystemTime, plan: &mut Plan) {
    if plan.seen.contains(path) {
        return;
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            plan.skipped
                .push(skip(rule, path, PlanSkipReason::Io(e.to_string())));
            return;
        }
    };
    if let Some(r) = special_reason(&meta) {
        plan.skipped.push(skip(rule, path, reason_of(r)));
        return;
    }
    let Some(path_str) = path.to_str() else {
        plan.skipped
            .push(skip(rule, path, PlanSkipReason::NonUtf8Path));
        return;
    };
    if let Err(d) = plan.policy.check_delete(path_str) {
        plan.skipped
            .push(skip(rule, path, PlanSkipReason::Denied(d)));
        return;
    }

    let m = measure(path, &meta, 0);
    if let Some(bad) = m.blocker {
        plan.skipped.push(skip(rule, path, bad));
        return;
    }
    if target.min_age_days > 0 {
        let cutoff = now
            .checked_sub(Duration::from_secs(u64::from(target.min_age_days) * 86_400))
            .unwrap_or(SystemTime::UNIX_EPOCH);
        if m.newest > cutoff {
            plan.skipped.push(skip(rule, path, PlanSkipReason::TooNew));
            return;
        }
    }
    plan.seen.insert(path.to_path_buf());
    plan.items.push(Candidate {
        rule_id: rule.id.clone(),
        path: path.to_path_buf(),
        is_dir: meta.is_dir(),
        size: m.size,
        file_count: m.files,
        disposal: rule.disposal,
    });
}

fn skip(rule: &Rule, path: &Path, reason: PlanSkipReason) -> PlanSkip {
    PlanSkip {
        rule_id: rule.id.clone(),
        path: path.to_path_buf(),
        reason,
    }
}

fn reason_of(r: SkipReason) -> PlanSkipReason {
    match r {
        SkipReason::CloudPlaceholder => PlanSkipReason::CloudPlaceholder,
        SkipReason::ReparsePoint => PlanSkipReason::ReparsePoint,
        SkipReason::Error => PlanSkipReason::Io("unreadable".into()),
    }
}

struct Measure {
    size: u64,
    files: u64,
    newest: SystemTime,
    /// 子树内发现的、使整项不能删除的原因。
    blocker: Option<PlanSkipReason>,
}

/// 统计子树大小、文件数与最新修改时间，同时检查是否含受保护名称或云占位文件。
/// 子树内的链接不跟随、不计入。
fn measure(path: &Path, meta: &Metadata, depth: usize) -> Measure {
    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let mut m = Measure {
        size: 0,
        files: 0,
        newest: mtime,
        blocker: None,
    };
    if !meta.is_dir() {
        m.size = meta.len();
        m.files = 1;
        return m;
    }
    if depth >= MAX_DEPTH {
        m.blocker = Some(PlanSkipReason::Io("directory nesting too deep".into()));
        return m;
    }
    let Ok(rd) = fs::read_dir(path) else {
        m.blocker = Some(PlanSkipReason::Io("cannot read directory".into()));
        return m;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if is_protected_name(&name) {
            m.blocker = Some(PlanSkipReason::ProtectedInside(name));
            return m;
        }
        let Ok(child_meta) = e.metadata() else {
            continue;
        };
        match special_reason(&child_meta) {
            Some(SkipReason::CloudPlaceholder) => {
                m.blocker = Some(PlanSkipReason::CloudPlaceholder);
                return m;
            }
            Some(_) => continue,
            None => {}
        }
        let c = measure(&e.path(), &child_meta, depth + 1);
        if c.blocker.is_some() {
            m.blocker = c.blocker;
            return m;
        }
        m.size += c.size;
        m.files += c.files;
        m.newest = m.newest.max(c.newest);
    }
    m
}
