//! 清理执行器：按计划删除，逐项二次校验，并先写操作日志再动手。

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::plan::{Candidate, Plan};
use crate::rules::Disposal;
use crate::scanner::special_reason;
use crate::sysaction::ServiceControl;

#[derive(Debug, Clone, Copy, Default)]
pub struct ExecOptions {
    /// 只走流程、不删除任何东西。
    pub dry_run: bool,
    /// 覆盖规则自带的删除方式。
    pub override_disposal: Option<Disposal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "detail", rename_all = "snake_case")]
pub enum Status {
    /// 已永久删除。
    Deleted,
    /// 已移入回收站（空间要清空回收站后才释放）。
    Recycled,
    /// dry-run：本应处理但未执行。
    WouldDelete,
    /// 执行时二次校验未通过，未触碰。
    Refused(String),
    /// 执行出错（被占用、权限不足等）。
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub rule_id: String,
    pub path: String,
    pub size: u64,
    pub status: Status,
}

#[derive(Debug, Default)]
pub struct Report {
    pub entries: Vec<Entry>,
    /// 已永久删除并释放的字节数。
    pub freed_bytes: u64,
    /// 已移入回收站的字节数（尚未释放）。
    pub recycled_bytes: u64,
    pub cancelled: bool,
    /// 停止/恢复服务时遇到的问题（不影响文件删除本身，但需要告知用户）。
    pub service_errors: Vec<String>,
}

impl Report {
    pub fn count(&self, pred: impl Fn(&Status) -> bool) -> usize {
        self.entries.iter().filter(|e| pred(&e.status)).count()
    }

    pub fn failed(&self) -> usize {
        self.count(|s| matches!(s, Status::Failed(_)))
    }

    pub fn refused(&self) -> usize {
        self.count(|s| matches!(s, Status::Refused(_)))
    }
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Record<'a> {
    /// 停止或恢复 Windows 服务。
    Service {
        ts: u64,
        action: &'a str,
        name: &'a str,
        ok: bool,
    },
    /// 动手之前写入。崩溃后若只有 intent 没有 result，说明该项状态未知。
    Intent {
        ts: u64,
        rule: &'a str,
        path: &'a str,
        size: u64,
        action: &'a str,
    },
    Result {
        ts: u64,
        path: &'a str,
        #[serde(flatten)]
        status: &'a Status,
    },
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_record(journal: &mut Option<&mut dyn Write>, rec: &Record) -> io::Result<()> {
    if let Some(w) = journal.as_deref_mut() {
        serde_json::to_writer(&mut *w, rec).map_err(io::Error::other)?;
        w.write_all(b"\n")?;
        w.flush()?;
    }
    Ok(())
}

/// 执行计划。
///
/// 日志写入失败时立即中止（不允许"无日志地删除"），已完成的项保留在报告里。
/// `on_progress(已处理项数, 总项数)` 每处理一项调用一次。
pub fn execute(
    plan: &Plan,
    opts: ExecOptions,
    journal: Option<&mut dyn Write>,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Report {
    execute_with(plan, opts, journal, None, cancel, on_progress)
}

/// 记录并执行一次服务操作。
fn service_op(
    journal: &mut Option<&mut dyn Write>,
    report: &mut Report,
    action: &str,
    name: &str,
    result: Result<(), String>,
) {
    let ok = result.is_ok();
    let _ = write_record(
        journal,
        &Record::Service {
            ts: now_secs(),
            action,
            name,
            ok,
        },
    );
    if let Err(e) = result {
        report.service_errors.push(format!("{action} {name}: {e}"));
    }
}

/// 恢复我们停掉的服务。
fn restore_services(
    journal: &mut Option<&mut dyn Write>,
    report: &mut Report,
    ctl: Option<&dyn ServiceControl>,
    stopped: &mut Vec<String>,
) {
    if let Some(ctl) = ctl {
        // 与停止相反的顺序恢复。
        for name in stopped.drain(..).rev() {
            service_op(journal, report, "start", &name, ctl.start(&name));
        }
    }
    stopped.clear();
}

/// 与 [`execute`] 相同，但会在每条规则的文件处理前后停止并恢复它声明的服务。
///
/// 服务只会恢复"我们自己停掉的"；无论取消、日志失败还是正常结束，都会恢复。
/// dry-run 不碰任何服务。
pub fn execute_with(
    plan: &Plan,
    opts: ExecOptions,
    mut journal: Option<&mut dyn Write>,
    services: Option<&dyn ServiceControl>,
    cancel: &AtomicBool,
    on_progress: &mut dyn FnMut(usize, usize),
) -> Report {
    let mut report = Report::default();
    let total = plan.items.len();
    let ctl = if opts.dry_run { None } else { services };
    let mut stopped: Vec<String> = Vec::new();
    let mut current_rule: Option<&str> = None;

    for (i, item) in plan.items.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        // 规则切换：恢复上一条规则停掉的服务，再停止新规则需要的服务。
        if current_rule != Some(item.rule_id.as_str()) {
            restore_services(&mut journal, &mut report, ctl, &mut stopped);
            current_rule = Some(item.rule_id.as_str());
            if let (Some(ctl), Some(names)) = (ctl, plan.rule_services.get(&item.rule_id)) {
                for name in names {
                    match ctl.stop(name) {
                        Ok(true) => {
                            stopped.push(name.clone());
                            service_op(&mut journal, &mut report, "stop", name, Ok(()));
                        }
                        Ok(false) => {}
                        Err(e) => service_op(&mut journal, &mut report, "stop", name, Err(e)),
                    }
                }
            }
        }
        let disposal = opts.override_disposal.unwrap_or(item.disposal);
        let path_str = item.path.to_string_lossy().into_owned();
        let action = if opts.dry_run {
            "dry_run"
        } else if disposal == Disposal::Recycle {
            "recycle"
        } else {
            "delete"
        };

        let intent = Record::Intent {
            ts: now_secs(),
            rule: &item.rule_id,
            path: &path_str,
            size: item.size,
            action,
        };
        if let Err(e) = write_record(&mut journal, &intent) {
            report.entries.push(Entry {
                rule_id: item.rule_id.clone(),
                path: path_str,
                size: item.size,
                status: Status::Failed(format!("journal write failed, aborting: {e}")),
            });
            break;
        }

        let status = run_one(plan, item, disposal, opts.dry_run);
        match &status {
            Status::Deleted => report.freed_bytes += item.size,
            Status::Recycled => report.recycled_bytes += item.size,
            _ => {}
        }
        let _ = write_record(
            &mut journal,
            &Record::Result {
                ts: now_secs(),
                path: &path_str,
                status: &status,
            },
        );
        report.entries.push(Entry {
            rule_id: item.rule_id.clone(),
            path: path_str,
            size: item.size,
            status,
        });
        on_progress(i + 1, total);
    }
    restore_services(&mut journal, &mut report, ctl, &mut stopped);
    report
}

fn run_one(plan: &Plan, item: &Candidate, disposal: Disposal, dry_run: bool) -> Status {
    // 二次校验：计划生成之后路径可能已被替换（TOCTOU）。
    let Some(p) = item.path.to_str() else {
        return Status::Refused("non-UTF-8 path".into());
    };
    if let Err(d) = plan.policy.check_delete(p) {
        return Status::Refused(d.to_string());
    }
    match fs::symlink_metadata(&item.path) {
        Ok(meta) => {
            if special_reason(&meta).is_some() {
                return Status::Refused("path is now a link or cloud placeholder".into());
            }
            if meta.is_dir() != item.is_dir {
                return Status::Refused("file type changed since planning".into());
            }
        }
        // 已经不存在：目标达成，不算失败。
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Status::Deleted,
        Err(e) => return Status::Failed(e.to_string()),
    }

    if dry_run {
        return Status::WouldDelete;
    }
    match disposal {
        Disposal::Permanent => match remove_permanently(&item.path, item.is_dir) {
            Ok(()) => Status::Deleted,
            Err(e) => Status::Failed(e.to_string()),
        },
        Disposal::Recycle => match trash::delete(&item.path) {
            Ok(()) => Status::Recycled,
            Err(e) => Status::Failed(e.to_string()),
        },
    }
}

fn remove_permanently(path: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir {
        // remove_dir_all 不跟随符号链接/junction，只删链接本身。
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}
