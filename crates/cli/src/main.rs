use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use diskclean_core::builtin::windows_rules;
use diskclean_core::cleaner::{execute, ExecOptions, Status};
use diskclean_core::plan::{build_plan, Plan};
use diskclean_core::rules::{Disposal, Env, Risk};
use diskclean_core::safety::{KnownDirs, SafetyPolicy};
use diskclean_core::{format_size, scanner};

const USAGE: &str = "\
用法:
  diskclean scan <目录> [--top N]
  diskclean rules
  diskclean plan  [--rules a,b] [--exclude 路径]...
  diskclean clean [--rules a,b] [--exclude 路径]... [--dry-run] [--recycle] --yes

  plan 只预览；clean 不带 --yes 时同样只预览。默认规则 = 低风险且默认勾选的规则。";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let res = match args.first().map(String::as_str) {
        Some("scan") => scan_cmd(&args[1..]),
        Some("rules") => rules_cmd(),
        Some("plan") => clean_cmd(&args[1..], false),
        Some("clean") => clean_cmd(&args[1..], true),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match res {
        Ok(code) => code,
        Err(e) => {
            eprintln!("错误: {e}");
            ExitCode::FAILURE
        }
    }
}

fn scan_cmd(args: &[String]) -> Result<ExitCode, String> {
    let mut path: Option<PathBuf> = None;
    let mut top = 10usize;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--top" {
            top = it
                .next()
                .and_then(|v| v.parse().ok())
                .ok_or("--top 需要一个数字")?;
        } else if path.is_none() {
            path = Some(PathBuf::from(a));
        } else {
            return Err(USAGE.into());
        }
    }
    let path = path.ok_or(USAGE)?;

    let cancel = AtomicBool::new(false);
    let out = scanner::scan(&path, &cancel, &mut |p| {
        eprint!(
            "\r已扫描 {} 个文件 / {} 个目录 / {}   ",
            p.files,
            p.dirs,
            format_size(p.bytes)
        );
    })
    .map_err(|e| format!("{}: {e}", path.display()))?;
    eprintln!();

    println!(
        "{}  共 {}（{} 个文件）",
        path.display(),
        format_size(out.root.size),
        out.root.file_count
    );
    println!("\n最大的子项:");
    for c in out.root.children.iter().take(top) {
        println!(
            "  {:>10}  {}{}",
            format_size(c.size),
            c.name,
            if c.is_dir { "/" } else { "" }
        );
    }
    println!("\n最大的文件:");
    for (p, s) in scanner::top_files(&path, &out.root, top) {
        println!("  {:>10}  {}", format_size(s), p.display());
    }
    if !out.skipped.is_empty() {
        println!(
            "\n已跳过 {} 项（符号链接/云占位/读取失败）",
            out.skipped.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn rules_cmd() -> Result<ExitCode, String> {
    println!("{:<24} {:<7} {:<6} 目标数", "ID", "风险", "默认");
    for r in windows_rules() {
        println!(
            "{:<24} {:<7} {:<6} {}",
            r.id,
            format!("{:?}", r.risk).to_lowercase(),
            if r.default_selected { "勾选" } else { "-" },
            r.targets.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn print_plan(plan: &Plan) {
    println!("\n清理预览:");
    let mut rows = plan.by_rule();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    for (id, size, files) in rows {
        println!("  {:>10}  {:>7} 个文件  {}", format_size(size), files, id);
    }
    println!(
        "合计: {}（{} 个文件，{} 项）",
        format_size(plan.total_size()),
        plan.total_files(),
        plan.items.len()
    );
    if !plan.skipped.is_empty() {
        println!(
            "已跳过 {} 项（太新、受保护、链接或读取失败等）",
            plan.skipped.len()
        );
    }
}

fn clean_cmd(args: &[String], apply: bool) -> Result<ExitCode, String> {
    let mut rule_ids: Option<Vec<String>> = None;
    let mut excludes = Vec::new();
    let (mut dry_run, mut recycle, mut yes) = (false, false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rules" => {
                let v = it.next().ok_or("--rules 需要逗号分隔的规则 ID")?;
                rule_ids = Some(v.split(',').map(str::to_string).collect());
            }
            "--exclude" => excludes.push(it.next().ok_or("--exclude 需要一个路径")?.clone()),
            "--dry-run" => dry_run = true,
            "--recycle" => recycle = true,
            "--yes" => yes = true,
            other => return Err(format!("未知参数 {other}\n{USAGE}")),
        }
    }

    let dirs =
        KnownDirs::from_env().ok_or("读取不到 Windows 系统目录环境变量；清理功能仅支持 Windows")?;
    let mut policy = SafetyPolicy::new(&dirs).map_err(|e| format!("无法初始化安全策略: {e}"))?;
    for x in &excludes {
        policy
            .exclude(x)
            .map_err(|e| format!("排除路径 {x} 无效: {e}"))?;
    }

    let rules = windows_rules();
    let selected: Vec<String> = match rule_ids {
        Some(ids) => {
            for id in &ids {
                if !rules.iter().any(|r| &r.id == id) {
                    return Err(format!("未知规则 {id}（用 `diskclean rules` 查看）"));
                }
            }
            ids
        }
        None => rules
            .iter()
            .filter(|r| r.default_selected && r.risk == Risk::Low)
            .map(|r| r.id.clone())
            .collect(),
    };
    let sel: Vec<&str> = selected.iter().map(String::as_str).collect();

    let cancel = AtomicBool::new(false);
    let plan = build_plan(
        &rules,
        &sel,
        &Env::from_process(),
        &policy,
        SystemTime::now(),
        &cancel,
    );
    print_plan(&plan);

    if !apply || plan.items.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    if !yes && !dry_run {
        println!("\n未加 --yes，未做任何改动。");
        return Ok(ExitCode::SUCCESS);
    }

    let journal_path = std::env::var_os("LOCALAPPDATA")
        .map(|d| PathBuf::from(d).join("diskclean"))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("journal.jsonl");
    if let Some(dir) = journal_path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("无法创建日志目录: {e}"))?;
    }
    let mut journal = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&journal_path)
        .map_err(|e| format!("无法打开操作日志 {}: {e}", journal_path.display()))?;

    let opts = ExecOptions {
        dry_run,
        override_disposal: recycle.then_some(Disposal::Recycle),
    };
    let report = execute(
        &plan,
        opts,
        Some(&mut journal as &mut dyn Write),
        &cancel,
        &mut |done, total| {
            eprint!("\r进度 {done}/{total}   ");
        },
    );
    eprintln!();

    println!("\n完成{}:", if dry_run { "（dry-run）" } else { "" });
    println!("  已释放: {}", format_size(report.freed_bytes));
    if report.recycled_bytes > 0 {
        println!(
            "  已移入回收站: {}（清空回收站后才会释放）",
            format_size(report.recycled_bytes)
        );
    }
    println!(
        "  失败 {} 项，拒绝 {} 项",
        report.failed(),
        report.refused()
    );
    for e in report
        .entries
        .iter()
        .filter(|e| matches!(e.status, Status::Failed(_) | Status::Refused(_)))
        .take(20)
    {
        println!("    {}  {:?}", e.path, e.status);
    }
    println!("  操作日志: {}", journal_path.display());
    Ok(if report.failed() + report.refused() > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}
