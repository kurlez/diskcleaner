use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use diskclean_core::{format_size, scanner};

const USAGE: &str = "用法: diskclean scan <目录> [--top N]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scan") => match scan_cmd(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("错误: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn scan_cmd(args: &[String]) -> Result<(), String> {
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
    Ok(())
}
