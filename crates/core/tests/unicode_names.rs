//! 文件名里的中文、日文、韩文、emoji、组合字符，以及不合法的编码，在各个环节都不能乱码或丢失。

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::SystemTime;

use diskclean_core::cleaner::{execute, ExecOptions};
use diskclean_core::duplicates::{find_duplicates, DupOptions};
use diskclean_core::migrate::{manifest_of, verify_equal, Copier, StdCopier};
#[cfg(unix)]
use diskclean_core::plan::PlanSkipReason;
use diskclean_core::plan::{build_plan, Candidate, Plan};
use diskclean_core::registry::{export_keys, to_utf16le_with_bom, Hive, MemRegistry, RegValue};
use diskclean_core::rules::{Disposal, Env, Risk, Rule, Target, TargetKind};
use diskclean_core::safety::{PathStyle, SafetyPolicy};
use diskclean_core::scanner;

static N: AtomicU64 = AtomicU64::new(0);

/// 覆盖常见脚本、emoji（需要代理对）、全角符号、空格、点号、预组合与分解形式的重音字符。
const NAMES: &[&str] = &[
    "项目 报告 (终稿).docx",
    "日本語のファイル.txt",
    "한국어 파일.txt",
    "emoji📄🔥.bin",
    "Ünïcödé-ÀÉÎõü.txt",
    "全角：文件＿名称.dat",
    "a b  c   d.txt",
    "…中文…省略号.log",
    "caf\u{e9}.txt",   // é 预组合
    "cafe\u{301}.txt", // e + 组合重音（分解形式），与上一个是两个不同的文件
    "العربية.txt",
    "ไทย.txt",
];

struct Sb(PathBuf);

impl Sb {
    fn new() -> Self {
        let n = N.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("dc-uni-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Sb(fs::canonicalize(d).unwrap())
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for Sb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn populate(sb: &Sb) {
    for (i, n) in NAMES.iter().enumerate() {
        let dir = sb.p("资料库/二级目录 📁");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(n), vec![b'x'; 100 + i]).unwrap();
    }
}

#[test]
fn the_scanner_reports_every_name_exactly() {
    let sb = Sb::new();
    populate(&sb);
    let out = scanner::scan(&sb.0, &AtomicBool::new(false), &mut |_| {}).unwrap();
    let lib = &out.root.children[0];
    assert_eq!(lib.name, "资料库");
    let sub = &lib.children[0];
    assert_eq!(sub.name, "二级目录 📁");
    let mut got: Vec<&str> = sub.children.iter().map(|c| c.name.as_str()).collect();
    let mut want: Vec<&str> = NAMES.to_vec();
    got.sort();
    want.sort();
    assert_eq!(got, want, "文件名必须逐字符一致");
    assert!(
        got.iter().all(|n| !n.contains('\u{FFFD}')),
        "不能出现替换字符"
    );
    // 预组合与分解形式是两个不同的文件，不能被合并。
    assert_eq!(NAMES.iter().filter(|n| n.starts_with("caf")).count(), 2);
    assert_eq!(
        sub.children
            .iter()
            .filter(|c| c.name.starts_with("caf"))
            .count(),
        2
    );
}

#[test]
fn top_files_keep_the_full_unicode_path() {
    let sb = Sb::new();
    populate(&sb);
    let out = scanner::scan(&sb.0, &AtomicBool::new(false), &mut |_| {}).unwrap();
    let top = scanner::top_files(&sb.0, &out.root, 3);
    for (path, _) in &top {
        assert!(path.exists(), "{path:?} 必须能原样找回磁盘上的文件");
        let s = path.to_string_lossy();
        assert!(s.contains("资料库") && s.contains("二级目录 📁"));
    }
}

#[test]
fn duplicates_with_unicode_names_are_found_and_reported_verbatim() {
    let sb = Sb::new();
    let a = sb.p("备份/我的照片📷/假期 2024.jpg");
    let b = sb.p("下载/副本 - 假期 2024 (1).jpg");
    for p in [&a, &b] {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, vec![9u8; 5000]).unwrap();
    }
    let out = find_duplicates(
        &sb.0,
        &DupOptions {
            min_size: 1,
            partial_bytes: 1024,
        },
        &AtomicBool::new(false),
        &mut |_| {},
    )
    .unwrap();
    assert_eq!(out.groups.len(), 1);
    let mut paths: Vec<PathBuf> = out.groups[0].files.iter().map(|f| f.path.clone()).collect();
    paths.sort();
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(paths, want);
}

#[test]
fn copying_and_verifying_preserve_unicode_names() {
    let sb = Sb::new();
    populate(&sb);
    let dst = sb.p("目标/迁移后的目录");
    StdCopier
        .copy_tree(&sb.p("资料库"), &dst, &AtomicBool::new(false), &mut |_| {})
        .unwrap();
    verify_equal(&sb.p("资料库"), &dst).unwrap();
    let m = manifest_of(&dst).unwrap();
    for n in NAMES {
        assert!(m.contains_key(&format!("二级目录 📁/{n}")), "缺少 {n}");
    }
}

#[test]
fn cleanup_journal_keeps_unicode_paths_readable() {
    let sb = Sb::new();
    let victim = sb.p("待清理/缓存 📦/临时文件.tmp");
    fs::create_dir_all(victim.parent().unwrap()).unwrap();
    fs::write(&victim, b"junk").unwrap();
    let mut policy = SafetyPolicy::empty(PathStyle::Posix);
    policy.protect(&sb.p("保护区").to_string_lossy()).unwrap();
    let plan = Plan::from_items(
        vec![Candidate {
            rule_id: "测试".into(),
            path: victim.clone(),
            is_dir: false,
            size: 4,
            file_count: 1,
            disposal: Disposal::Permanent,
        }],
        policy,
    );
    let mut buf: Vec<u8> = Vec::new();
    let report = execute(
        &plan,
        ExecOptions::default(),
        Some(&mut buf),
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(report.freed_bytes, 4);
    let text = String::from_utf8(buf).expect("日志必须是合法 UTF-8");
    assert!(
        text.contains("临时文件.tmp") && text.contains("缓存 📦"),
        "日志里的中文要原样可读，而不是 \\uXXXX 转义: {text}"
    );
    let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(first["path"].as_str().unwrap(), victim.to_string_lossy());
}

#[test]
fn registry_backups_roundtrip_unicode_through_utf16() {
    let reg = MemRegistry::new();
    let key = r"SOFTWARE\某公司\产品 📦";
    reg.set(
        Hive::LocalMachine,
        key,
        "安装路径",
        RegValue::sz(r"D:\程序文件\我的软件"),
    );
    reg.set(Hive::LocalMachine, key, "emoji", RegValue::sz("🔥 hot"));
    reg.set(Hive::LocalMachine, key, "", RegValue::sz("默认值"));
    reg.set(
        Hive::LocalMachine,
        key,
        "多行",
        RegValue::multi_sz(&["第一", "第二 🎉"]),
    );
    let text = export_keys(&reg, &[(Hive::LocalMachine, key.to_string())]).unwrap();
    // 文本形式的字符串直接可读（不是十六进制）。
    assert!(
        text.contains(r#""安装路径"="D:\\程序文件\\我的软件""#),
        "{text}"
    );
    assert!(text.contains(r#"@="默认值""#));
    assert!(text.contains(r"[HKEY_LOCAL_MACHINE\SOFTWARE\某公司\产品 📦]"));

    // 写成 UTF-16LE + BOM 再读回，所有字符（包括需要代理对的 emoji）都应原样还原。
    let bytes = to_utf16le_with_bom(&text);
    assert_eq!(&bytes[..2], [0xFF, 0xFE]);
    let units: Vec<u16> = bytes[2..]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(String::from_utf16(&units).unwrap(), text);
    assert!(text.contains("🔥 hot"));
}

fn rule(id: &str, path: &str) -> Rule {
    Rule {
        id: id.into(),
        risk: Risk::Low,
        default_selected: true,
        disposal: Disposal::Permanent,
        targets: vec![Target {
            path: path.into(),
            kind: TargetKind::Contents,
            name_globs: vec![],
            min_age_days: 0,
        }],
        services: vec![],
    }
}

#[test]
fn rules_work_in_directories_with_unicode_names() {
    let sb = Sb::new();
    let target = sb.p("用户 数据/缓存");
    fs::create_dir_all(target.join("子目录")).unwrap();
    fs::write(target.join("子目录/文件.bin"), vec![1u8; 30]).unwrap();
    fs::write(target.join("根文件 📄.bin"), vec![1u8; 12]).unwrap();
    let env = Env::from_pairs([("BASE", sb.0.to_string_lossy())]);
    let mut policy = SafetyPolicy::empty(PathStyle::Posix);
    policy.protect(&sb.0.to_string_lossy()).unwrap();
    let plan = build_plan(
        &[rule("r", "%BASE%/用户 数据/缓存")],
        &["r"],
        &env,
        &policy,
        SystemTime::now(),
        &AtomicBool::new(false),
    );
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.total_size(), 42);
    let report = execute(
        &plan,
        ExecOptions::default(),
        None,
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert_eq!(report.freed_bytes, 42);
    assert!(target.is_dir() && fs::read_dir(&target).unwrap().count() == 0);
}

/// 不合法的文件名（Linux 上是非 UTF-8 字节，Windows 上对应未配对的代理项）：
/// 不能崩溃，不能被误删，也不能被当成别的文件。
#[cfg(unix)]
#[test]
fn invalid_encoding_in_a_file_name_is_survived_and_never_deleted() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let sb = Sb::new();
    let dir = sb.p("cache");
    fs::create_dir_all(&dir).unwrap();
    let bad: OsString =
        OsString::from_vec(vec![b'b', b'a', b'd', 0xFF, 0xFE, b'.', b't', b'm', b'p']);
    let bad_path = dir.join(&bad);
    fs::write(&bad_path, vec![7u8; 33]).unwrap();
    fs::write(dir.join("正常.tmp"), vec![7u8; 5]).unwrap();

    // 扫描：照常统计大小，名字用替换字符显示，而不是崩溃。
    let out = scanner::scan(&sb.0, &AtomicBool::new(false), &mut |_| {}).unwrap();
    assert_eq!(out.root.size, 38);
    let names: Vec<String> = out.root.children[0]
        .children
        .iter()
        .map(|c| c.name.clone())
        .collect();
    assert!(names.iter().any(|n| n.contains('\u{FFFD}')));
    assert!(names.contains(&"正常.tmp".to_string()));

    // 清理：无法做安全校验的路径被跳过并保持原样；正常文件照常处理。
    let env = Env::from_pairs([("BASE", sb.0.to_string_lossy())]);
    let mut policy = SafetyPolicy::empty(PathStyle::Posix);
    policy.protect(&sb.0.to_string_lossy()).unwrap();
    let plan = build_plan(
        &[rule("r", "%BASE%/cache")],
        &["r"],
        &env,
        &policy,
        SystemTime::now(),
        &AtomicBool::new(false),
    );
    assert!(plan
        .skipped
        .iter()
        .any(|s| s.reason == PlanSkipReason::NonUtf8Path));
    assert_eq!(plan.items.len(), 1);
    execute(
        &plan,
        ExecOptions::default(),
        None,
        &AtomicBool::new(false),
        &mut |_, _| {},
    );
    assert!(bad_path.exists(), "名字编码不合法的文件不能被删除");
    assert!(!dir.join("正常.tmp").exists());
}
