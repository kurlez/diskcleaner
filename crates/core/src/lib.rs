//! diskclean 核心库：路径安全、扫描、（后续）规则与清理。与 GUI 解耦。

pub mod builtin;
pub mod cleaner;
pub mod cloud;
pub mod duplicates;
pub mod macapps;
pub mod mft;
pub mod migrate;
pub mod plan;
pub mod procs;
pub mod registry;
pub mod rules;
pub mod safety;
pub mod scanner;
pub mod sysaction;
pub mod uninstall;

/// 把字节数格式化为人类可读形式（1024 进制）。
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::format_size;

    #[test]
    fn formats_sizes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(5 * 1024 * 1024 * 1024), "5.0 GB");
    }
}
