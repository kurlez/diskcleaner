//! 用户设置（目前只有排除路径），以 JSON 保存在应用配置目录。

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub exclusions: Vec<String>,
}

impl Settings {
    /// 文件不存在或损坏时回退默认值（损坏的设置不应该让程序打不开）。
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// 先写临时文件再改名，避免写到一半崩溃留下半个文件。
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )?;
        fs::rename(&tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_fallbacks() {
        let dir = std::env::temp_dir().join(format!("dc-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("sub/settings.json");

        assert_eq!(Settings::load(&file), Settings::default());

        let s = Settings {
            exclusions: vec![r"D:\keep".into()],
        };
        s.save(&file).unwrap();
        assert_eq!(Settings::load(&file), s);

        fs::write(&file, "{ not json").unwrap();
        assert_eq!(Settings::load(&file), Settings::default());
        fs::remove_dir_all(&dir).unwrap();
    }
}
