# DiskClean

Windows 磁盘清理工具：Rust 核心 + Tauri 2 桌面界面 + Svelte 前端，中英双语，发布版以管理员权限运行。
需求与设计见 [docs/requirements.md](docs/requirements.md)。

## 开发

核心库与命令行（任意平台可测试）：

```bash
cargo test
cargo run -p diskclean-cli -- rules
```

桌面应用（Windows，需要 Rust、Node 20+ 和 WebView2）：

```bash
cd app
npm install
npm run tauri dev      # 开发版，不要求管理员
npm run tauri build    # 发布版，生成 NSIS/MSI，运行时弹 UAC
```

仅预览界面（任意平台，使用模拟数据）：

```bash
cd app && npm install && npm run dev
```

检查：`npm run check`（类型）、`npm test`（前端单测）。
