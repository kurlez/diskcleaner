# 磁盘清理工具 需求设计 v0.3

## 已确认决策
- 平台：仅 Windows 10 22H2 / Windows 11（不支持更老版本）
- 形态：桌面 GUI，Tauri 2（Rust 后端）+ Svelte + TypeScript
- 界面语言：中英双语（i18n）
- 权限：MVP 采用方案 A —— manifest `requireAdministrator`，整个应用以管理员运行
  - 前端只加载本地打包资源，禁用外部导航；Tauri capabilities 最小化
  - 后续可演进为方案 B（普通权限主程序 + 提权 helper，命名管道通信）

## 工程结构
- `crates/core`：路径安全、扫描、规则、清理编排（与 GUI 解耦，可在任意平台单测）
- `crates/cli`：调试/测试入口
- `app/`（M3）：Tauri + Svelte

## 功能（优先级）
**P0（MVP）**：磁盘概览；扫描与分析（目录树、Top N、treemap）；Windows 规则集一键清理
（用户/系统临时文件、回收站、缩略图缓存、崩溃转储、Windows 更新下载缓存、传递优化缓存、
浏览器缓存、开发者缓存、旧日志、Windows.old）；预览→确认→执行→报告；保护名单、dry-run、
操作日志、历史与恢复；设置（排除路径、规则开关、过期天数）。

**P1**：重复文件；USN Journal 增量扫描；系统工具封装（休眠文件、还原点/卷影副本、
`DISM /StartComponentCleanup`，禁止手动删 WinSxS）；卸载残留。

**P2**：定时清理、低空间提醒、自定义规则（YAML）。

## 硬性安全约束
1. 保护名单默认拒绝：系统目录、Program Files、ProgramData、用户配置文件及文档/桌面/图片等；
   仅更具体的"允许根"（如 `C:\Windows\Temp`）内部可删（已在 `safety.rs` 实现并测试）。
2. 不跟随重解析点（symlink/junction/挂载点）。
3. 跳过 OneDrive 等云占位文件。
4. 硬链接不重复计数；长路径用 `\\?\`；处理 ADS。
5. 被占用文件跳过并记录，不强杀进程。
6. 删除前二次校验路径（防 TOCTOU）；调用方须先取规范长路径（8.3 短名会被拒绝）。
7. 默认移入回收站；永久删除需单独确认。
8. 全程本地，不联网。

## 非功能
- 1TB NTFS：MFT 扫描 ≤ 30 秒出完整树；遍历模式几分钟内先出部分结果
- 后台线程 + 事件流，UI 不卡顿
- 清理前写 intent log，崩溃后可追溯
- 发布：MSI/NSIS + 代码签名

## 里程碑
| 阶段 | 内容 | 状态 |
|---|---|---|
| M1 | workspace、路径安全模块、遍历扫描器、CLI | 完成 |
| M2 | 规则引擎 + Windows 规则集；预览/执行/回收站/日志/dry-run | 待做 |
| M3 | Tauri GUI（概览、扫描、目录树、清理向导、报告，中英双语） | 待做 |
| M4 | MFT 快速扫描；treemap；设置页 | 待做 |
| M5 | 重复文件、USN 增量、系统工具封装；打包签名 | 待做 |
