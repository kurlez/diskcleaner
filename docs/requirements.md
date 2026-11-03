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
| M2 | 规则引擎 + Windows 规则集；预览/执行/回收站/日志/dry-run | 完成（待 Windows 真机验证） |
| M3 | Tauri GUI（概览、扫描、目录树、清理向导、报告，中英双语） | 完成（待 Windows 真机验证） |
| M4 | MFT 快速扫描；treemap；设置页 | 待做 |
| M5 | 重复文件、USN 增量、系统工具封装；打包签名 | 待做 |

## M2 设计要点
- 规则 = 路径模板（`%VAR%`、目录名通配符）+ 名称过滤 + 最小年龄 + 风险等级 + 删除方式。
- 流程：`build_plan`（只读）→ 用户确认 → `execute`（逐项二次校验、先写日志再删除）。
- 展开路径时：基路径取规范长路径（环境变量常含 8.3 短名）；途中任一级是链接/junction 的目标直接丢弃。
- 计划项含受保护名称（`.git` 等）或云占位文件则整项跳过；修改时间取子树内最新者。
- 用户排除项（`SafetyPolicy::exclude`）优先级最高，规则的允许根无法覆盖。
- 操作日志为 JSON Lines（`intent` 在前，`result` 在后）；日志写不进去则中止，不做"无日志删除"。
- 回收站不释放空间：报告分开统计 `freed_bytes` 与 `recycled_bytes`；
  内置规则清理的都是可再生数据，默认 `Permanent`，可用 `--recycle` 覆盖。
- 未纳入 M2：清空回收站、`Windows.old`、`DISM`、休眠文件、卷影副本、停止 `wuauserv`（M5 的"系统动作"）。

## M3 设计要点
- 结构：`app/src-tauri`（Tauri 2 后端）+ `app/`（Svelte 5 + TS + Vite 前端）。
  后端逻辑集中在 `service.rs`（与 Tauri 无关，可单测），`lib.rs` 只做命令封装。
- **前端只能提交规则 ID**；真正要删除的路径始终来自后端保存的计划，且计划一次性有效。
- 长任务（扫描、分析、执行）在阻塞线程池运行，通过 `scan-progress` / `clean-progress` 事件推送进度，可取消。
- 扫描结果保留在后端，目录树按需懒加载（每层最多 1000 项）。
- 错误以 `{code, detail}` 返回，由前端按 `err.<code>` 翻译。
- i18n：`zh` / `en` 两套词典，单测校验键集合、占位符一致，且覆盖所有规则、跳过原因与错误码。
- 管理员权限：发布版（release）嵌入 `requireAdministrator` manifest；开发版不加，否则 `tauri dev` 无法启动。
- 安全：严格 CSP；capabilities 只开放事件监听；前端不加载任何外部资源。
- 浏览器里 `npm run dev` 会使用 `lib/mock.ts` 的模拟数据预览界面；发布版不含 mock。
- 暂未做：treemap 可视化与 MFT 快速扫描（M4）、"清空回收站"等系统动作（M5）。
