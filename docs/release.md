# 发布与签名

## 构建安装包

```powershell
cd app
npm ci
npm run tauri build
```

产物在 `target/release/bundle/`：`nsis/*.exe`。发布版的可执行文件内嵌
`requireAdministrator` manifest，启动时会弹出 UAC。

macOS：

```bash
cd app
npm ci
npm run tauri build -- --target universal-apple-darwin
```

产物在 `target/universal-apple-darwin/release/bundle/dmg/*.dmg`（`tauri.macos.conf.json` 只在 macOS 上生效，
指定 dmg 目标、最低系统 11.0 与 ad-hoc 签名）。macOS 版**没有**管理员 manifest，应用以普通用户运行；
需要管理员的少数系统动作（如精简 Time Machine 快照）会通过系统授权对话框单独请求。

持续集成（`.github/workflows/ci.yml`）在每次推送时：
- Linux：`cargo fmt`、`clippy -D warnings`、全部 Rust 测试、前端类型检查与测试、前端构建；
- Windows：全部 Rust 测试（独立任务）并构建**未签名**的安装包，作为构建产物上传；
- macOS：全部 Rust 测试（独立任务）并构建**通用**（arm64 + x86_64）的 .dmg，ad-hoc 签名但未经公证；
- 发布（`v*` 标签，或主分支上以 `release:` 开头的提交）：只要 Windows 安装包成功就发布，macOS 的 .dmg 成功时一并附上。

## 代码签名

未签名的安装包会触发 SmartScreen 警告，对外发布前需要签名。

1. 取得代码签名证书（OV 或 EV；EV 能更快建立 SmartScreen 信誉）。
2. 本地签名：在 `app/src-tauri/tauri.conf.json` 的 `bundle.windows` 中配置
   `certificateThumbprint`（证书已导入本机证书库）、`digestAlgorithm: "sha256"` 与 `timestampUrl`。
3. 在 CI 中签名：把证书（PFX，base64）与密码放进仓库 Secrets，构建前导入证书库，
   再通过上面的 `certificateThumbprint` 引用。**不要把证书或密码提交到仓库。**
4. 云端签名服务（如 Azure Trusted Signing）可通过 `bundle.windows.signCommand` 接入。

签名后用 `signtool verify /pa <安装包>` 验证。

## macOS 签名与公证

ad-hoc 签名只能保证 Apple 芯片上能启动，用户下载后仍会被 Gatekeeper 拦截。对外发布需要：

1. Apple Developer 账号与 **Developer ID Application** 证书；
2. 在 CI 的 Secrets 里放证书（base64 的 .p12）与密码，导入临时钥匙串，
   并设置 `APPLE_SIGNING_IDENTITY`（覆盖 `signingIdentity: "-"`）；
3. 公证：设置 `APPLE_ID`、`APPLE_PASSWORD`（App 专用密码）与 `APPLE_TEAM_ID`，Tauri 构建时会自动提交公证并装订票据。

**不要把证书或密码提交到仓库。**
