# 发布与签名

## 构建安装包

```powershell
cd app
npm ci
npm run tauri build
```

产物在 `target/release/bundle/`：`nsis/*.exe` 与 `msi/*.msi`。发布版的可执行文件内嵌
`requireAdministrator` manifest，启动时会弹出 UAC。

持续集成（`.github/workflows/ci.yml`）在每次推送时：
- Linux：`cargo fmt`、`clippy -D warnings`、全部 Rust 测试、前端类型检查与测试、前端构建；
- Windows：全部 Rust 测试并构建**未签名**的安装包，作为构建产物上传。

## 代码签名

未签名的安装包会触发 SmartScreen 警告，对外发布前需要签名。

1. 取得代码签名证书（OV 或 EV；EV 能更快建立 SmartScreen 信誉）。
2. 本地签名：在 `app/src-tauri/tauri.conf.json` 的 `bundle.windows` 中配置
   `certificateThumbprint`（证书已导入本机证书库）、`digestAlgorithm: "sha256"` 与 `timestampUrl`。
3. 在 CI 中签名：把证书（PFX，base64）与密码放进仓库 Secrets，构建前导入证书库，
   再通过上面的 `certificateThumbprint` 引用。**不要把证书或密码提交到仓库。**
4. 云端签名服务（如 Azure Trusted Signing）可通过 `bundle.windows.signCommand` 接入。

签名后用 `signtool verify /pa <安装包>` 验证。
