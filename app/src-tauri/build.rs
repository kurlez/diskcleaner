// 发布版要求管理员权限（UAC 弹窗）。开发版不加，否则 `tauri dev` 无法直接启动。
const ADMIN_MANIFEST: &str = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

fn main() {
    let mut attrs = tauri_build::Attributes::new();
    let target_windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let release = std::env::var("PROFILE").as_deref() == Ok("release");
    if target_windows && release {
        attrs = attrs
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(ADMIN_MANIFEST));
    }
    tauri_build::try_build(attrs).expect("failed to run tauri-build");
}
