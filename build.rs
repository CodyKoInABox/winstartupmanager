#[cfg(windows)]
mod app_icon {
    include!("src/icon.rs");
}

#[cfg(windows)]
fn main() {
    use std::fs::File;
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=src/icon.rs");
    println!("cargo:rerun-if-changed=assets/wsm_logo.png");
    let output_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let icon_path = output_dir.join("win-startup-manager.ico");
    let mut directory = ico::IconDir::new(ico::ResourceType::Icon);
    for size in [16, 24, 32, 48, 64, 128, 256] {
        let image = ico::IconImage::from_rgba_data(size, size, app_icon::app_icon_rgba(size));
        directory.add_entry(ico::IconDirEntry::encode(&image).expect("app icon should encode"));
    }
    directory
        .write(File::create(&icon_path).expect("app icon file should be created"))
        .expect("app icon file should be written");

    let manifest = r#"
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;

    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon(icon_path.to_str().expect("icon path should be Unicode"))
        .set("FileDescription", "Win Startup Manager")
        .set("ProductName", "Win Startup Manager")
        .set(
            "LegalCopyright",
            "Copyright (c) 2026 Maruan Biasi El Achkar",
        )
        .set_manifest(manifest);
    resource
        .compile()
        .expect("Windows resources should compile");
}

#[cfg(not(windows))]
fn main() {}
