use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Startup, KF_FLAG_DEFAULT, SHGetKnownFolderPath, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

use crate::domain::{expand_environment, extract_executable};
use crate::error::{AppError, AppResult};

pub(crate) struct ComApartment;

impl ComApartment {
    pub(crate) fn initialize() -> AppResult<Self> {
        // SAFETY: This is called on dedicated worker threads before any other COM call. The
        // matching CoUninitialize is owned by this guard.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }
            .map_err(|error| AppError::Platform(format!("Could not initialize COM: {error}")))?;
        Ok(Self)
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: A successful CoInitializeEx call created this guard on the same thread.
        unsafe { CoUninitialize() };
    }
}

pub(crate) fn known_startup_folder(common: bool) -> AppResult<PathBuf> {
    let folder_id = if common {
        &FOLDERID_CommonStartup
    } else {
        &FOLDERID_Startup
    };

    // SAFETY: SHGetKnownFolderPath allocates a NUL-terminated path for the requested well-known
    // folder. It is copied immediately and released with CoTaskMemFree below.
    let raw =
        unsafe { SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT, None) }.map_err(|error| {
            AppError::Platform(format!("Could not resolve Startup folder: {error}"))
        })?;
    // SAFETY: `raw` points to the NUL-terminated string returned above.
    let result = unsafe { raw.to_string() }
        .map(PathBuf::from)
        .map_err(|error| AppError::Platform(format!("Startup folder path is invalid: {error}")));
    // SAFETY: The pointer was allocated by SHGetKnownFolderPath.
    unsafe { CoTaskMemFree(Some(raw.0.cast())) };
    result
}

pub(crate) fn to_wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn wide_buffer_to_string(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

pub(crate) fn normalized_executable(command: &str) -> Option<PathBuf> {
    extract_executable(&expand_environment(command)).map(|path| {
        let raw = path.to_string_lossy();
        if let Some(stripped) = raw.strip_prefix(r"\??\") {
            PathBuf::from(stripped)
        } else {
            path
        }
    })
}

pub(crate) fn is_windows_component(command: &str) -> bool {
    let expanded = expand_environment(command).to_ascii_lowercase();
    let system_root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_ascii_lowercase();
    let known_system_images = [
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "wininit.exe",
        "smss.exe",
        "csrss.exe",
    ];

    expanded.contains(&format!(r"{}\system32\", system_root))
        || expanded.contains(r"%systemroot%\system32\")
        || expanded.contains(r"\windows\system32\")
        || known_system_images
            .iter()
            .any(|image| expanded.trim_matches('"').starts_with(image))
}

pub fn is_process_elevated() -> bool {
    is_elevated::is_elevated()
}

pub fn restart_elevated() -> AppResult<()> {
    let executable = std::env::current_exe()?;
    let executable = to_wide(executable.as_os_str());
    let operation = to_wide("runas");

    // SAFETY: All strings are NUL-terminated and remain alive for the duration of the call.
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(executable.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        return Err(AppError::Platform(format!(
            "Windows did not start the elevated process (ShellExecute code {})",
            result.0 as isize
        )));
    }
    Ok(())
}

pub fn reveal_in_explorer(path: &Path) -> AppResult<()> {
    let argument = if path.is_dir() {
        path.as_os_str().to_os_string()
    } else {
        format!(r#"/select,"{}""#, path.display()).into()
    };
    Command::new("explorer.exe")
        .arg(argument)
        .spawn()
        .map(|_| ())
        .map_err(AppError::from_io)
}

pub fn open_startup_settings() -> AppResult<()> {
    let operation = to_wide("open");
    let target = to_wide("ms-settings:startupapps");
    // SAFETY: All strings are NUL-terminated and remain alive for the duration of the call.
    let result = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(operation.as_ptr()),
            PCWSTR(target.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if result.0 as isize <= 32 {
        Err(AppError::Platform(
            "Could not open Windows Startup settings".into(),
        ))
    } else {
        Ok(())
    }
}
