use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, CoCreateInstance, IPersistFile, STGM_READ,
};
use windows::Win32::UI::Shell::{IShellLinkW, SLGP_RAWPATH, ShellLink};
use windows::core::{Interface, PCWSTR};

use crate::domain::{
    RiskLevel, SourceKind, SourceLocator, StartupEntry, StartupScope, TriggerKind, stable_id,
};
use crate::error::{AppError, AppResult};
use crate::platform::windows::ProviderOutput;
use crate::platform::windows::shell::{
    ComApartment, known_startup_folder, to_wide, wide_buffer_to_string,
};
use crate::state::{ManagedChange, RestoreData, StateStore, default_state_path};

pub fn scan_startup_folders(store: &StateStore) -> ProviderOutput {
    let mut output = ProviderOutput::default();
    let _apartment = match ComApartment::initialize() {
        Ok(apartment) => Some(apartment),
        Err(error) => {
            output.warnings.push(format!(
                "Shortcut details are unavailable because COM could not start: {error}"
            ));
            None
        }
    };

    for common in [false, true] {
        let folder = match known_startup_folder(common) {
            Ok(folder) => folder,
            Err(error) => {
                output.warnings.push(error.to_string());
                continue;
            }
        };
        match scan_folder(&folder, common, _apartment.is_some(), &mut output.warnings) {
            Ok(mut entries) => output.entries.append(&mut entries),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => output.warnings.push(format!(
                "Could not scan {} Startup folder ({}): {error}",
                if common { "common" } else { "user" },
                folder.display()
            )),
        }
    }

    append_manager_disabled_entries(store, &mut output);
    output
}

fn scan_folder(
    folder: &Path,
    common: bool,
    can_resolve_shortcuts: bool,
    warnings: &mut Vec<String>,
) -> std::io::Result<Vec<StartupEntry>> {
    let mut entries = Vec::new();
    for item in fs::read_dir(folder)? {
        let item = match item {
            Ok(item) => item,
            Err(error) => {
                tracing::warn!(?error, folder = %folder.display(), "Startup folder item was unreadable");
                continue;
            }
        };
        let path = item.path();
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("desktop.ini"))
        {
            continue;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(?error, path = %path.display(), "Startup item metadata was unreadable");
                continue;
            }
        };
        if metadata.is_dir() {
            continue;
        }

        let entry = entry_from_path(path, common, &metadata, can_resolve_shortcuts);
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) => warnings.push(format!(
                "Could not inspect Startup item {}: {error}",
                item.path().display()
            )),
        }
    }
    Ok(entries)
}

fn entry_from_path(
    path: PathBuf,
    common: bool,
    metadata: &fs::Metadata,
    can_resolve_shortcuts: bool,
) -> std::io::Result<StartupEntry> {
    let name = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    let shortcut = can_resolve_shortcuts
        .then(|| resolve_shortcut(&path))
        .filter(|_| extension.eq_ignore_ascii_case("lnk"))
        .and_then(Result::ok);
    let (command, executable, mut description) = if let Some(shortcut) = shortcut {
        let command = if shortcut.arguments.is_empty() {
            format!(r#""{}""#, shortcut.target.display())
        } else {
            format!(r#""{}" {}"#, shortcut.target.display(), shortcut.arguments)
        };
        (
            command,
            Some(shortcut.target),
            (!shortcut.description.is_empty()).then_some(shortcut.description),
        )
    } else if extension.eq_ignore_ascii_case("url") {
        let url = read_url_shortcut(&path).unwrap_or_else(|| path.display().to_string());
        (
            url,
            None,
            Some("Internet shortcut opened at sign-in".into()),
        )
    } else {
        (format!(r#""{}""#, path.display()), Some(path.clone()), None)
    };
    if common {
        let note = "The common Startup folder is visible but read-only in v0.1.";
        match &mut description {
            Some(text) => {
                text.push(' ');
                text.push_str(note);
            }
            None => description = Some(note.into()),
        }
    }
    let target_exists = executable.as_ref().map(|target| target.exists());
    let item_fingerprint = file_fingerprint(&path, metadata)?;
    let id = startup_file_id(&path, common);

    Ok(StartupEntry {
        id,
        name: if name.is_empty() {
            "Unnamed startup item".into()
        } else {
            name
        },
        command,
        executable,
        description,
        publisher: None,
        source: SourceKind::StartupFolder,
        scope: if common {
            StartupScope::AllUsers
        } else {
            StartupScope::CurrentUser
        },
        trigger: TriggerKind::SignIn,
        risk: if common {
            RiskLevel::Review
        } else {
            RiskLevel::Normal
        },
        enabled: true,
        can_toggle: !common && metadata.is_file() && !metadata.file_type().is_symlink(),
        requires_admin: common,
        is_system: false,
        target_exists,
        fingerprint: item_fingerprint,
        locator: SourceLocator::StartupFolder { path, common },
    })
}

#[derive(Debug)]
struct ShortcutDetails {
    target: PathBuf,
    arguments: String,
    description: String,
}

fn resolve_shortcut(path: &Path) -> AppResult<ShortcutDetails> {
    // SAFETY: COM is initialized by the provider before calling this function. The returned
    // interfaces are released automatically on this same thread.
    let link: IShellLinkW = unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }
        .map_err(|error| {
            AppError::Platform(format!("Could not create Shell Link reader: {error}"))
        })?;
    let persist: IPersistFile = link
        .cast()
        .map_err(|error| AppError::Platform(format!("Could not read Shell Link: {error}")))?;
    let wide_path = to_wide(path.as_os_str());
    // SAFETY: The path is NUL-terminated and remains alive for the call.
    unsafe { persist.Load(PCWSTR(wide_path.as_ptr()), STGM_READ) }
        .map_err(|error| AppError::Platform(format!("Could not load shortcut: {error}")))?;

    let mut target = vec![0u16; 32_768];
    let mut arguments = vec![0u16; 8_192];
    let mut description = vec![0u16; 2_048];
    // SAFETY: All output slices are writable and sized as passed to the Win32 API. A null
    // WIN32_FIND_DATA pointer is explicitly allowed.
    unsafe {
        link.GetPath(&mut target, std::ptr::null_mut(), SLGP_RAWPATH.0 as u32)?;
        link.GetArguments(&mut arguments)?;
        link.GetDescription(&mut description)?;
    }

    let target = wide_buffer_to_string(&target);
    if target.is_empty() {
        return Err(AppError::Platform(
            "Shortcut has no filesystem target".into(),
        ));
    }
    Ok(ShortcutDetails {
        target: PathBuf::from(target),
        arguments: wide_buffer_to_string(&arguments),
        description: wide_buffer_to_string(&description),
    })
}

fn read_url_shortcut(path: &Path) -> Option<String> {
    let contents = fs::read_to_string(path).ok()?;
    contents.lines().find_map(|line| {
        line.strip_prefix("URL=")
            .or_else(|| line.strip_prefix("Url="))
            .map(str::trim)
            .map(str::to_owned)
    })
}

fn file_fingerprint(path: &Path, metadata: &fs::Metadata) -> std::io::Result<String> {
    let length = metadata.len().to_le_bytes();
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
        .to_le_bytes();

    // Keep the same deterministic framing as `domain::fingerprint`: each logical part is
    // followed by a NUL byte. Stream file contents so every regular file is fully covered
    // without imposing a size-dependent integrity boundary or allocating the whole file.
    let mut hasher = blake3::Hasher::new();
    hasher.update(&length);
    hasher.update(&[0]);
    hasher.update(&modified);
    hasher.update(&[0]);
    if metadata.is_file() {
        let mut file = File::open(path)?;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn append_manager_disabled_entries(store: &StateStore, output: &mut ProviderOutput) {
    for change in store.changes() {
        if !matches!(&change.restore, RestoreData::StartupFile { .. }) {
            continue;
        }
        let (original_path, parked_path) = match validate_saved_change(change) {
            Ok(paths) => paths,
            Err(error) => {
                output.warnings.push(format!(
                    "A saved Startup-folder change failed integrity checks and was ignored: {error}"
                ));
                continue;
            }
        };
        if original_path.exists() {
            output.warnings.push(format!(
                "{} now exists in its original Startup folder as well as saved history.",
                change.entry.name
            ));
            continue;
        }
        let parked_metadata = match fs::symlink_metadata(parked_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                output.warnings.push(format!(
                    "The parked file for {} is not a regular file; it cannot be restored automatically.",
                    change.entry.name
                ));
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                output.warnings.push(format!(
                    "The parked file for {} is missing; it cannot be restored automatically.",
                    change.entry.name
                ));
                continue;
            }
            Err(error) => {
                output.warnings.push(format!(
                    "The parked file for {} could not be inspected and was ignored: {error}",
                    change.entry.name
                ));
                continue;
            }
        };
        match file_fingerprint(parked_path, &parked_metadata) {
            Ok(fingerprint) if fingerprint == change.entry.fingerprint => {}
            Ok(_) => {
                output.warnings.push(format!(
                    "The parked file for {} no longer matches its saved receipt and was ignored.",
                    change.entry.name
                ));
                continue;
            }
            Err(error) => {
                output.warnings.push(format!(
                    "The parked file for {} could not be verified and was ignored: {error}",
                    change.entry.name
                ));
                continue;
            }
        }

        let mut entry = change.entry.clone();
        entry.enabled = false;
        output.entries.push(entry);
    }
}

pub fn set_startup_file_enabled(
    entry: &StartupEntry,
    enabled: bool,
    store: &mut StateStore,
) -> AppResult<()> {
    let path = validate_mutable_entry(entry)?;

    if enabled {
        restore_startup_file(entry, store)
    } else {
        disable_startup_file(entry, path, store)
    }
}

fn disable_startup_file(
    entry: &StartupEntry,
    original_path: &Path,
    store: &mut StateStore,
) -> AppResult<()> {
    let metadata = fs::symlink_metadata(original_path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => AppError::NotFound(entry.name.clone()),
        _ => AppError::from_io(error),
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AppError::ProtectedEntry);
    }
    if file_fingerprint(original_path, &metadata).map_err(AppError::from_io)? != entry.fingerprint {
        return Err(AppError::StaleEntry);
    }

    let parked_path = parked_path_for(entry, original_path)?;
    if parked_path.exists() {
        return Err(AppError::RestoreConflict(parked_path.display().to_string()));
    }
    if let Some(parent) = parked_path.parent() {
        fs::create_dir_all(parent).map_err(AppError::from_io)?;
    }

    store.add(ManagedChange::new(
        entry.clone(),
        RestoreData::StartupFile {
            original_path: original_path.to_path_buf(),
            parked_path: parked_path.clone(),
        },
    ))?;

    if let Err(error) = fs::rename(original_path, &parked_path) {
        let _ = store.remove(&entry.id);
        return Err(AppError::from_io(error));
    }
    Ok(())
}

fn restore_startup_file(entry: &StartupEntry, store: &mut StateStore) -> AppResult<()> {
    let change = store
        .find(&entry.id)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("saved state for {}", entry.name)))?;
    if change.id != entry.id || change.entry.id != entry.id {
        return Err(AppError::ProtectedEntry);
    }
    let (original_path, parked_path) = validate_saved_change(&change)?;
    if !same_entry_provenance(entry, &change.entry) {
        return Err(AppError::ProtectedEntry);
    }
    if original_path.exists() {
        return Err(AppError::RestoreConflict(
            original_path.display().to_string(),
        ));
    }
    let parked_metadata =
        fs::symlink_metadata(parked_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => AppError::NotFound(parked_path.display().to_string()),
            _ => AppError::from_io(error),
        })?;
    if !parked_metadata.is_file() || parked_metadata.file_type().is_symlink() {
        return Err(AppError::ProtectedEntry);
    }
    if file_fingerprint(parked_path, &parked_metadata).map_err(AppError::from_io)?
        != change.entry.fingerprint
    {
        return Err(AppError::StaleEntry);
    }
    fs::rename(parked_path, original_path).map_err(AppError::from_io)?;
    store.remove(&entry.id)?;
    Ok(())
}

fn validate_saved_change(change: &ManagedChange) -> AppResult<(&Path, &Path)> {
    if change.id != change.entry.id {
        return Err(AppError::ProtectedEntry);
    }
    let entry = &change.entry;
    let SourceLocator::StartupFolder {
        path: saved_locator,
        common,
    } = &entry.locator
    else {
        return Err(AppError::ProtectedEntry);
    };
    // v0.1 deliberately never mutates the all-users Startup folder, even if an elevated
    // process or a hand-edited journal claims that an entry is recoverable.
    if *common {
        return Err(AppError::ProtectedEntry);
    }
    validate_entry_provenance(entry)?;
    if !entry.enabled || !entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    let RestoreData::StartupFile {
        original_path,
        parked_path,
    } = &change.restore
    else {
        return Err(AppError::ProtectedEntry);
    };
    if !paths_equal(original_path, saved_locator) {
        return Err(AppError::ProtectedEntry);
    }

    let expected_parked_path = parked_path_for(entry, original_path)?;
    if !paths_equal(parked_path, &expected_parked_path) {
        return Err(AppError::ProtectedEntry);
    }
    Ok((original_path, parked_path))
}

fn validate_mutable_entry(entry: &StartupEntry) -> AppResult<&Path> {
    let SourceLocator::StartupFolder { path, common } = &entry.locator else {
        return Err(AppError::ProtectedEntry);
    };
    if *common || !entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    validate_entry_provenance(entry)?;
    Ok(path)
}

fn validate_entry_provenance(entry: &StartupEntry) -> AppResult<()> {
    let SourceLocator::StartupFolder { path, common } = &entry.locator else {
        return Err(AppError::ProtectedEntry);
    };
    let expected_scope = if *common {
        StartupScope::AllUsers
    } else {
        StartupScope::CurrentUser
    };
    let expected_risk = if *common {
        RiskLevel::Review
    } else {
        RiskLevel::Normal
    };
    if entry.id != startup_file_id(path, *common)
        || entry.source != SourceKind::StartupFolder
        || entry.scope != expected_scope
        || entry.trigger != TriggerKind::SignIn
        || entry.risk != expected_risk
        || entry.requires_admin != *common
        || entry.is_system
        || entry.fingerprint.len() != 64
        || !entry
            .fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(AppError::ProtectedEntry);
    }
    validate_startup_path(path, *common)
}

fn same_entry_provenance(request: &StartupEntry, receipt: &StartupEntry) -> bool {
    request.id == receipt.id
        && request.source == receipt.source
        && request.scope == receipt.scope
        && request.trigger == receipt.trigger
        && request.risk == receipt.risk
        && request.requires_admin == receipt.requires_admin
        && request.is_system == receipt.is_system
        && request.fingerprint == receipt.fingerprint
        && request.locator == receipt.locator
}

fn startup_file_id(path: &Path, common: bool) -> String {
    stable_id(&[
        "startup-file",
        if common { "common" } else { "user" },
        &path.to_string_lossy().to_lowercase(),
    ])
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn parked_path_for(entry: &StartupEntry, original_path: &Path) -> AppResult<PathBuf> {
    let data_dir = default_state_path()
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| AppError::Platform("Could not resolve app data directory".into()))?;
    let file_name = original_path
        .file_name()
        .ok_or_else(|| AppError::Platform("Startup item has no file name".into()))?;
    Ok(data_dir.join("disabled").join(&entry.id).join(file_name))
}

fn validate_startup_path(path: &Path, common: bool) -> AppResult<()> {
    let expected = known_startup_folder(common)?;
    let Some(parent) = path.parent() else {
        return Err(AppError::ProtectedEntry);
    };
    if !paths_equal(parent, &expected) {
        return Err(AppError::ProtectedEntry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::domain::fingerprint;

    fn temporary_file(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "win-startup-manager-{label}-{}-{nonce}.cmd",
            std::process::id()
        ))
    }

    #[test]
    fn streamed_fingerprint_preserves_framing_for_large_files() {
        let path = temporary_file("fingerprint");
        let contents = (0..(2 * 1024 * 1024 + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        fs::write(&path, &contents).expect("write test file");
        let metadata = fs::symlink_metadata(&path).expect("read test metadata");
        let length = metadata.len().to_le_bytes();
        let modified = metadata
            .modified()
            .expect("read modification time")
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes();

        let actual = file_fingerprint(&path, &metadata).expect("fingerprint test file");
        let expected = fingerprint(&[&length, &modified, &contents]);

        fs::remove_file(&path).expect("remove test file");
        assert_eq!(actual, expected);
    }

    #[test]
    fn common_startup_receipts_are_always_read_only() {
        let path = temporary_file("common-read-only");
        fs::write(&path, b"@exit /b 0\r\n").expect("write test file");
        let metadata = fs::symlink_metadata(&path).expect("read test metadata");
        let entry = entry_from_path(path.clone(), true, &metadata, false).expect("build entry");

        assert!(!entry.can_toggle);
        assert!(matches!(
            validate_mutable_entry(&entry),
            Err(AppError::ProtectedEntry)
        ));

        let change = ManagedChange::new(
            entry,
            RestoreData::StartupFile {
                original_path: path.clone(),
                parked_path: path.with_extension("parked"),
            },
        );
        assert!(matches!(
            validate_saved_change(&change),
            Err(AppError::ProtectedEntry)
        ));

        fs::remove_file(&path).expect("remove test file");
    }
}
