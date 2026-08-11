use std::collections::HashMap;
use std::mem::size_of;
use std::slice;

use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW,
    ENUM_SERVICE_TYPE, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfig2W, QueryServiceConfigW, SC_ENUM_PROCESS_INFO, SC_HANDLE, SC_MANAGER_CONNECT,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_CONFIG_LAUNCH_PROTECTED,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START, SERVICE_ERROR,
    SERVICE_LAUNCH_PROTECTED_INFO, SERVICE_LAUNCH_PROTECTED_NONE, SERVICE_NO_CHANGE,
    SERVICE_QUERY_CONFIG, SERVICE_START_TYPE, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::core::PCWSTR;

use crate::domain::{
    RiskLevel, SourceKind, SourceLocator, StartupEntry, StartupScope, TriggerKind, fingerprint,
    stable_id,
};
use crate::error::{AppError, AppResult};
use crate::platform::windows::ProviderOutput;
use crate::platform::windows::shell::{is_windows_component, normalized_executable, to_wide};
use crate::state::{ManagedChange, RestoreData, StateStore};

struct OwnedScHandle(SC_HANDLE);

impl Drop for OwnedScHandle {
    fn drop(&mut self) {
        // SAFETY: This handle was returned by an SCM API and is owned by this guard.
        let _ = unsafe { CloseServiceHandle(self.0) };
    }
}

#[derive(Debug)]
struct ServiceConfig {
    binary_path: String,
    account: String,
    start_type: SERVICE_START_TYPE,
    delayed_auto_start: bool,
    launch_protected: bool,
    dependency_count: usize,
}

pub fn scan_services(store: &StateStore) -> ProviderOutput {
    match enumerate_services(store) {
        Ok(output) => output,
        Err(error) => ProviderOutput::warning(format!("Services scan failed: {error}")),
    }
}

fn enumerate_services(store: &StateStore) -> AppResult<ProviderOutput> {
    // SAFETY: Null machine/database names mean the active local SCM database.
    let manager = OwnedScHandle(
        unsafe {
            OpenSCManagerW(
                PCWSTR::null(),
                PCWSTR::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE,
            )
        }
        .map_err(map_windows_error)?,
    );

    let managed_changes: HashMap<String, &ManagedChange> = store
        .changes()
        .iter()
        .filter_map(|change| match &change.restore {
            RestoreData::Service { service_name, .. } => {
                Some((service_name.to_ascii_lowercase(), change))
            }
            _ => None,
        })
        .collect();

    let mut needed = 0;
    let mut returned = 0;
    // SAFETY: The first call intentionally supplies no buffer to obtain the required byte size.
    let first = unsafe {
        EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        )
    };
    if needed == 0 {
        first.map_err(map_windows_error)?;
        return Ok(ProviderOutput::default());
    }

    let mut buffer = words_for_bytes(needed);
    // SAFETY: The usize-backed allocation is aligned for the structures returned by the API.
    let bytes = words_as_bytes(&mut buffer);
    unsafe {
        EnumServicesStatusExW(
            manager.0,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            Some(bytes),
            &mut needed,
            &mut returned,
            None,
            PCWSTR::null(),
        )
    }
    .map_err(map_windows_error)?;

    // SAFETY: EnumServicesStatusExW wrote `returned` consecutive structures into this aligned
    // buffer. The referenced strings remain valid while the buffer lives.
    let statuses = unsafe {
        slice::from_raw_parts(
            buffer.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(),
            returned as usize,
        )
    };
    let mut output = ProviderOutput::default();

    for status in statuses {
        // SAFETY: Both pointers are owned by the live enumeration buffer and NUL-terminated.
        let name = match unsafe { status.lpServiceName.to_string() } {
            Ok(name) => name,
            Err(error) => {
                output
                    .warnings
                    .push(format!("A service name was unreadable: {error}"));
                continue;
            }
        };
        let display_name =
            unsafe { status.lpDisplayName.to_string() }.unwrap_or_else(|_| name.clone());
        let name_wide = to_wide(&name);
        // SAFETY: The service name is NUL-terminated and the manager handle is live.
        let service = match unsafe {
            OpenServiceW(manager.0, PCWSTR(name_wide.as_ptr()), SERVICE_QUERY_CONFIG)
        } {
            Ok(handle) => OwnedScHandle(handle),
            Err(error) => {
                tracing::debug!(service = name, ?error, "service config is inaccessible");
                continue;
            }
        };
        let config = match query_service_config(service.0) {
            Ok(config) => config,
            Err(error) => {
                tracing::debug!(
                    service = name,
                    ?error,
                    "service config could not be queried"
                );
                continue;
            }
        };
        let current_fingerprint = service_fingerprint(&config);
        let managed_change = managed_changes.get(&name.to_ascii_lowercase()).copied();
        let expected_disabled_fingerprint =
            managed_change.and_then(|change| match &change.restore {
                RestoreData::Service {
                    disabled_fingerprint,
                    ..
                } => disabled_fingerprint.as_deref(),
                _ => None,
            });
        let manager_disabled = expected_disabled_fingerprint == Some(current_fingerprint.as_str());
        let returned_to_original =
            managed_change.is_some_and(|change| change.entry.fingerprint == current_fingerprint);
        let recovery_conflict =
            managed_change.is_some() && !manager_disabled && !returned_to_original;
        if config.start_type != SERVICE_AUTO_START && managed_change.is_none() {
            continue;
        }

        output.entries.push(entry_from_service(
            name,
            display_name,
            config,
            manager_disabled,
            recovery_conflict,
        ));
    }
    Ok(output)
}

fn entry_from_service(
    name: String,
    display_name: String,
    config: ServiceConfig,
    manager_disabled: bool,
    recovery_conflict: bool,
) -> StartupEntry {
    let executable = normalized_executable(&config.binary_path);
    let target_exists = executable.as_ref().map(|path| path.exists());
    let protected = config.launch_protected
        || is_windows_component(&config.binary_path)
        || is_per_user_service(&name);
    let start_bytes = config.start_type.0.to_le_bytes();
    let delayed_byte = [u8::from(config.delayed_auto_start)];
    let service_fingerprint = fingerprint(&[
        config.binary_path.as_bytes(),
        config.account.as_bytes(),
        &start_bytes,
        &delayed_byte,
    ]);
    let mut description = if manager_disabled {
        "Win Startup Manager changed this service to Manual. Its original automatic mode is saved and can be restored.".to_owned()
    } else {
        "This background service starts with Windows. Turning it off changes its next-boot mode to Manual; it does not stop the currently running service.".to_owned()
    };
    if config.dependency_count > 0 {
        description.push_str(&format!(
            " Windows reports {} service {}.",
            config.dependency_count,
            if config.dependency_count == 1 {
                "dependency"
            } else {
                "dependencies"
            }
        ));
    }
    if is_per_user_service(&name) {
        description
            .push_str(" This appears to be a per-user service instance and is locked for safety.");
    }
    if recovery_conflict {
        description.push_str(
            " The service changed outside Win Startup Manager after it was prevented. It is locked to avoid overwriting the administrator's newer configuration; use the saved recovery record for manual resolution.",
        );
    }

    StartupEntry {
        id: stable_id(&["service", &name.to_ascii_lowercase()]),
        name: if display_name.trim().is_empty() {
            name.clone()
        } else {
            display_name
        },
        command: config.binary_path,
        executable,
        description: Some(description),
        publisher: None,
        source: SourceKind::Service,
        scope: StartupScope::System,
        trigger: if config.delayed_auto_start {
            TriggerKind::DelayedService
        } else {
            TriggerKind::AutomaticService
        },
        risk: if protected {
            RiskLevel::Protected
        } else {
            RiskLevel::Caution
        },
        enabled: config.start_type == SERVICE_AUTO_START,
        can_toggle: !protected && !recovery_conflict,
        requires_admin: true,
        is_system: protected,
        target_exists,
        fingerprint: service_fingerprint,
        locator: SourceLocator::Service { name },
    }
}

fn query_service_config(service: SC_HANDLE) -> AppResult<ServiceConfig> {
    let mut needed = 0;
    // SAFETY: This sizing call intentionally passes no output buffer.
    let first = unsafe { QueryServiceConfigW(service, None, 0, &mut needed) };
    if needed == 0 {
        return Err(first
            .expect_err("zero-sized QUERY_SERVICE_CONFIGW should not succeed")
            .into());
    }
    let mut buffer = words_for_bytes(needed);
    // SAFETY: The allocation is aligned and at least `needed` bytes long.
    unsafe {
        QueryServiceConfigW(
            service,
            Some(buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            std::mem::size_of_val(buffer.as_slice()) as u32,
            &mut needed,
        )
    }
    .map_err(map_windows_error)?;
    // SAFETY: QueryServiceConfigW initialized a QUERY_SERVICE_CONFIGW at the start of the buffer.
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    // SAFETY: These pointers refer into the live configuration buffer and are NUL-terminated.
    let binary_path = unsafe { config.lpBinaryPathName.to_string() }
        .map_err(|error| AppError::Platform(format!("Invalid service path: {error}")))?;
    let account = unsafe { config.lpServiceStartName.to_string() }.unwrap_or_default();
    let dependency_count = unsafe { count_multi_sz(config.lpDependencies.0) };

    let mut delayed = SERVICE_DELAYED_AUTO_START_INFO::default();
    // SAFETY: The byte slice covers exactly the writable fixed-size output structure.
    let delayed_bytes = unsafe {
        slice::from_raw_parts_mut(
            (&mut delayed as *mut SERVICE_DELAYED_AUTO_START_INFO).cast::<u8>(),
            size_of::<SERVICE_DELAYED_AUTO_START_INFO>(),
        )
    };
    let mut delayed_needed = 0;
    // SAFETY: The buffer and byte count match SERVICE_DELAYED_AUTO_START_INFO.
    let delayed_auto_start = unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Some(delayed_bytes),
            &mut delayed_needed,
        )
        .is_ok()
            && delayed.fDelayedAutostart.as_bool()
    };

    let mut protected = SERVICE_LAUNCH_PROTECTED_INFO::default();
    // SAFETY: The byte slice covers exactly the writable fixed-size output structure.
    let protected_bytes = unsafe {
        slice::from_raw_parts_mut(
            (&mut protected as *mut SERVICE_LAUNCH_PROTECTED_INFO).cast::<u8>(),
            size_of::<SERVICE_LAUNCH_PROTECTED_INFO>(),
        )
    };
    let mut protected_needed = 0;
    // SAFETY: The buffer and byte count match SERVICE_LAUNCH_PROTECTED_INFO.
    let launch_protected = unsafe {
        QueryServiceConfig2W(
            service,
            SERVICE_CONFIG_LAUNCH_PROTECTED,
            Some(protected_bytes),
            &mut protected_needed,
        )
        .is_ok()
            && protected.dwLaunchProtected != SERVICE_LAUNCH_PROTECTED_NONE
    };

    Ok(ServiceConfig {
        binary_path,
        account,
        start_type: config.dwStartType,
        delayed_auto_start,
        launch_protected,
        dependency_count,
    })
}

pub fn set_service_enabled(
    entry: &StartupEntry,
    enabled: bool,
    store: &mut StateStore,
) -> AppResult<()> {
    if !entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    let SourceLocator::Service { name } = &entry.locator else {
        return Err(AppError::Platform("Invalid service locator".into()));
    };
    if name.contains('\0') || name.is_empty() {
        return Err(AppError::ProtectedEntry);
    }

    if enabled {
        restore_service(entry, name, store)
    } else {
        disable_service(entry, name, store)
    }
}

fn disable_service(entry: &StartupEntry, name: &str, store: &mut StateStore) -> AppResult<()> {
    let config = query_named_service(name, SERVICE_QUERY_CONFIG)?;
    let original_fingerprint = service_fingerprint(&config);
    if let Some(existing) = store.find(&entry.id).cloned() {
        let RestoreData::Service {
            disabled_fingerprint,
            ..
        } = &existing.restore
        else {
            return Err(AppError::RestoreConflict(
                "the saved recovery record has the wrong source type".into(),
            ));
        };
        if disabled_fingerprint.as_deref() == Some(original_fingerprint.as_str()) {
            return Ok(());
        }
        if existing.entry.fingerprint == original_fingerprint {
            // The service was restored outside the app to the exact configuration we saved.
            // Retire that stale receipt before creating a fresh one.
            store.remove(&entry.id)?;
        } else {
            return Err(AppError::RestoreConflict(format!(
                "service {name} no longer matches either side of its saved change"
            )));
        }
    }
    if original_fingerprint != entry.fingerprint {
        return Err(AppError::StaleEntry);
    }
    if config.start_type != SERVICE_AUTO_START {
        return Err(AppError::StaleEntry);
    }
    let disabled_fingerprint = service_fingerprint_with_mode(&config, SERVICE_DEMAND_START, false);
    store.add(ManagedChange::new(
        entry.clone(),
        RestoreData::Service {
            service_name: name.into(),
            start_type: config.start_type.0,
            delayed_auto_start: config.delayed_auto_start,
            disabled_fingerprint: Some(disabled_fingerprint.clone()),
        },
    ))?;

    if let Err(error) = set_service_start_mode(name, SERVICE_DEMAND_START, false) {
        if query_named_service(name, SERVICE_QUERY_CONFIG)
            .is_ok_and(|current| service_fingerprint(&current) == original_fingerprint)
        {
            store.remove(&entry.id)?;
            return Err(error);
        }
        return Err(AppError::Platform(format!(
            "{error} The service may be partially changed; its exact recovery record was retained."
        )));
    }
    let current = query_named_service(name, SERVICE_QUERY_CONFIG)?;
    if service_fingerprint(&current) != disabled_fingerprint {
        return Err(AppError::Platform(
            "Windows reported success, but the service does not match the expected Manual state. The recovery record was retained.".into(),
        ));
    }
    Ok(())
}

fn restore_service(entry: &StartupEntry, name: &str, store: &mut StateStore) -> AppResult<()> {
    let change = store
        .find(&entry.id)
        .cloned()
        .ok_or_else(|| AppError::NotFound(format!("saved state for {}", entry.name)))?;
    let RestoreData::Service {
        service_name,
        start_type,
        delayed_auto_start,
        disabled_fingerprint,
    } = change.restore
    else {
        return Err(AppError::Platform(
            "Saved state has the wrong restore type".into(),
        ));
    };
    if !service_name.eq_ignore_ascii_case(name) {
        return Err(AppError::StaleEntry);
    }
    if start_type != SERVICE_AUTO_START.0 {
        return Err(AppError::RestoreConflict(
            "the saved service start mode is not an automatic mode created by this app".into(),
        ));
    }
    let expected_disabled_fingerprint = disabled_fingerprint.ok_or_else(|| {
        AppError::RestoreConflict(
            "this legacy recovery record has no verifiable post-change fingerprint".into(),
        )
    })?;
    let current = query_named_service(name, SERVICE_QUERY_CONFIG)?;
    let current_fingerprint = service_fingerprint(&current);
    if current_fingerprint != entry.fingerprint
        || current_fingerprint != expected_disabled_fingerprint
    {
        return Err(AppError::RestoreConflict(format!(
            "service {name} changed after Win Startup Manager set it to Manual"
        )));
    }
    set_service_start_mode(name, SERVICE_START_TYPE(start_type), delayed_auto_start)?;
    let restored = query_named_service(name, SERVICE_QUERY_CONFIG)?;
    if service_fingerprint(&restored) != change.entry.fingerprint {
        return Err(AppError::Platform(
            "Windows reported success, but the restored service configuration does not match the saved original. The recovery record was retained.".into(),
        ));
    }
    store.remove(&entry.id)?;
    Ok(())
}

fn query_named_service(name: &str, access: u32) -> AppResult<ServiceConfig> {
    // SAFETY: Null names select the active local SCM database.
    let manager = OwnedScHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(map_windows_error)?,
    );
    let wide_name = to_wide(name);
    // SAFETY: The service name is NUL-terminated and remains alive for the call.
    let service = OwnedScHandle(
        unsafe { OpenServiceW(manager.0, PCWSTR(wide_name.as_ptr()), access) }
            .map_err(map_windows_error)?,
    );
    query_service_config(service.0)
}

fn set_service_start_mode(
    name: &str,
    start_type: SERVICE_START_TYPE,
    delayed_auto_start: bool,
) -> AppResult<()> {
    // SAFETY: Null names select the active local SCM database.
    let manager = OwnedScHandle(
        unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(map_windows_error)?,
    );
    let wide_name = to_wide(name);
    // SAFETY: The service name is NUL-terminated and remains alive for the call.
    let service = OwnedScHandle(
        unsafe {
            OpenServiceW(
                manager.0,
                PCWSTR(wide_name.as_ptr()),
                SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG,
            )
        }
        .map_err(map_windows_error)?,
    );

    let before = query_service_config(service.0)?;
    if let Err(error) = apply_service_mode(
        service.0,
        before.start_type,
        before.delayed_auto_start,
        start_type,
        delayed_auto_start,
    ) {
        let rollback = query_service_config(service.0).and_then(|current| {
            apply_service_mode(
                service.0,
                current.start_type,
                current.delayed_auto_start,
                before.start_type,
                before.delayed_auto_start,
            )
        });
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(AppError::Platform(format!(
                "{error} Automatic rollback also failed: {rollback_error}"
            ))),
        };
    }
    Ok(())
}

fn apply_service_mode(
    service: SC_HANDLE,
    current_start_type: SERVICE_START_TYPE,
    current_delayed_auto_start: bool,
    desired_start_type: SERVICE_START_TYPE,
    desired_delayed_auto_start: bool,
) -> AppResult<()> {
    if desired_start_type != SERVICE_AUTO_START && desired_delayed_auto_start {
        return Err(AppError::Platform(
            "Delayed auto-start is only valid for automatic services".into(),
        ));
    }

    let set_delayed = |delayed: bool| -> AppResult<()> {
        let info = SERVICE_DELAYED_AUTO_START_INFO {
            fDelayedAutostart: delayed.into(),
        };
        // SAFETY: `info` matches the requested SERVICE_CONFIG structure and lives for the call.
        unsafe {
            ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some((&info as *const SERVICE_DELAYED_AUTO_START_INFO).cast()),
            )
        }
        .map_err(map_windows_error)
    };

    let mut delayed = current_delayed_auto_start;
    if current_start_type == SERVICE_AUTO_START
        && current_delayed_auto_start
        && (desired_start_type != SERVICE_AUTO_START || !desired_delayed_auto_start)
    {
        // Windows requires the delayed flag to be cleared while the service is still automatic.
        set_delayed(false)?;
        delayed = false;
    }

    if current_start_type != desired_start_type {
        change_service_start_type(service, desired_start_type)?;
    }
    if desired_start_type == SERVICE_AUTO_START && delayed != desired_delayed_auto_start {
        set_delayed(desired_delayed_auto_start)?;
    }
    Ok(())
}

fn change_service_start_type(service: SC_HANDLE, start_type: SERVICE_START_TYPE) -> AppResult<()> {
    // SAFETY: SERVICE_NO_CHANGE and null parameters preserve every configuration field except
    // the requested start type.
    unsafe {
        ChangeServiceConfigW(
            service,
            ENUM_SERVICE_TYPE(SERVICE_NO_CHANGE),
            start_type,
            SERVICE_ERROR(SERVICE_NO_CHANGE),
            PCWSTR::null(),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
    }
    .map_err(map_windows_error)
}

fn service_fingerprint(config: &ServiceConfig) -> String {
    service_fingerprint_with_mode(config, config.start_type, config.delayed_auto_start)
}

fn service_fingerprint_with_mode(
    config: &ServiceConfig,
    start_type: SERVICE_START_TYPE,
    delayed_auto_start: bool,
) -> String {
    let start_bytes = start_type.0.to_le_bytes();
    let delayed_byte = [u8::from(delayed_auto_start)];
    fingerprint(&[
        config.binary_path.as_bytes(),
        config.account.as_bytes(),
        &start_bytes,
        &delayed_byte,
    ])
}

fn words_for_bytes(bytes: u32) -> Vec<usize> {
    vec![0; (bytes as usize).div_ceil(size_of::<usize>())]
}

fn words_as_bytes(words: &mut [usize]) -> &mut [u8] {
    // SAFETY: u8 has alignment 1 and the byte slice covers exactly the usize allocation.
    unsafe {
        slice::from_raw_parts_mut(
            words.as_mut_ptr().cast::<u8>(),
            std::mem::size_of_val(words),
        )
    }
}

unsafe fn count_multi_sz(pointer: *mut u16) -> usize {
    if pointer.is_null() {
        return 0;
    }
    let mut count = 0;
    let mut offset = 0usize;
    loop {
        // SAFETY: QUERY_SERVICE_CONFIGW guarantees a double-NUL-terminated MULTI_SZ pointer.
        if unsafe { *pointer.add(offset) } == 0 {
            // SAFETY: The next unit exists because the sequence is double-NUL terminated.
            if unsafe { *pointer.add(offset + 1) } == 0 {
                break;
            }
            count += 1;
        }
        offset += 1;
    }
    if offset > 0 { count + 1 } else { 0 }
}

fn is_per_user_service(name: &str) -> bool {
    name.rsplit_once('_').is_some_and(|(_, suffix)| {
        (5..=12).contains(&suffix.len())
            && suffix
                .chars()
                .all(|character| character.is_ascii_hexdigit())
    })
}

fn map_windows_error(error: windows::core::Error) -> AppError {
    if error.code().0 as u32 == 0x8007_0005 {
        AppError::PermissionDenied
    } else {
        AppError::Platform(error.to_string())
    }
}

impl From<windows::core::Error> for AppError {
    fn from(error: windows::core::Error) -> Self {
        map_windows_error(error)
    }
}
