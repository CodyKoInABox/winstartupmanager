use std::borrow::Cow;
use std::io;

use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::{RegKey, RegValue};

use crate::domain::{
    RegistryHive, RegistryView, RiskLevel, SourceKind, SourceLocator, StartupEntry, StartupScope,
    TriggerKind, fingerprint, stable_id,
};
use crate::error::{AppError, AppResult};
use crate::platform::windows::ProviderOutput;
use crate::platform::windows::shell::{is_windows_component, normalized_executable};
use crate::state::{ManagedChange, RestoreData, StateStore};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_ONCE_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\RunOnce";
const POLICY_RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";

#[derive(Clone, Copy, PartialEq, Eq)]
struct RegistryLocation {
    hive: RegistryHive,
    view: RegistryView,
    key: &'static str,
    trigger: TriggerKind,
    policy: bool,
}

#[derive(Clone)]
struct MutableRegistryLocator {
    location: RegistryLocation,
    value: String,
    id: String,
}

struct ValidatedRegistryChange {
    locator: MutableRegistryLocator,
    entry: StartupEntry,
    value_type: u32,
    bytes: Vec<u8>,
}

pub fn scan_registry(store: &StateStore) -> ProviderOutput {
    let mut output = ProviderOutput::default();

    for location in registry_locations() {
        match scan_location(location) {
            Ok(mut entries) => output.entries.append(&mut entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => output.warnings.push(format!(
                "Could not scan {}\\{} ({}): {}",
                location.hive.label(),
                location.key,
                location.view.label(),
                error
            )),
        }
    }

    append_manager_disabled_entries(store, &mut output);
    output
}

fn registry_locations() -> Vec<RegistryLocation> {
    let mut locations = Vec::new();
    for (key, trigger, policy) in [
        (RUN_KEY, TriggerKind::SignIn, false),
        (RUN_ONCE_KEY, TriggerKind::RunOnce, false),
        (POLICY_RUN_KEY, TriggerKind::Policy, true),
    ] {
        locations.push(RegistryLocation {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Default,
            key,
            trigger,
            policy,
        });
        for view in [RegistryView::Registry64, RegistryView::Registry32] {
            locations.push(RegistryLocation {
                hive: RegistryHive::LocalMachine,
                view,
                key,
                trigger,
                policy,
            });
        }
    }
    locations
}

fn scan_location(location: RegistryLocation) -> io::Result<Vec<StartupEntry>> {
    let key = root_key(location.hive)
        .open_subkey_with_flags(location.key, KEY_READ | view_flag(location.view))?;
    let mut entries = Vec::new();

    for value in key.enum_values() {
        let (name, raw) = match value {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    key = location.key,
                    "registry value could not be read"
                );
                continue;
            }
        };
        entries.push(entry_from_raw(location, name, &raw));
    }
    Ok(entries)
}

fn entry_from_raw(location: RegistryLocation, name: String, raw: &RegValue<'_>) -> StartupEntry {
    let command = String::from_reg_value(raw)
        .unwrap_or_else(|_| format!("<unsupported registry value: {:?}>", raw.vtype));
    let supported = matches!(raw.vtype, REG_SZ | REG_EXPAND_SZ);
    let executable = supported.then(|| normalized_executable(&command)).flatten();
    let target_exists = executable.as_ref().map(|path| path.exists());
    let system = supported && is_windows_component(&command);
    let scope = if location.policy {
        StartupScope::ManagedPolicy
    } else if location.hive == RegistryHive::CurrentUser {
        StartupScope::CurrentUser
    } else {
        StartupScope::AllUsers
    };
    let risk = if location.policy || system {
        RiskLevel::Protected
    } else if location.trigger == TriggerKind::RunOnce {
        RiskLevel::Caution
    } else if location.hive == RegistryHive::LocalMachine {
        RiskLevel::Review
    } else {
        RiskLevel::Normal
    };
    let type_bytes = reg_type_to_u32(&raw.vtype).to_le_bytes();
    let id = registry_entry_id(location, &name);

    let mut description: Option<String> = match location.trigger {
        TriggerKind::RunOnce => {
            Some("Windows intends to run this once for setup, repair, or an update.".into())
        }
        TriggerKind::Policy => Some("This sign-in command is managed by Windows policy.".into()),
        _ => None,
    };
    if location.hive == RegistryHive::LocalMachine && !location.policy {
        let note = "Machine-wide Registry startup entries are visible but read-only in v0.1.";
        match &mut description {
            Some(text) => {
                text.push(' ');
                text.push_str(note);
            }
            None => description = Some(note.into()),
        }
    }

    StartupEntry {
        id,
        name: if name.is_empty() {
            "(Default)".into()
        } else {
            name.clone()
        },
        command,
        executable,
        description,
        publisher: None,
        source: SourceKind::Registry,
        scope,
        trigger: location.trigger,
        risk,
        enabled: true,
        can_toggle: supported && is_mutable_location(location) && !system,
        requires_admin: location.hive == RegistryHive::LocalMachine,
        is_system: system || location.policy,
        target_exists,
        fingerprint: fingerprint(&[&type_bytes, raw.bytes.as_ref()]),
        locator: SourceLocator::Registry {
            hive: location.hive,
            view: location.view,
            key: location.key.into(),
            value: name,
        },
    }
}

fn append_manager_disabled_entries(store: &StateStore, output: &mut ProviderOutput) {
    for change in store.changes() {
        if !matches!(change.restore, RestoreData::Registry { .. }) {
            continue;
        }

        if store
            .changes()
            .iter()
            .filter(|candidate| candidate.id == change.id)
            .count()
            != 1
        {
            output.warnings.push(format!(
                "Ignored duplicate saved registry state for {}; no registry access was attempted.",
                change.entry.name
            ));
            continue;
        }

        let saved = match validate_managed_change(change) {
            Ok(saved) => saved,
            Err(error) => {
                output.warnings.push(format!(
                    "Ignored unsafe or invalid saved registry state for {}: {error}",
                    change.entry.name
                ));
                continue;
            }
        };

        match registry_value_exists(
            saved.locator.location.hive,
            saved.locator.location.view,
            saved.locator.location.key,
            &saved.locator.value,
        ) {
            Ok(false) => {
                let mut entry = saved.entry;
                entry.enabled = false;
                output.entries.push(entry);
            }
            Ok(true) => output.warnings.push(format!(
                "{} was changed outside Win Startup Manager; refresh its saved state before restoring.",
                change.entry.name
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut entry = saved.entry;
                entry.enabled = false;
                output.entries.push(entry);
            }
            Err(error) => output.warnings.push(format!(
                "Could not verify disabled registry entry {}: {error}",
                change.entry.name
            )),
        }
    }
}

pub fn set_registry_enabled(
    entry: &StartupEntry,
    enabled: bool,
    store: &mut StateStore,
) -> AppResult<()> {
    // Authorization comes only from the exact source provenance. UI and journal
    // metadata such as `can_toggle` and `requires_admin` are intentionally not
    // security boundaries.
    let locator = validate_mutable_entry(entry)?;

    if enabled {
        restore_registry_value(entry, &locator, store)
    } else {
        disable_registry_value(entry, &locator, store)
    }
}

fn disable_registry_value(
    entry: &StartupEntry,
    locator: &MutableRegistryLocator,
    store: &mut StateStore,
) -> AppResult<()> {
    if let Some(change) = find_unique_change(store, &locator.id)? {
        let saved = validate_managed_change(change)?;
        if !same_mutable_locator(locator, &saved.locator)
            || !entry_consistent_with_trusted(entry, &saved.entry)
        {
            return Err(registry_safety_error());
        }

        return match registry_value_exists(
            saved.locator.location.hive,
            saved.locator.location.view,
            saved.locator.location.key,
            &saved.locator.value,
        ) {
            Ok(false) => Ok(()),
            Ok(true) => Err(AppError::RestoreConflict(entry.source_location())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AppError::from_io(error)),
        };
    }

    let key = root_key(locator.location.hive)
        .open_subkey_with_flags(
            locator.location.key,
            KEY_QUERY_VALUE | KEY_SET_VALUE | view_flag(locator.location.view),
        )
        .map_err(AppError::from_io)?;
    let raw = key
        .get_raw_value(&locator.value)
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => AppError::NotFound(entry.name.clone()),
            _ => AppError::from_io(error),
        })?;

    let trusted_entry = entry_from_raw(locator.location, locator.value.clone(), &raw);
    if !trusted_entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    if !entry_consistent_with_trusted(entry, &trusted_entry) {
        return Err(AppError::StaleEntry);
    }

    let type_number = reg_type_to_u32(&raw.vtype);
    let change = ManagedChange::new(
        trusted_entry,
        RestoreData::Registry {
            value_type: type_number,
            bytes: raw.bytes.into_owned(),
        },
    );
    store.add(change)?;

    if let Err(error) = key.delete_value(&locator.value) {
        let _ = store.remove(&locator.id);
        return Err(AppError::from_io(error));
    }
    Ok(())
}

fn restore_registry_value(
    entry: &StartupEntry,
    locator: &MutableRegistryLocator,
    store: &mut StateStore,
) -> AppResult<()> {
    let change = find_unique_change(store, &locator.id)?
        .ok_or_else(|| AppError::NotFound(format!("saved state for {}", entry.name)))?;
    let saved = validate_managed_change(change)?;
    if !same_mutable_locator(locator, &saved.locator)
        || !entry_consistent_with_trusted(entry, &saved.entry)
    {
        return Err(registry_safety_error());
    }

    let value_type = reg_type_from_u32(saved.value_type)
        .ok_or_else(|| AppError::Platform("Saved registry value type is unsupported".into()))?;
    let key = root_key(saved.locator.location.hive)
        .open_subkey_with_flags(
            saved.locator.location.key,
            KEY_QUERY_VALUE | KEY_SET_VALUE | view_flag(saved.locator.location.view),
        )
        .map_err(AppError::from_io)?;

    match key.get_raw_value(&saved.locator.value) {
        Ok(_) => return Err(AppError::RestoreConflict(entry.source_location())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(AppError::from_io(error)),
    }

    key.set_raw_value(
        &saved.locator.value,
        &RegValue {
            bytes: Cow::Owned(saved.bytes),
            vtype: value_type,
        },
    )
    .map_err(AppError::from_io)?;
    store.remove(&locator.id)?;
    Ok(())
}

fn validate_mutable_entry(entry: &StartupEntry) -> AppResult<MutableRegistryLocator> {
    let SourceLocator::Registry {
        hive,
        view,
        key,
        value,
    } = &entry.locator
    else {
        return Err(registry_safety_error());
    };

    let location =
        canonical_mutable_location(*hive, *view, key).ok_or_else(registry_safety_error)?;
    if value.contains('\0') {
        return Err(registry_safety_error());
    }

    let id = registry_entry_id(location, value);
    if entry.id != id
        || entry.source != SourceKind::Registry
        || entry.scope != StartupScope::CurrentUser
        || entry.trigger != location.trigger
    {
        return Err(registry_safety_error());
    }

    Ok(MutableRegistryLocator {
        location,
        value: value.clone(),
        id,
    })
}

fn validate_managed_change(change: &ManagedChange) -> AppResult<ValidatedRegistryChange> {
    let locator = validate_mutable_entry(&change.entry)?;
    if change.id != locator.id || !change.entry.enabled {
        return Err(registry_safety_error());
    }

    let RestoreData::Registry { value_type, bytes } = &change.restore else {
        return Err(registry_safety_error());
    };
    let value_type_kind = reg_type_from_u32(*value_type).ok_or_else(registry_safety_error)?;
    let raw = RegValue {
        bytes: Cow::Borrowed(bytes.as_slice()),
        vtype: value_type_kind,
    };
    let trusted_entry = entry_from_raw(locator.location, locator.value.clone(), &raw);

    // Rebuilding from the exact recovery bytes prevents edited journal display
    // fields from granting authority. In particular, these decisions do not use
    // the serialized `can_toggle` or `requires_admin` values.
    if !trusted_entry.can_toggle || !entry_consistent_with_trusted(&change.entry, &trusted_entry) {
        return Err(registry_safety_error());
    }

    Ok(ValidatedRegistryChange {
        locator,
        entry: trusted_entry,
        value_type: *value_type,
        bytes: bytes.clone(),
    })
}

fn find_unique_change<'a>(store: &'a StateStore, id: &str) -> AppResult<Option<&'a ManagedChange>> {
    let mut matches = store.changes().iter().filter(|change| change.id == id);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(registry_safety_error());
    }
    Ok(first)
}

fn canonical_mutable_location(
    hive: RegistryHive,
    view: RegistryView,
    key: &str,
) -> Option<RegistryLocation> {
    if hive != RegistryHive::CurrentUser || view != RegistryView::Default {
        return None;
    }

    let (key, trigger) = if key.eq_ignore_ascii_case(RUN_KEY) {
        (RUN_KEY, TriggerKind::SignIn)
    } else if key.eq_ignore_ascii_case(RUN_ONCE_KEY) {
        (RUN_ONCE_KEY, TriggerKind::RunOnce)
    } else {
        return None;
    };

    Some(RegistryLocation {
        hive,
        view,
        key,
        trigger,
        policy: false,
    })
}

fn is_mutable_location(location: RegistryLocation) -> bool {
    canonical_mutable_location(location.hive, location.view, location.key).is_some()
        && !location.policy
}

fn registry_entry_id(location: RegistryLocation, value: &str) -> String {
    let normalized_value = value.to_lowercase();
    stable_id(&[
        "registry",
        location.hive.label(),
        location.view.label(),
        location.key,
        &normalized_value,
    ])
}

fn same_mutable_locator(left: &MutableRegistryLocator, right: &MutableRegistryLocator) -> bool {
    left.location == right.location
        && left.value.to_lowercase() == right.value.to_lowercase()
        && left.id == right.id
}

fn entry_consistent_with_trusted(entry: &StartupEntry, trusted: &StartupEntry) -> bool {
    let Ok(entry_locator) = validate_mutable_entry(entry) else {
        return false;
    };
    let Ok(trusted_locator) = validate_mutable_entry(trusted) else {
        return false;
    };

    same_mutable_locator(&entry_locator, &trusted_locator)
        && entry.name == trusted.name
        && entry.command == trusted.command
        && entry.fingerprint == trusted.fingerprint
}

fn registry_safety_error() -> AppError {
    AppError::Platform(
        "Registry entry failed safety validation; no registry changes were made".into(),
    )
}

fn registry_value_exists(
    hive: RegistryHive,
    view: RegistryView,
    key_path: &str,
    value_name: &str,
) -> io::Result<bool> {
    let key = root_key(hive).open_subkey_with_flags(key_path, KEY_QUERY_VALUE | view_flag(view))?;
    match key.get_raw_value(value_name) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn root_key(hive: RegistryHive) -> RegKey {
    match hive {
        RegistryHive::CurrentUser => RegKey::predef(HKEY_CURRENT_USER),
        RegistryHive::LocalMachine => RegKey::predef(HKEY_LOCAL_MACHINE),
    }
}

const fn view_flag(view: RegistryView) -> u32 {
    match view {
        RegistryView::Default => 0,
        RegistryView::Registry32 => KEY_WOW64_32KEY,
        RegistryView::Registry64 => KEY_WOW64_64KEY,
    }
}

fn reg_type_to_u32(value_type: &RegType) -> u32 {
    match value_type {
        REG_NONE => 0,
        REG_SZ => 1,
        REG_EXPAND_SZ => 2,
        REG_BINARY => 3,
        REG_DWORD => 4,
        REG_DWORD_BIG_ENDIAN => 5,
        REG_LINK => 6,
        REG_MULTI_SZ => 7,
        REG_RESOURCE_LIST => 8,
        REG_FULL_RESOURCE_DESCRIPTOR => 9,
        REG_RESOURCE_REQUIREMENTS_LIST => 10,
        REG_QWORD => 11,
    }
}

fn reg_type_from_u32(value_type: u32) -> Option<RegType> {
    Some(match value_type {
        0 => REG_NONE,
        1 => REG_SZ,
        2 => REG_EXPAND_SZ,
        3 => REG_BINARY,
        4 => REG_DWORD,
        5 => REG_DWORD_BIG_ENDIAN,
        6 => REG_LINK,
        7 => REG_MULTI_SZ,
        8 => REG_RESOURCE_LIST,
        9 => REG_FULL_RESOURCE_DESCRIPTOR,
        10 => REG_RESOURCE_REQUIREMENTS_LIST,
        11 => REG_QWORD,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_value(command: &str) -> RegValue<'static> {
        let mut bytes = command
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        RegValue {
            bytes: Cow::Owned(bytes),
            vtype: REG_SZ,
        }
    }

    fn user_run_location() -> RegistryLocation {
        RegistryLocation {
            hive: RegistryHive::CurrentUser,
            view: RegistryView::Default,
            key: RUN_KEY,
            trigger: TriggerKind::SignIn,
            policy: false,
        }
    }

    fn user_entry() -> (StartupEntry, RegValue<'static>) {
        let raw = string_value(r"C:\Program Files\Acme\acme.exe --background");
        let entry = entry_from_raw(user_run_location(), "Acme".into(), &raw);
        (entry, raw)
    }

    #[test]
    fn local_machine_entries_are_visible_but_never_mutable() {
        let raw = string_value(r"C:\Apps\Acme.exe");
        let location = RegistryLocation {
            hive: RegistryHive::LocalMachine,
            view: RegistryView::Registry64,
            key: RUN_KEY,
            trigger: TriggerKind::SignIn,
            policy: false,
        };
        let entry = entry_from_raw(location, "Acme".into(), &raw);

        assert!(!entry.can_toggle);
        assert!(entry.requires_admin);
        assert!(validate_mutable_entry(&entry).is_err());
    }

    #[test]
    fn mutation_boundary_only_accepts_default_view_user_run_keys() {
        let (entry, _) = user_entry();
        assert!(validate_mutable_entry(&entry).is_ok());

        let mut wrong_view = entry.clone();
        let SourceLocator::Registry { view, .. } = &mut wrong_view.locator else {
            unreachable!();
        };
        *view = RegistryView::Registry64;
        assert!(validate_mutable_entry(&wrong_view).is_err());

        let mut policy = entry;
        let SourceLocator::Registry { key, .. } = &mut policy.locator else {
            unreachable!();
        };
        *key = POLICY_RUN_KEY.into();
        assert!(validate_mutable_entry(&policy).is_err());
    }

    #[test]
    fn stable_registry_identity_normalizes_case_but_includes_provenance() {
        let location = user_run_location();
        assert_eq!(
            registry_entry_id(location, "Acme"),
            registry_entry_id(location, "ACME")
        );

        let run_once = RegistryLocation {
            key: RUN_ONCE_KEY,
            trigger: TriggerKind::RunOnce,
            ..location
        };
        assert_ne!(
            registry_entry_id(location, "Acme"),
            registry_entry_id(run_once, "Acme")
        );
    }

    #[test]
    fn saved_display_flags_do_not_grant_or_remove_registry_authority() {
        let (mut entry, raw) = user_entry();
        entry.can_toggle = false;
        entry.requires_admin = true;
        let change = ManagedChange::new(
            entry,
            RestoreData::Registry {
                value_type: reg_type_to_u32(&raw.vtype),
                bytes: raw.bytes.into_owned(),
            },
        );

        let validated = validate_managed_change(&change).unwrap();
        assert!(validated.entry.can_toggle);
        assert!(!validated.entry.requires_admin);
    }

    #[test]
    fn forged_saved_locator_and_content_fail_closed() {
        let (entry, raw) = user_entry();
        let mut forged_locator = ManagedChange::new(
            entry.clone(),
            RestoreData::Registry {
                value_type: reg_type_to_u32(&raw.vtype),
                bytes: raw.bytes.clone().into_owned(),
            },
        );
        let SourceLocator::Registry { hive, .. } = &mut forged_locator.entry.locator else {
            unreachable!();
        };
        *hive = RegistryHive::LocalMachine;
        assert!(validate_managed_change(&forged_locator).is_err());

        let mut forged_content = ManagedChange::new(
            entry,
            RestoreData::Registry {
                value_type: reg_type_to_u32(&raw.vtype),
                bytes: raw.bytes.into_owned(),
            },
        );
        forged_content.entry.command.push_str(" --forged");
        assert!(validate_managed_change(&forged_content).is_err());
    }
}
