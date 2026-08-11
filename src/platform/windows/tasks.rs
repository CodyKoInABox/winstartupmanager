use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::Win32::System::TaskScheduler::{
    IAction, IExecAction, IRegisteredTask, ITaskFolder, ITaskService, ITrigger, TASK_ACTION_EXEC,
    TASK_ENUM_HIDDEN, TASK_TRIGGER_BOOT, TASK_TRIGGER_LOGON, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use crate::domain::{
    RiskLevel, SourceKind, SourceLocator, StartupEntry, StartupScope, TriggerKind, fingerprint,
    stable_id,
};
use crate::error::{AppError, AppResult};
use crate::platform::windows::ProviderOutput;
use crate::platform::windows::shell::{ComApartment, is_windows_component, normalized_executable};
use crate::state::StateStore;

pub fn scan_scheduled_tasks(_: &StateStore) -> ProviderOutput {
    match enumerate_tasks() {
        Ok(output) => output,
        Err(error) => ProviderOutput::warning(format!("Scheduled Tasks scan failed: {error}")),
    }
}

fn enumerate_tasks() -> AppResult<ProviderOutput> {
    let _apartment = ComApartment::initialize()?;
    let service = connect_task_service()?;
    // SAFETY: The COM service is connected and the BSTR lives for the duration of the call.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(map_windows_error)?;
    let mut output = ProviderOutput::default();
    walk_folder(&root, &mut output);
    Ok(output)
}

fn connect_task_service() -> AppResult<ITaskService> {
    // SAFETY: COM is initialized on this worker thread. The interface does not leave the thread.
    let service: ITaskService =
        unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
            .map_err(map_windows_error)?;
    let empty = VARIANT::default();
    // SAFETY: Empty variants request a connection using the current user and local computer.
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }.map_err(map_windows_error)?;
    Ok(service)
}

fn walk_folder(folder: &ITaskFolder, output: &mut ProviderOutput) {
    // SAFETY: The folder is a live Task Scheduler COM interface on this COM thread.
    match unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) } {
        Ok(tasks) => {
            let count = unsafe { tasks.Count() }.unwrap_or_default();
            for index in 1..=count {
                let index_value = VARIANT::from(index);
                let task = match unsafe { tasks.get_Item(&index_value) } {
                    Ok(task) => task,
                    Err(error) => {
                        output
                            .warnings
                            .push(format!("A scheduled task was inaccessible: {error}"));
                        continue;
                    }
                };
                match inspect_task(&task) {
                    Ok(Some(entry)) => output.entries.push(entry),
                    Ok(None) => {}
                    Err(error) => {
                        let name = unsafe { task.Path() }
                            .map(|path| path.to_string())
                            .unwrap_or_else(|_| "unknown task".into());
                        output
                            .warnings
                            .push(format!("Could not inspect {name}: {error}"));
                    }
                }
            }
        }
        Err(error) => output
            .warnings
            .push(format!("A scheduled task folder was inaccessible: {error}")),
    }

    // SAFETY: The folder is a live Task Scheduler COM interface on this COM thread.
    let folders = match unsafe { folder.GetFolders(0) } {
        Ok(folders) => folders,
        Err(error) => {
            output.warnings.push(format!(
                "Could not enumerate a scheduled task folder: {error}"
            ));
            return;
        }
    };
    let count = unsafe { folders.Count() }.unwrap_or_default();
    for index in 1..=count {
        let index_value = VARIANT::from(index);
        match unsafe { folders.get_Item(&index_value) } {
            Ok(child) => walk_folder(&child, output),
            Err(error) => output
                .warnings
                .push(format!("A scheduled task folder was inaccessible: {error}")),
        }
    }
}

fn inspect_task(task: &IRegisteredTask) -> AppResult<Option<StartupEntry>> {
    // SAFETY: All COM calls stay on the initialized Task Scheduler worker thread.
    let definition = unsafe { task.Definition() }.map_err(map_windows_error)?;
    let triggers = unsafe { definition.Triggers() }.map_err(map_windows_error)?;
    let mut trigger_count = 0;
    unsafe { triggers.Count(&mut trigger_count) }.map_err(map_windows_error)?;

    let mut has_boot = false;
    let mut has_logon = false;
    let mut has_enabled_non_startup = false;
    for index in 1..=trigger_count {
        let trigger = unsafe { triggers.get_Item(index) }.map_err(map_windows_error)?;
        let kind = trigger_type(&trigger)?;
        let trigger_enabled = trigger_enabled(&trigger)?;
        if !trigger_enabled {
            continue;
        }
        if kind == TASK_TRIGGER_BOOT {
            has_boot = true;
        } else if kind == TASK_TRIGGER_LOGON {
            has_logon = true;
        } else {
            has_enabled_non_startup = true;
        }
    }
    if !has_boot && !has_logon {
        return Ok(None);
    }

    let actions = unsafe { definition.Actions() }.map_err(map_windows_error)?;
    let mut action_count = 0;
    unsafe { actions.Count(&mut action_count) }.map_err(map_windows_error)?;
    let mut commands = Vec::new();
    let mut first_executable = None;
    for index in 1..=action_count {
        let action: IAction = unsafe { actions.get_Item(index) }.map_err(map_windows_error)?;
        let mut kind = Default::default();
        unsafe { action.Type(&mut kind) }.map_err(map_windows_error)?;
        if kind != TASK_ACTION_EXEC {
            commands.push("<non-executable task action>".into());
            continue;
        }
        let exec: IExecAction = action.cast().map_err(map_windows_error)?;
        let path = bstr_out(|out| unsafe { exec.Path(out) })?;
        let arguments = bstr_out(|out| unsafe { exec.Arguments(out) })?;
        let command = if arguments.trim().is_empty() {
            format!(r#""{path}""#)
        } else {
            format!(r#""{path}" {arguments}"#)
        };
        if first_executable.is_none() {
            first_executable = normalized_executable(&command);
        }
        commands.push(command);
    }

    let name = unsafe { task.Name() }
        .map_err(map_windows_error)?
        .to_string();
    let path = unsafe { task.Path() }
        .map_err(map_windows_error)?
        .to_string();
    let enabled = unsafe { task.Enabled() }
        .map_err(map_windows_error)?
        .as_bool();
    let xml = unsafe { task.Xml() }
        .map_err(map_windows_error)?
        .to_string();
    let registration = unsafe { definition.RegistrationInfo() }.ok();
    let author = registration
        .as_ref()
        .and_then(|info| bstr_out(|out| unsafe { info.Author(out) }).ok())
        .filter(|value| !value.trim().is_empty());
    let registered_description = registration
        .as_ref()
        .and_then(|info| bstr_out(|out| unsafe { info.Description(out) }).ok())
        .filter(|value| !value.trim().is_empty());

    let command = if commands.is_empty() {
        "<task has no executable action>".into()
    } else {
        commands.join("  •  ")
    };
    let microsoft_task = path
        .to_ascii_lowercase()
        .starts_with(r"\microsoft\windows\")
        || author
            .as_deref()
            .is_some_and(|value| value.to_ascii_lowercase().contains("microsoft"))
        || is_windows_component(&command);
    let mixed = has_enabled_non_startup;
    let trigger = match (has_logon, has_boot) {
        (true, true) => TriggerKind::SignInAndBoot,
        (false, true) => TriggerKind::Boot,
        _ => TriggerKind::SignIn,
    };
    let scope = if has_boot || microsoft_task {
        StartupScope::System
    } else {
        StartupScope::CurrentUser
    };
    let description = if mixed {
        Some(match registered_description {
            Some(description) => format!(
                "{description}\n\nThis task also has a non-startup trigger, so changing the whole task is locked for safety."
            ),
            None => "This task also has a non-startup trigger, so changing the whole task is locked for safety.".into(),
        })
    } else {
        registered_description
    };
    let target_exists = first_executable.as_ref().map(|target| target.exists());

    Ok(Some(StartupEntry {
        id: stable_id(&["scheduled-task", &path.to_ascii_lowercase()]),
        name,
        command,
        executable: first_executable,
        description,
        publisher: author,
        source: SourceKind::ScheduledTask,
        scope,
        trigger,
        risk: if microsoft_task {
            RiskLevel::Protected
        } else if mixed || has_boot {
            RiskLevel::Caution
        } else {
            RiskLevel::Review
        },
        enabled,
        can_toggle: !microsoft_task && !mixed,
        requires_admin: has_boot || microsoft_task,
        is_system: microsoft_task,
        target_exists,
        fingerprint: fingerprint(&[xml.as_bytes()]),
        locator: SourceLocator::ScheduledTask { path },
    }))
}

fn trigger_type(
    trigger: &ITrigger,
) -> AppResult<windows::Win32::System::TaskScheduler::TASK_TRIGGER_TYPE2> {
    let mut kind = Default::default();
    // SAFETY: `kind` is a valid writable output parameter.
    unsafe { trigger.Type(&mut kind) }.map_err(map_windows_error)?;
    Ok(kind)
}

fn trigger_enabled(trigger: &ITrigger) -> AppResult<bool> {
    let mut enabled = VARIANT_BOOL::default();
    // SAFETY: `enabled` is a valid writable output parameter.
    unsafe { trigger.Enabled(&mut enabled) }.map_err(map_windows_error)?;
    Ok(enabled.as_bool())
}

fn bstr_out(get: impl FnOnce(*mut BSTR) -> windows::core::Result<()>) -> AppResult<String> {
    let mut value = BSTR::new();
    get(&mut value).map_err(map_windows_error)?;
    Ok(value.to_string())
}

pub fn set_task_enabled(entry: &StartupEntry, enabled: bool) -> AppResult<()> {
    if !entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    let SourceLocator::ScheduledTask { path } = &entry.locator else {
        return Err(AppError::Platform("Invalid scheduled task locator".into()));
    };
    if !path.starts_with('\\') || path.contains('\0') {
        return Err(AppError::ProtectedEntry);
    }

    let _apartment = ComApartment::initialize()?;
    let service = connect_task_service()?;
    // SAFETY: The COM interfaces and strings remain on this initialized worker thread.
    let root = unsafe { service.GetFolder(&BSTR::from("\\")) }.map_err(map_windows_error)?;
    let task = unsafe { root.GetTask(&BSTR::from(path)) }.map_err(map_windows_error)?;
    let current_xml = unsafe { task.Xml() }
        .map_err(map_windows_error)?
        .to_string();
    if fingerprint(&[current_xml.as_bytes()]) != entry.fingerprint {
        return Err(AppError::StaleEntry);
    }
    unsafe { task.SetEnabled(VARIANT_BOOL::from(enabled)) }.map_err(map_windows_error)
}

fn map_windows_error(error: windows::core::Error) -> AppError {
    if error.code().0 as u32 == 0x8007_0005 {
        AppError::PermissionDenied
    } else {
        AppError::Platform(error.to_string())
    }
}
