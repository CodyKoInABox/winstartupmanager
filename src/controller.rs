use std::sync::mpsc::SyncSender;
use std::thread;

use eframe::egui;

use crate::domain::{SourceLocator, StartupEntry};
use crate::error::{AppError, AppResult};
use crate::platform;
use crate::scan::{WorkerEvent, send};
use crate::state::StateTransaction;

pub fn spawn_set_enabled(
    entry: StartupEntry,
    desired_enabled: bool,
    sender: SyncSender<WorkerEvent>,
    context: egui::Context,
) {
    let id = entry.id.clone();
    let _ = thread::Builder::new()
        .name(format!("startup-mutation-{id}"))
        .spawn(move || {
            let result = set_enabled(&entry, desired_enabled).map_err(|error| error.to_string());
            send(
                &sender,
                &context,
                WorkerEvent::MutationFinished {
                    entry_id: id,
                    desired_enabled,
                    result,
                },
            );
        });
}

fn set_enabled(entry: &StartupEntry, desired_enabled: bool) -> AppResult<()> {
    if entry.enabled == desired_enabled {
        return Ok(());
    }
    if !entry.can_toggle {
        return Err(AppError::ProtectedEntry);
    }
    match &entry.locator {
        SourceLocator::ScheduledTask { .. } => platform::set_task_enabled(entry, desired_enabled),
        SourceLocator::Registry { .. }
        | SourceLocator::StartupFolder { .. }
        | SourceLocator::Service { .. } => {
            let mut transaction = StateTransaction::begin()?;
            let store = transaction.store_mut();
            match &entry.locator {
                SourceLocator::Registry { .. } => {
                    platform::set_registry_enabled(entry, desired_enabled, store)
                }
                SourceLocator::StartupFolder { .. } => {
                    platform::set_startup_file_enabled(entry, desired_enabled, store)
                }
                SourceLocator::Service { .. } => {
                    platform::set_service_enabled(entry, desired_enabled, store)
                }
                SourceLocator::ScheduledTask { .. } => unreachable!(),
            }
        }
    }
}
