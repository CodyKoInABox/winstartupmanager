use std::sync::mpsc::SyncSender;
use std::thread;

use eframe::egui;

use crate::domain::{SourceKind, StartupEntry};
use crate::platform;
use crate::state::StateStore;

#[derive(Debug)]
pub enum WorkerEvent {
    ProviderStarted {
        generation: u64,
        source: SourceKind,
    },
    ProviderFinished {
        generation: u64,
        source: SourceKind,
        entries: Vec<StartupEntry>,
        warnings: Vec<String>,
    },
    ScanFinished {
        generation: u64,
    },
    MutationFinished {
        entry_id: String,
        desired_enabled: bool,
        result: Result<(), String>,
    },
}

pub fn spawn_scan(generation: u64, sender: SyncSender<WorkerEvent>, context: egui::Context) {
    let _ = thread::Builder::new()
        .name(format!("startup-scan-{generation}"))
        .spawn(move || {
            let (store, state_warning) = StateStore::load_or_default();
            thread::scope(|scope| {
                for source in SourceKind::ALL {
                    let sender = sender.clone();
                    let context = context.clone();
                    let store = store.clone();
                    let state_warning = state_warning.clone();
                    scope.spawn(move || {
                        send(
                            &sender,
                            &context,
                            WorkerEvent::ProviderStarted { generation, source },
                        );
                        let mut output = match source {
                            SourceKind::Registry => platform::scan_registry(&store),
                            SourceKind::StartupFolder => platform::scan_startup_folders(&store),
                            SourceKind::ScheduledTask => platform::scan_scheduled_tasks(&store),
                            SourceKind::Service => platform::scan_services(&store),
                        };
                        if source == SourceKind::Registry
                            && let Some(warning) = state_warning
                        {
                            output.warnings.push(warning);
                        }
                        send(
                            &sender,
                            &context,
                            WorkerEvent::ProviderFinished {
                                generation,
                                source,
                                entries: output.entries,
                                warnings: output.warnings,
                            },
                        );
                    });
                }
            });
            send(&sender, &context, WorkerEvent::ScanFinished { generation });
        });
}

pub(crate) fn send(sender: &SyncSender<WorkerEvent>, context: &egui::Context, event: WorkerEvent) {
    if sender.send(event).is_ok() {
        context.request_repaint();
    }
}
