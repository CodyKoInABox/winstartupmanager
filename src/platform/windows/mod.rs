mod registry;
mod services;
mod shell;
mod startup_folder;
mod tasks;

use crate::domain::StartupEntry;

pub use registry::{scan_registry, set_registry_enabled};
pub use services::{scan_services, set_service_enabled};
pub use shell::{is_process_elevated, open_startup_settings, restart_elevated, reveal_in_explorer};
pub use startup_folder::{scan_startup_folders, set_startup_file_enabled};
pub use tasks::{scan_scheduled_tasks, set_task_enabled};

#[derive(Debug, Default)]
pub struct ProviderOutput {
    pub entries: Vec<StartupEntry>,
    pub warnings: Vec<String>,
}

impl ProviderOutput {
    pub fn warning(error: impl Into<String>) -> Self {
        Self {
            entries: Vec::new(),
            warnings: vec![error.into()],
        }
    }
}
