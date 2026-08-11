#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
mod unsupported {
    use std::path::Path;

    use crate::domain::StartupEntry;
    use crate::error::{AppError, AppResult};
    use crate::state::StateStore;

    #[derive(Debug, Default)]
    pub struct ProviderOutput {
        pub entries: Vec<StartupEntry>,
        pub warnings: Vec<String>,
    }

    fn unsupported() -> AppError {
        AppError::Platform("Win Startup Manager only supports Windows".into())
    }

    pub fn scan_registry(_: &StateStore) -> ProviderOutput {
        ProviderOutput::default()
    }

    pub fn scan_startup_folders(_: &StateStore) -> ProviderOutput {
        ProviderOutput::default()
    }

    pub fn scan_scheduled_tasks(_: &StateStore) -> ProviderOutput {
        ProviderOutput::default()
    }

    pub fn scan_services(_: &StateStore) -> ProviderOutput {
        ProviderOutput::default()
    }

    pub fn set_registry_enabled(_: &StartupEntry, _: bool, _: &mut StateStore) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn set_startup_file_enabled(
        _: &StartupEntry,
        _: bool,
        _: &mut StateStore,
    ) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn set_task_enabled(_: &StartupEntry, _: bool) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn set_service_enabled(_: &StartupEntry, _: bool, _: &mut StateStore) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn is_process_elevated() -> bool {
        false
    }

    pub fn restart_elevated() -> AppResult<()> {
        Err(unsupported())
    }

    pub fn reveal_in_explorer(_: &Path) -> AppResult<()> {
        Err(unsupported())
    }

    pub fn open_startup_settings() -> AppResult<()> {
        Err(unsupported())
    }
}

#[cfg(not(windows))]
pub use unsupported::*;
