//! Read-only provider smoke test for contributors.
//!
//! Run with `cargo run --example scan` on Windows. This never changes startup state.

#[cfg(windows)]
fn main() {
    use win_startup_manager::domain::SourceKind;
    use win_startup_manager::{platform, state::StateStore};

    let (store, state_warning) = StateStore::load_or_default();
    if let Some(warning) = state_warning {
        eprintln!("state: {warning}");
    }

    for (source, output) in [
        (SourceKind::Registry, platform::scan_registry(&store)),
        (
            SourceKind::StartupFolder,
            platform::scan_startup_folders(&store),
        ),
        (
            SourceKind::ScheduledTask,
            platform::scan_scheduled_tasks(&store),
        ),
        (SourceKind::Service, platform::scan_services(&store)),
    ] {
        let enabled = output.entries.iter().filter(|entry| entry.enabled).count();
        let disabled = output.entries.len() - enabled;
        println!(
            "{}: {} entries ({} active, {} prevented), {} warning(s)",
            source.label(),
            output.entries.len(),
            enabled,
            disabled,
            output.warnings.len()
        );
        for warning in output.warnings {
            eprintln!("  warning: {warning}");
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The startup providers are available on Windows only.");
}
