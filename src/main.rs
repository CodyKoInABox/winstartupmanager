#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result {
    let _log_guard = init_logging();

    #[cfg(not(windows))]
    {
        eprintln!("Win Startup Manager currently supports Windows 10 and Windows 11 only.");
        return Ok(());
    }

    #[cfg(windows)]
    {
        let native_options = eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_title(win_startup_manager::APP_NAME)
                .with_inner_size([1220.0, 780.0])
                .with_min_inner_size([920.0, 620.0])
                .with_app_id("dev.winstartupmanager.app")
                .with_icon(eframe::egui::IconData {
                    rgba: win_startup_manager::icon::app_icon_rgba(64),
                    width: 64,
                    height: 64,
                }),
            renderer: eframe::Renderer::Wgpu,
            ..Default::default()
        };

        eframe::run_native(
            win_startup_manager::APP_NAME,
            native_options,
            Box::new(|creation_context| {
                Ok(Box::new(win_startup_manager::app::StartupManagerApp::new(
                    creation_context,
                )))
            }),
        )
    }
}

fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let project =
        directories::ProjectDirs::from("dev", "WinStartupManager", "Win Startup Manager")?;
    let log_dir = project.data_local_dir().join("logs");
    std::fs::create_dir_all(&log_dir).ok()?;

    let appender = tracing_appender::rolling::daily(log_dir, "startup-manager.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(writer)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    Some(guard)
}
