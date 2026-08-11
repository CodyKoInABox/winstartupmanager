use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Windows denied access. Restart Win Startup Manager as administrator and try again.")]
    PermissionDenied,

    #[error("This startup entry changed since it was scanned. Refresh before changing it.")]
    StaleEntry,

    #[error("Cannot restore this entry because something else now uses its original location: {0}")]
    RestoreConflict(String),

    #[error("The startup entry no longer exists: {0}")]
    NotFound(String),

    #[error("This entry is protected because changing it could make Windows unstable")]
    ProtectedEntry,

    #[error("Win Startup Manager state is unavailable at {path}: {source}")]
    StateIo {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Could not read saved state: {0}")]
    StateFormat(#[from] serde_json::Error),

    #[error("{0}")]
    Platform(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    #[cfg(windows)]
    pub fn from_io(error: std::io::Error) -> Self {
        match error.raw_os_error() {
            Some(5) => Self::PermissionDenied,
            _ => Self::Io(error),
        }
    }
}
