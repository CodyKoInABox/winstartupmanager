use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};

use crate::domain::StartupEntry;
use crate::error::{AppError, AppResult};

const STATE_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedChange {
    pub id: String,
    pub changed_at_unix: u64,
    pub entry: StartupEntry,
    pub restore: RestoreData,
}

impl ManagedChange {
    pub fn new(entry: StartupEntry, restore: RestoreData) -> Self {
        Self {
            id: entry.id.clone(),
            changed_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            entry,
            restore,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RestoreData {
    Registry {
        value_type: u32,
        bytes: Vec<u8>,
    },
    StartupFile {
        original_path: PathBuf,
        parked_path: PathBuf,
    },
    Service {
        service_name: String,
        start_type: u32,
        delayed_auto_start: bool,
        #[serde(default)]
        disabled_fingerprint: Option<String>,
    },
}

/// An exclusive state transaction shared by every journal-backed mutation.
///
/// The lock lives in a separate, stable file because saving `state.json` uses
/// atomic replacement. Operating-system file locks are released if the process
/// exits unexpectedly, so a crash cannot leave the journal permanently locked.
pub struct StateTransaction {
    store: StateStore,
    _lock: StateFileLock,
}

impl StateTransaction {
    pub fn begin() -> AppResult<Self> {
        Self::begin_at(default_state_path())
    }

    fn begin_at(path: PathBuf) -> AppResult<Self> {
        let lock = StateFileLock::acquire(lock_path_for(&path))?;
        let store = StateStore::load_from(path)?;
        Ok(Self { store, _lock: lock })
    }

    pub fn store_mut(&mut self) -> &mut StateStore {
        &mut self.store
    }
}

struct StateFileLock {
    file: File,
}

impl StateFileLock {
    fn acquire(path: PathBuf) -> AppResult<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|source| AppError::StateIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| AppError::StateIo {
                path: path.clone(),
                source,
            })?;
        file.lock().map_err(|source| AppError::StateIo {
            path: path.clone(),
            source,
        })?;
        Ok(Self { file })
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        if let Err(error) = self.file.unlock() {
            tracing::warn!(?error, "state transaction lock could not be released");
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateStore {
    schema: u32,
    #[serde(default)]
    changes: Vec<ManagedChange>,
    #[serde(skip)]
    path: PathBuf,
}

impl Default for StateStore {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            changes: Vec::new(),
            path: default_state_path(),
        }
    }
}

impl StateStore {
    pub fn load() -> AppResult<Self> {
        Self::load_from(default_state_path())
    }

    pub fn load_or_default() -> (Self, Option<String>) {
        match Self::load() {
            Ok(store) => (store, None),
            Err(error) => {
                let mut store = Self::default();
                store.changes.clear();
                (
                    store,
                    Some(format!("Saved change history could not be read: {error}")),
                )
            }
        }
    }

    pub fn load_from(path: PathBuf) -> AppResult<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                ..Self::default()
            });
        }

        let bytes = fs::read(&path).map_err(|source| AppError::StateIo {
            path: path.clone(),
            source,
        })?;
        let mut store: Self = serde_json::from_slice(&bytes)?;
        if store.schema > STATE_SCHEMA {
            return Err(AppError::Platform(format!(
                "Saved state uses newer schema {} (this build supports {})",
                store.schema, STATE_SCHEMA
            )));
        }
        store.path = path;
        Ok(store)
    }

    pub fn changes(&self) -> &[ManagedChange] {
        &self.changes
    }

    pub fn find(&self, id: &str) -> Option<&ManagedChange> {
        self.changes.iter().find(|change| change.id == id)
    }

    pub fn add(&mut self, change: ManagedChange) -> AppResult<()> {
        if self.find(&change.id).is_some() {
            return Ok(());
        }
        self.changes.push(change);
        if let Err(error) = self.save() {
            self.changes.pop();
            return Err(error);
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> AppResult<Option<ManagedChange>> {
        let Some(index) = self.changes.iter().position(|change| change.id == id) else {
            return Ok(None);
        };
        let change = self.changes.remove(index);
        if let Err(error) = self.save() {
            self.changes.insert(index, change);
            return Err(error);
        }
        Ok(Some(change))
    }

    pub fn save(&self) -> AppResult<()> {
        self.save_to(&self.path)
    }

    fn save_to(&self, path: &Path) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| AppError::StateIo {
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let bytes = serde_json::to_vec_pretty(self)?;
        let mut file =
            AtomicWriteFile::options()
                .open(path)
                .map_err(|source| AppError::StateIo {
                    path: path.to_path_buf(),
                    source,
                })?;
        file.write_all(&bytes)
            .and_then(|_| file.commit())
            .map_err(|source| AppError::StateIo {
                path: path.to_path_buf(),
                source,
            })
    }
}

pub fn default_state_path() -> PathBuf {
    directories::ProjectDirs::from("dev", "WinStartupManager", "Win Startup Manager")
        .map(|project| project.data_local_dir().join("state.json"))
        .unwrap_or_else(|| PathBuf::from("win-startup-manager-state.json"))
}

fn lock_path_for(state_path: &Path) -> PathBuf {
    let mut path = OsString::from(state_path.as_os_str());
    path.push(".lock");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{RiskLevel, SourceKind, SourceLocator, StartupScope, TriggerKind};

    fn example_entry() -> StartupEntry {
        StartupEntry {
            id: "example".into(),
            name: "Example".into(),
            command: r"C:\Example.exe".into(),
            executable: Some(r"C:\Example.exe".into()),
            description: None,
            publisher: None,
            source: SourceKind::Service,
            scope: StartupScope::System,
            trigger: TriggerKind::AutomaticService,
            risk: RiskLevel::Caution,
            enabled: true,
            can_toggle: true,
            requires_admin: true,
            is_system: false,
            target_exists: Some(false),
            fingerprint: "fingerprint".into(),
            locator: SourceLocator::Service {
                name: "example".into(),
            },
        }
    }

    #[test]
    fn state_round_trip_is_lossless() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut store = StateStore::load_from(path.clone()).unwrap();
        store
            .add(ManagedChange::new(
                example_entry(),
                RestoreData::Service {
                    service_name: "example".into(),
                    start_type: 2,
                    delayed_auto_start: true,
                    disabled_fingerprint: Some("disabled-fingerprint".into()),
                },
            ))
            .unwrap();

        let loaded = StateStore::load_from(path).unwrap();
        assert_eq!(loaded.changes().len(), 1);
        assert_eq!(loaded.changes()[0].entry.name, "Example");
        let RestoreData::Service {
            disabled_fingerprint,
            ..
        } = &loaded.changes()[0].restore
        else {
            panic!("expected service recovery data");
        };
        assert_eq!(
            disabled_fingerprint.as_deref(),
            Some("disabled-fingerprint")
        );
    }

    #[test]
    fn transaction_uses_a_stable_exclusive_lock_file() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        let transaction = StateTransaction::begin_at(state_path.clone()).unwrap();

        let lock_path = lock_path_for(&state_path);
        let competing_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        assert!(matches!(
            competing_file.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));

        drop(transaction);
        competing_file.try_lock().unwrap();
        competing_file.unlock().unwrap();
    }

    #[test]
    fn service_recovery_data_without_disabled_fingerprint_is_supported() {
        let serialized = serde_json::json!({
            "schema": STATE_SCHEMA,
            "changes": [{
                "id": "example",
                "changed_at_unix": 0,
                "entry": example_entry(),
                "restore": {
                    "type": "service",
                    "service_name": "example",
                    "start_type": 2,
                    "delayed_auto_start": true
                }
            }]
        });

        let loaded: StateStore = serde_json::from_value(serialized).unwrap();
        let RestoreData::Service {
            disabled_fingerprint,
            ..
        } = &loaded.changes()[0].restore
        else {
            panic!("expected service recovery data");
        };
        assert_eq!(disabled_fingerprint, &None);
    }
}
