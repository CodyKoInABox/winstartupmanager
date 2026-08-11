use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Registry,
    StartupFolder,
    ScheduledTask,
    Service,
}

impl SourceKind {
    pub const ALL: [Self; 4] = [
        Self::Registry,
        Self::StartupFolder,
        Self::ScheduledTask,
        Self::Service,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Registry => "Registry",
            Self::StartupFolder => "Startup folder",
            Self::ScheduledTask => "Scheduled task",
            Self::Service => "Service",
        }
    }

    pub const fn short_label(self) -> &'static str {
        match self {
            Self::Registry => "Registry",
            Self::StartupFolder => "Folder",
            Self::ScheduledTask => "Task",
            Self::Service => "Service",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupScope {
    CurrentUser,
    AllUsers,
    System,
    ManagedPolicy,
}

impl StartupScope {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CurrentUser => "Current user",
            Self::AllUsers => "All users",
            Self::System => "System",
            Self::ManagedPolicy => "Managed by policy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Normal,
    Review,
    Caution,
    Protected,
}

impl RiskLevel {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Normal => "Normal",
            Self::Review => "Review",
            Self::Caution => "Caution",
            Self::Protected => "Protected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    SignIn,
    Boot,
    SignInAndBoot,
    AutomaticService,
    DelayedService,
    RunOnce,
    Policy,
}

impl TriggerKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::SignIn => "At sign-in",
            Self::Boot => "At boot",
            Self::SignInAndBoot => "At sign-in and boot",
            Self::AutomaticService => "Automatic service",
            Self::DelayedService => "Delayed service",
            Self::RunOnce => "Once at sign-in",
            Self::Policy => "Policy sign-in",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryHive {
    CurrentUser,
    LocalMachine,
}

impl RegistryHive {
    pub const fn label(self) -> &'static str {
        match self {
            Self::CurrentUser => "HKEY_CURRENT_USER",
            Self::LocalMachine => "HKEY_LOCAL_MACHINE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryView {
    Default,
    Registry32,
    Registry64,
}

impl RegistryView {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Default => "native",
            Self::Registry32 => "32-bit",
            Self::Registry64 => "64-bit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceLocator {
    Registry {
        hive: RegistryHive,
        view: RegistryView,
        key: String,
        value: String,
    },
    StartupFolder {
        path: PathBuf,
        common: bool,
    },
    ScheduledTask {
        path: String,
    },
    Service {
        name: String,
    },
}

impl SourceLocator {
    pub fn location_label(&self) -> String {
        match self {
            Self::Registry {
                hive,
                view,
                key,
                value,
            } => format!("{}\\{} → {} ({})", hive.label(), key, value, view.label()),
            Self::StartupFolder { path, .. } => path.display().to_string(),
            Self::ScheduledTask { path } => path.clone(),
            Self::Service { name } => format!("Service Control Manager → {name}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub executable: Option<PathBuf>,
    pub description: Option<String>,
    pub publisher: Option<String>,
    pub source: SourceKind,
    pub scope: StartupScope,
    pub trigger: TriggerKind,
    pub risk: RiskLevel,
    pub enabled: bool,
    pub can_toggle: bool,
    pub requires_admin: bool,
    pub is_system: bool,
    pub target_exists: Option<bool>,
    pub fingerprint: String,
    pub locator: SourceLocator,
}

impl StartupEntry {
    pub fn source_location(&self) -> String {
        self.locator.location_label()
    }

    pub fn search_text(&self) -> String {
        format!(
            "{} {} {} {} {} {}",
            self.name,
            self.command,
            self.publisher.as_deref().unwrap_or_default(),
            self.source.label(),
            self.scope.label(),
            self.source_location()
        )
        .to_lowercase()
    }

    pub fn display_executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }
}

pub fn stable_id(parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex()[..20].to_string()
}

pub fn fingerprint(parts: &[&[u8]]) -> String {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
        hasher.update(&[0]);
    }
    hasher.finalize().to_hex().to_string()
}

pub fn extract_executable(command: &str) -> Option<PathBuf> {
    let expanded = expand_environment(command.trim());
    if expanded.is_empty() {
        return None;
    }

    let candidate = if let Some(rest) = expanded.strip_prefix('"') {
        rest.find('"').map(|end| &rest[..end]).unwrap_or(rest)
    } else {
        let lower = expanded.to_ascii_lowercase();
        [".exe", ".com", ".bat", ".cmd", ".ps1"]
            .iter()
            .filter_map(|suffix| lower.find(suffix).map(|index| index + suffix.len()))
            .min()
            .map(|end| &expanded[..end])
            .unwrap_or_else(|| expanded.split_whitespace().next().unwrap_or_default())
    };

    let candidate = candidate.trim().trim_matches('"');
    (!candidate.is_empty()).then(|| PathBuf::from(candidate))
}

pub fn expand_environment(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        if chars[index] == '%'
            && let Some(relative_end) = chars[index + 1..]
                .iter()
                .position(|character| *character == '%')
        {
            let end = index + 1 + relative_end;
            let key: String = chars[index + 1..end].iter().collect();
            if let Some(value) = environment_value(&key) {
                output.push_str(&value);
            } else {
                output.extend(chars[index..=end].iter());
            }
            index = end + 1;
            continue;
        }

        output.push(chars[index]);
        index += 1;
    }

    output
}

fn environment_value(key: &str) -> Option<String> {
    std::env::var(key).ok().or_else(|| {
        std::env::vars()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_change_with_provenance() {
        assert_eq!(stable_id(&["a", "b"]), stable_id(&["a", "b"]));
        assert_ne!(stable_id(&["a", "b"]), stable_id(&["a", "c"]));
    }

    #[test]
    fn extracts_quoted_executable() {
        assert_eq!(
            extract_executable(r#""C:\Program Files\Acme\acme.exe" --silent"#),
            Some(PathBuf::from(r"C:\Program Files\Acme\acme.exe"))
        );
    }

    #[test]
    fn extracts_unquoted_executable_with_spaces() {
        assert_eq!(
            extract_executable(r"C:\Program Files\Acme\acme.exe --silent"),
            Some(PathBuf::from(r"C:\Program Files\Acme\acme.exe"))
        );
    }
}
