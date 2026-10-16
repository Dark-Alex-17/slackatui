use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const KEYCHAIN_SERVICE: &str = "slackatui";

/// The longest command line, excluding the trailing newline, that `security -i`
/// reads as one command; longer input is split and executed as several commands.
const KEYCHAIN_LINE_MAX: usize = 4095;

/// Persisted tokens for a workspace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoredTokens {
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub user_token: String,
    #[serde(default)]
    pub cookie: String,
    pub team_id: String,
    #[serde(default)]
    pub team_name: String,
    #[serde(default)]
    pub user_id: String,
    #[serde(default)]
    pub bot_user_id: String,
    #[serde(default)]
    pub bot_scope: String,
    #[serde(default)]
    pub user_scope: String,
    #[serde(default)]
    pub saved_at: Option<DateTime<Utc>>,
}

/// Which storage backend to use for tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreType {
    Keychain,
    File,
}

impl StoreType {
    pub fn from_str(s: &str) -> Result<Self, StoreError> {
        match s {
            "keychain" | "" => Ok(StoreType::Keychain),
            "file" => Ok(StoreType::File),
            other => Err(StoreError::UnknownStore(other.to_string())),
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    Io(String),
    Json(String),
    KeychainError(String),
    NotFound(String),
    UnknownStore(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(msg) => write!(f, "store I/O error: {}", msg),
            StoreError::Json(msg) => write!(f, "store JSON error: {}", msg),
            StoreError::KeychainError(msg) => write!(f, "keychain error: {}", msg),
            StoreError::NotFound(msg) => write!(f, "tokens not found: {}", msg),
            StoreError::UnknownStore(s) => write!(f, "unknown token store: {}", s),
        }
    }
}

impl std::error::Error for StoreError {}

/// Returns the default path for file-based token storage.
pub fn token_file_path() -> PathBuf {
    let config_dir = dirs::config_dir().unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config")
    });
    config_dir.join("slackatui").join("tokens.json")
}

fn account_key(team_id: &str) -> &str {
    if team_id.is_empty() {
        "default"
    } else {
        team_id
    }
}

// --- Keychain backend (macOS `security` CLI) ---

/// Save tokens to macOS Keychain.
/// Always stores under the team_id key AND under "default" so that loading
/// without a specific team_id finds the most recently stored tokens.
pub fn store_tokens_keychain(tokens: &StoredTokens) -> Result<(), StoreError> {
    let data = serde_json::to_string(tokens).map_err(|e| StoreError::Json(e.to_string()))?;
    let account = account_key(&tokens.team_id);

    // Store under the team-specific key
    keychain_set(account, &data)?;

    // Also store under "default" so load_tokens with empty team_id works
    if account != "default" {
        keychain_set("default", &data)?;
    }

    Ok(())
}

/// Read credentials from `SLACK_TOKEN` and `SLACK_COOKIE`, bypassing the token store.
/// Returns `None` when `SLACK_TOKEN` is unset or empty.
pub fn tokens_from_env() -> Option<StoredTokens> {
    tokens_from_env_values(
        std::env::var("SLACK_TOKEN").ok(),
        std::env::var("SLACK_COOKIE").ok(),
    )
}

fn tokens_from_env_values(token: Option<String>, cookie: Option<String>) -> Option<StoredTokens> {
    let token = token.map(|t| t.trim().to_string()).filter(|t| !t.is_empty())?;
    Some(StoredTokens {
        user_token: token,
        cookie: cookie.map(|c| c.trim().to_string()).unwrap_or_default(),
        ..Default::default()
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

/// The `security -i` command line that upserts `data` under `account`.
/// The secret is hex-encoded (`-X`) so it never appears on a process argument list.
fn keychain_add_command(account: &str, data: &str) -> Result<String, StoreError> {
    // `security -i` tokenises the line on whitespace, so the account must not be
    // able to smuggle in further arguments or commands.
    let account_ok = !account.is_empty()
        && account
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if !account_ok {
        return Err(StoreError::KeychainError(format!(
            "invalid keychain account {:?}",
            account
        )));
    }
    let line = format!(
        "add-generic-password -a {} -s {} -U -X {}\n",
        account,
        KEYCHAIN_SERVICE,
        hex_upper(data.as_bytes())
    );
    let command_len = line.len() - 1;
    if command_len > KEYCHAIN_LINE_MAX {
        return Err(StoreError::KeychainError(format!(
            "keychain payload too large ({} bytes; security -i accepts at most {} per command)",
            command_len, KEYCHAIN_LINE_MAX
        )));
    }
    Ok(line)
}

fn keychain_set(account: &str, data: &str) -> Result<(), StoreError> {
    use std::io::Write;

    let command = keychain_add_command(account, data)?;
    let mut child = Command::new("security")
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| StoreError::KeychainError(e.to_string()))?;

    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| StoreError::KeychainError("security stdin unavailable".to_string()))?;
        stdin
            .write_all(command.as_bytes())
            .map_err(|e| StoreError::KeychainError(e.to_string()))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| StoreError::KeychainError(e.to_string()))?;

    // `security -i` exits with the status of the last command it ran, not 0 at EOF,
    // so a rejected add-generic-password is visible here.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StoreError::KeychainError(format!(
            "add-generic-password failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Load tokens from macOS Keychain.
pub fn load_tokens_keychain(team_id: &str) -> Result<StoredTokens, StoreError> {
    let account = account_key(team_id);

    let output = Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            account,
            "-w",
        ])
        .output()
        .map_err(|e| StoreError::KeychainError(e.to_string()))?;

    if !output.status.success() {
        return Err(StoreError::NotFound(format!(
            "no tokens in keychain for team {:?}",
            account
        )));
    }

    let raw = String::from_utf8_lossy(&output.stdout);
    let tokens: StoredTokens =
        serde_json::from_str(raw.trim()).map_err(|e| StoreError::Json(e.to_string()))?;

    Ok(tokens)
}

// --- File backend ---

/// Save tokens to a JSON file with restricted permissions.
/// Supports multi-team storage keyed by team_id.
pub fn store_tokens_file(tokens: &StoredTokens) -> Result<(), StoreError> {
    store_tokens_file_at(tokens, &token_file_path())
}

/// Save tokens to a specific path (used for testing).
pub fn store_tokens_file_at(tokens: &StoredTokens, path: &std::path::Path) -> Result<(), StoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| StoreError::Io(e.to_string()))?;
    }

    // Load existing multi-team token file
    let mut all_tokens: HashMap<String, StoredTokens> = if let Ok(data) = fs::read_to_string(path)
    {
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        HashMap::new()
    };

    let key = account_key(&tokens.team_id).to_string();
    all_tokens.insert(key, tokens.clone());

    let data = serde_json::to_string_pretty(&all_tokens)
        .map_err(|e| StoreError::Json(e.to_string()))?;

    // Write with owner-only permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writer
            .write_all(data.as_bytes())
            .map_err(|e| StoreError::Io(e.to_string()))?;
    }

    #[cfg(not(unix))]
    {
        fs::write(path, &data).map_err(|e| StoreError::Io(e.to_string()))?;
    }

    Ok(())
}

/// Load tokens from the JSON file.
pub fn load_tokens_file(team_id: &str) -> Result<StoredTokens, StoreError> {
    load_tokens_file_at(team_id, &token_file_path())
}

/// Load tokens from a specific path (used for testing).
pub fn load_tokens_file_at(team_id: &str, path: &std::path::Path) -> Result<StoredTokens, StoreError> {
    let data = fs::read_to_string(path)
        .map_err(|e| StoreError::NotFound(e.to_string()))?;

    let all_tokens: HashMap<String, StoredTokens> =
        serde_json::from_str(&data).map_err(|e| StoreError::Json(e.to_string()))?;

    let key = account_key(team_id);

    if let Some(tokens) = all_tokens.get(key) {
        return Ok(tokens.clone());
    }

    // If no specific team requested, return first available
    if key == "default" {
        if let Some(tokens) = all_tokens.values().next() {
            return Ok(tokens.clone());
        }
    }

    Err(StoreError::NotFound(format!(
        "no tokens found for team {:?}",
        key
    )))
}

// --- Unified interface ---

/// Store tokens using the specified backend.
pub fn store_tokens(tokens: &StoredTokens, store_type: &StoreType) -> Result<(), StoreError> {
    match store_type {
        StoreType::Keychain => store_tokens_keychain(tokens),
        StoreType::File => store_tokens_file(tokens),
    }
}

/// Load tokens using the specified backend.
pub fn load_tokens(team_id: &str, store_type: &StoreType) -> Result<StoredTokens, StoreError> {
    match store_type {
        StoreType::Keychain => load_tokens_keychain(team_id),
        StoreType::File => load_tokens_file(team_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_tokens(team_id: &str, team_name: &str) -> StoredTokens {
        StoredTokens {
            bot_token: String::new(),
            user_token: "xoxp-test-token".to_string(),
            cookie: String::new(),
            team_id: team_id.to_string(),
            team_name: team_name.to_string(),
            user_id: "U123".to_string(),
            bot_user_id: String::new(),
            bot_scope: String::new(),
            user_scope: "channels:read,chat:write".to_string(),
            saved_at: Some(Utc::now()),
        }
    }

    #[test]
    fn test_account_key_empty() {
        assert_eq!(account_key(""), "default");
    }

    #[test]
    fn test_account_key_with_team() {
        assert_eq!(account_key("T123"), "T123");
    }

    #[test]
    fn test_store_type_from_str() {
        assert_eq!(StoreType::from_str("keychain").unwrap(), StoreType::Keychain);
        assert_eq!(StoreType::from_str("").unwrap(), StoreType::Keychain);
        assert_eq!(StoreType::from_str("file").unwrap(), StoreType::File);
        assert!(StoreType::from_str("invalid").is_err());
    }

    #[test]
    fn test_file_store_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let tokens = make_tokens("T123", "Test Team");
        store_tokens_file_at(&tokens, &path).unwrap();

        let loaded = load_tokens_file_at("T123", &path).unwrap();
        assert_eq!(loaded.user_token, "xoxp-test-token");
        assert_eq!(loaded.team_id, "T123");
        assert_eq!(loaded.team_name, "Test Team");
        assert_eq!(loaded.user_id, "U123");
        assert_eq!(loaded.user_scope, "channels:read,chat:write");
    }

    #[test]
    fn test_file_store_default_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let tokens = make_tokens("", "Default Team");
        store_tokens_file_at(&tokens, &path).unwrap();

        // Load with empty team_id should find it under "default"
        let loaded = load_tokens_file_at("", &path).unwrap();
        assert_eq!(loaded.team_name, "Default Team");
    }

    #[test]
    fn test_file_store_multi_team() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let team_a = make_tokens("TA", "Team A");
        let team_b = make_tokens("TB", "Team B");

        store_tokens_file_at(&team_a, &path).unwrap();
        store_tokens_file_at(&team_b, &path).unwrap();

        let loaded_a = load_tokens_file_at("TA", &path).unwrap();
        assert_eq!(loaded_a.team_name, "Team A");

        let loaded_b = load_tokens_file_at("TB", &path).unwrap();
        assert_eq!(loaded_b.team_name, "Team B");
    }

    #[test]
    fn test_file_store_overwrites_same_team() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let mut tokens = make_tokens("T1", "Team One");
        store_tokens_file_at(&tokens, &path).unwrap();

        tokens.user_token = "xoxp-updated".to_string();
        store_tokens_file_at(&tokens, &path).unwrap();

        let loaded = load_tokens_file_at("T1", &path).unwrap();
        assert_eq!(loaded.user_token, "xoxp-updated");
    }

    #[test]
    fn test_file_load_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.json");

        let result = load_tokens_file_at("T1", &path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StoreError::NotFound(_)));
    }

    #[test]
    fn test_file_load_team_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let tokens = make_tokens("T1", "Team One");
        store_tokens_file_at(&tokens, &path).unwrap();

        let result = load_tokens_file_at("T999", &path);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StoreError::NotFound(_)));
    }

    #[test]
    fn test_file_load_default_falls_back_to_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        // Store with a specific team ID (not "default")
        let tokens = make_tokens("T1", "Only Team");
        store_tokens_file_at(&tokens, &path).unwrap();

        // Loading with empty team_id should fall back to first available
        let loaded = load_tokens_file_at("", &path).unwrap();
        assert_eq!(loaded.team_name, "Only Team");
    }

    #[test]
    fn test_stored_tokens_serialization() {
        let tokens = make_tokens("T1", "Test");
        let json = serde_json::to_string(&tokens).unwrap();
        let parsed: StoredTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.team_id, "T1");
        assert_eq!(parsed.user_token, "xoxp-test-token");
    }

    #[test]
    fn test_stored_tokens_cookie_roundtrip() {
        let mut tokens = make_tokens("T1", "Test");
        tokens.cookie = "xoxd-cookie".to_string();
        let json = serde_json::to_string(&tokens).unwrap();
        let parsed: StoredTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cookie, "xoxd-cookie");
    }

    #[test]
    fn test_stored_tokens_legacy_without_cookie() {
        let json = r#"{"team_id":"T1","user_token":"xoxp-a"}"#;
        let parsed: StoredTokens = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.user_token, "xoxp-a");
        assert_eq!(parsed.cookie, "");
    }

    #[test]
    fn test_tokens_from_env_values_with_cookie() {
        let tokens =
            tokens_from_env_values(Some("xoxc-x".to_string()), Some("xoxd-y".to_string())).unwrap();
        assert_eq!(tokens.user_token, "xoxc-x");
        assert_eq!(tokens.cookie, "xoxd-y");
        assert_eq!(tokens.team_id, "");
    }

    #[test]
    fn test_tokens_from_env_values_without_cookie() {
        let tokens = tokens_from_env_values(Some("xoxc-x".to_string()), None).unwrap();
        assert_eq!(tokens.user_token, "xoxc-x");
        assert_eq!(tokens.cookie, "");
    }

    #[test]
    fn test_tokens_from_env_values_empty_token() {
        assert!(tokens_from_env_values(Some(String::new()), Some("xoxd-y".to_string())).is_none());
        assert!(tokens_from_env_values(Some("  ".to_string()), Some("xoxd-y".to_string())).is_none());
    }

    #[test]
    fn test_tokens_from_env_values_trims_whitespace() {
        let tokens =
            tokens_from_env_values(Some("xoxc-x\n".to_string()), Some(" xoxd-y\n".to_string()))
                .unwrap();
        assert_eq!(tokens.user_token, "xoxc-x");
        assert_eq!(tokens.cookie, "xoxd-y");
    }

    #[test]
    fn test_tokens_from_env_values_missing_token() {
        assert!(tokens_from_env_values(None, Some("xoxd-y".to_string())).is_none());
        assert!(tokens_from_env_values(None, None).is_none());
    }

    #[test]
    fn test_hex_upper() {
        assert_eq!(hex_upper(b"ab"), "6162");
        assert_eq!(hex_upper(b""), "");
        assert_eq!(hex_upper(&[0x00, 0xff]), "00FF");
    }

    #[test]
    fn test_keychain_add_command() {
        let secret = "{\"a\":1}";
        let cmd = keychain_add_command("T1", secret).unwrap();
        assert_eq!(
            cmd,
            "add-generic-password -a T1 -s slackatui -U -X 7B2261223A317D\n"
        );
        assert!(!cmd.contains(secret));
    }

    #[test]
    fn test_keychain_add_command_rejects_unsafe_account() {
        assert!(keychain_add_command("T1 -w", "x").is_err());
        assert!(keychain_add_command("T1\n", "x").is_err());
        assert!(keychain_add_command("", "x").is_err());
        assert!(keychain_add_command("default", "x").is_ok());
    }

    #[test]
    fn test_keychain_add_command_line_length_boundary() {
        let prefix = keychain_add_command("T1", "").unwrap();
        let prefix_len = prefix.len() - 1;
        assert_eq!(prefix_len, "add-generic-password -a T1 -s slackatui -U -X ".len());

        // Hex encoding doubles the data length, so this is the largest payload
        // whose command line still fits within KEYCHAIN_LINE_MAX.
        let max_data_len = (KEYCHAIN_LINE_MAX - prefix_len) / 2;
        let fits = "a".repeat(max_data_len);
        let line = keychain_add_command("T1", &fits).unwrap();
        assert_eq!(line.len() - 1, prefix_len + 2 * max_data_len);
        assert!(line.len() - 1 <= KEYCHAIN_LINE_MAX);

        let too_big = "a".repeat(max_data_len + 1);
        assert!(keychain_add_command("T1", &too_big).is_err());
    }

    #[test]
    fn test_token_file_path_is_reasonable() {
        let path = token_file_path();
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("slackatui"));
        assert!(path_str.ends_with("tokens.json"));
    }

    #[cfg(unix)]
    #[test]
    fn test_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");

        let tokens = make_tokens("T1", "Test");
        store_tokens_file_at(&tokens, &path).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        let mode = metadata.mode() & 0o777;
        assert_eq!(mode, 0o600, "token file should be owner-only (0600)");
    }
}
