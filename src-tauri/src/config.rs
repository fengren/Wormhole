use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TunnelType {
    Local,
    Remote,
    Dynamic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Password,
    Key,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: AuthMethod,
    pub key_path: Option<String>,
    pub tunnel_type: TunnelType,
    pub local_port: u16,
    pub remote_host: Option<String>,
    pub remote_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    pub connections: Vec<SshConfig>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            connections: Vec::new(),
        }
    }
}

pub fn app_config_dir() -> PathBuf {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("wormhole");
    std::fs::create_dir_all(&dir).ok();
    dir
}

fn config_path() -> PathBuf {
    app_config_dir().join("config.json")
}

pub fn load_state() -> AppState {
    let path = config_path();
    if path.exists() {
        let data = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&data).unwrap_or_default()
    } else {
        AppState::default()
    }
}

pub fn save_state(state: &AppState) -> anyhow::Result<()> {
    let path = config_path();
    let data = serde_json::to_string_pretty(state)?;
    std::fs::write(path, data)?;
    Ok(())
}
