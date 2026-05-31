mod config;
mod keychain;

use config::{AuthMethod, AuthProfile, SshConfig, StartMode, TunnelType};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    io::Write,
    net::{Shutdown, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{
    image::Image,
    menu::MenuBuilder,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, PhysicalPosition, State, WebviewUrl, WebviewWindowBuilder,
    WindowEvent,
};
use uuid::Uuid;

const MENU_SHOW: &str = "show";
const MENU_HIDE: &str = "hide";
const MENU_START_SERVICE: &str = "start_service";
const MENU_STOP_SERVICE: &str = "stop_service";
const TRAY_ID: &str = "wormhole";
const TRAY_ICON_SIZE: usize = 18;
const QUICK_PANEL_LABEL: &str = "quick-panel";
const QUICK_PANEL_WIDTH: f64 = 360.0;
const QUICK_PANEL_HEIGHT: f64 = 480.0;
const ON_DEMAND_READY_ATTEMPTS: usize = 100;
const ON_DEMAND_READY_SLEEP: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TunnelStatus {
    Stopped,
    Running,
    Exited,
    Dormant,
    NeedsAuth,
}

#[derive(Debug, Clone, Serialize)]
struct ConnectionView {
    #[serde(flatten)]
    config: SshConfig,
    status: TunnelStatus,
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectionInput {
    id: Option<String>,
    name: String,
    host: String,
    port: u16,
    username: String,
    auth_method: AuthMethod,
    password: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
    tunnel_type: TunnelType,
    local_port: u16,
    remote_host: Option<String>,
    remote_port: Option<u16>,
    auth_profile: AuthProfile,
    start_mode: StartMode,
    auto_reconnect: bool,
    idle_timeout_seconds: u64,
}

struct RuntimeState {
    children: Mutex<HashMap<String, Child>>,
    traffic: Mutex<Option<TrafficSnapshot>>,
    desired: Mutex<HashSet<String>>,
    on_demand: Mutex<HashMap<String, OnDemandHandle>>,
    upstream_ports: Mutex<HashMap<String, u16>>,
    last_activity: Mutex<HashMap<String, Instant>>,
    needs_auth: Mutex<HashSet<String>>,
}

struct OnDemandHandle {
    stop: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
struct TrafficSnapshot {
    captured_at: Instant,
    bytes_total: u64,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceReport {
    total: usize,
    running: usize,
    started: usize,
    clients: usize,
    failed: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceStatus {
    total: usize,
    running: usize,
    clients: usize,
    traffic_bytes_per_second: u64,
    traffic_bytes_total: u64,
}

fn validate_config(config: &SshConfig) -> Result<(), String> {
    if config.name.trim().is_empty() {
        return Err("Connection name is required.".into());
    }
    if config.host.trim().is_empty() {
        return Err("SSH host is required.".into());
    }
    if config.username.trim().is_empty() {
        return Err("Username is required.".into());
    }
    if config.port == 0 || config.local_port == 0 {
        return Err("Ports must be between 1 and 65535.".into());
    }
    if matches!(config.auth_method, AuthMethod::Key)
        && config.key_path.as_deref().unwrap_or("").trim().is_empty()
    {
        return Err("Key path is required for key authentication.".into());
    }
    if !matches!(config.tunnel_type, TunnelType::Dynamic) {
        if config
            .remote_host
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err("Remote host is required for local and remote tunnels.".into());
        }
        if config.remote_port.unwrap_or(0) == 0 {
            return Err("Remote port is required for local and remote tunnels.".into());
        }
    }
    Ok(())
}

fn to_config(input: ConnectionInput) -> SshConfig {
    let auth_profile = input.auth_profile;
    let start_mode = if matches!(auth_profile, AuthProfile::Mfa)
        || matches!(input.tunnel_type, TunnelType::Remote)
    {
        match input.start_mode {
            StartMode::OnDemand => StartMode::Always,
            mode => mode,
        }
    } else {
        input.start_mode
    };

    SshConfig {
        id: input.id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        name: input.name.trim().to_string(),
        host: input.host.trim().to_string(),
        port: input.port,
        username: input.username.trim().to_string(),
        auth_method: input.auth_method,
        key_path: input
            .key_path
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty()),
        tunnel_type: input.tunnel_type,
        local_port: input.local_port,
        remote_host: input
            .remote_host
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty()),
        remote_port: input.remote_port,
        auth_profile,
        start_mode,
        auto_reconnect: input.auto_reconnect,
        idle_timeout_seconds: input.idle_timeout_seconds.max(30),
    }
}

fn mark_status(runtime: &RuntimeState, id: &str) -> TunnelStatus {
    let mut children = runtime.children.lock().expect("runtime lock poisoned");
    if let Some(child) = children.get_mut(id) {
        match child.try_wait() {
            Ok(Some(_)) => {
                children.remove(id);
                TunnelStatus::Exited
            }
            Ok(None) => TunnelStatus::Running,
            Err(_) => {
                children.remove(id);
                TunnelStatus::Exited
            }
        }
    } else {
        TunnelStatus::Stopped
    }
}

fn find_config(id: &str) -> Result<SshConfig, String> {
    config::load_state()
        .connections
        .into_iter()
        .find(|connection| connection.id == id)
        .ok_or_else(|| "Connection not found.".to_string())
}

fn connection_view(
    runtime: &RuntimeState,
    config: SshConfig,
    listening_ports: &HashSet<u16>,
) -> ConnectionView {
    let status = tunnel_status(runtime, &config, listening_ports);
    ConnectionView { config, status }
}

fn tunnel_status(
    runtime: &RuntimeState,
    config: &SshConfig,
    listening_ports: &HashSet<u16>,
) -> TunnelStatus {
    match mark_status(runtime, &config.id) {
        TunnelStatus::Running => TunnelStatus::Running,
        TunnelStatus::Exited if matches!(config.auth_profile, AuthProfile::Mfa) => {
            runtime
                .needs_auth
                .lock()
                .expect("runtime lock poisoned")
                .insert(config.id.clone());
            TunnelStatus::NeedsAuth
        }
        _ if matches!(config.auth_profile, AuthProfile::Mfa)
            && runtime
                .needs_auth
                .lock()
                .expect("runtime lock poisoned")
                .contains(&config.id) =>
        {
            TunnelStatus::NeedsAuth
        }
        _ if has_on_demand_listener(runtime, &config.id) => TunnelStatus::Dormant,
        _ if !matches!(config.tunnel_type, TunnelType::Remote)
            && listening_ports.contains(&config.local_port) =>
        {
            TunnelStatus::Running
        }
        status => status,
    }
}

fn has_on_demand_listener(runtime: &RuntimeState, id: &str) -> bool {
    runtime
        .on_demand
        .lock()
        .expect("runtime lock poisoned")
        .contains_key(id)
}

fn active_tunnel_ids(runtime: &RuntimeState) -> HashSet<String> {
    let mut children = runtime.children.lock().expect("runtime lock poisoned");
    let mut inactive = Vec::new();

    for (id, child) in children.iter_mut() {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => inactive.push(id.clone()),
            Ok(None) => {}
        }
    }

    for id in inactive {
        children.remove(&id);
    }

    children.keys().cloned().collect()
}

fn askpass_path() -> Result<std::path::PathBuf, String> {
    let path = config::app_config_dir().join("askpass.sh");
    let script = "#!/bin/sh\nprintf '%s\\n' \"$WORMHOLE_ASKPASS_PASSWORD\"\n";
    fs::write(&path, script).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|err| err.to_string())?;
    }
    Ok(path)
}

#[cfg(test)]
fn tunnel_arg(config: &SshConfig) -> String {
    tunnel_arg_with_local_port(config, config.local_port)
}

fn tunnel_arg_with_local_port(config: &SshConfig, local_port: u16) -> String {
    match config.tunnel_type {
        TunnelType::Local => format!(
            "{}:{}:{}",
            local_port,
            config.remote_host.as_deref().unwrap_or("127.0.0.1"),
            config.remote_port.unwrap_or(0)
        ),
        TunnelType::Remote => format!(
            "{}:{}:{}",
            local_port,
            config.remote_host.as_deref().unwrap_or("127.0.0.1"),
            config.remote_port.unwrap_or(0)
        ),
        TunnelType::Dynamic => local_port.to_string(),
    }
}

fn spawn_ssh(config: &SshConfig, local_port_override: Option<u16>) -> Result<Child, String> {
    let local_port = local_port_override.unwrap_or(config.local_port);
    let mut command = Command::new("ssh");
    command
        .arg("-N")
        .arg("-T")
        .arg("-p")
        .arg(config.port.to_string())
        .arg("-o")
        .arg("ExitOnForwardFailure=yes")
        .arg("-o")
        .arg("ServerAliveInterval=30")
        .arg("-o")
        .arg("ServerAliveCountMax=3")
        .arg("-o")
        .arg("StrictHostKeyChecking=accept-new");

    match config.tunnel_type {
        TunnelType::Local => {
            command.arg("-L").arg(tunnel_arg_with_local_port(config, local_port));
        }
        TunnelType::Remote => {
            command.arg("-R").arg(tunnel_arg_with_local_port(config, local_port));
        }
        TunnelType::Dynamic => {
            command.arg("-D").arg(tunnel_arg_with_local_port(config, local_port));
        }
    }

    match config.auth_method {
        AuthMethod::Key => {
            if let Some(path) = &config.key_path {
                command.arg("-i").arg(path);
            }
            if let Ok(passphrase) = keychain::get_key_passphrase(&config.id) {
                let askpass = askpass_path()?;
                command
                    .env("SSH_ASKPASS", askpass)
                    .env("SSH_ASKPASS_REQUIRE", "force")
                    .env("DISPLAY", "wormhole")
                    .env("WORMHOLE_ASKPASS_PASSWORD", passphrase);
            }
        }
        AuthMethod::Password => {
            let password = keychain::get_password(&config.id)
                .map_err(|_| "Password is missing. Save the connection with a password first.")?;
            let askpass = askpass_path()?;
            command
                .env("SSH_ASKPASS", askpass)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env("DISPLAY", "wormhole")
                .env("WORMHOLE_ASKPASS_PASSWORD", password);
        }
    }

    command
        .arg(format!("{}@{}", config.username, config.host))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                "Could not find the ssh command on this Mac.".to_string()
            } else {
                err.to_string()
            }
        })
}

fn start_config(
    runtime: &RuntimeState,
    config: SshConfig,
    app: Option<AppHandle>,
) -> Result<ConnectionView, String> {
    validate_config(&config)?;

    runtime
        .desired
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone());

    if matches!(config.start_mode, StartMode::OnDemand)
        && !matches!(config.auth_profile, AuthProfile::Mfa)
        && !matches!(config.tunnel_type, TunnelType::Remote)
    {
        if let Some(app) = app {
            start_on_demand_listener(runtime, config.clone(), app)?;
            return Ok(ConnectionView {
                config,
                status: TunnelStatus::Dormant,
            });
        }
    }

    if !matches!(config.tunnel_type, TunnelType::Remote) {
        let ports = HashSet::from([config.local_port]);
        if listening_local_ports(&ports).contains(&config.local_port) {
            return Ok(ConnectionView {
                config,
                status: TunnelStatus::Running,
            });
        }
    }

    {
        let mut children = runtime.children.lock().expect("runtime lock poisoned");
        if let Some(child) = children.get_mut(&config.id) {
            if child.try_wait().map_err(|err| err.to_string())?.is_none() {
                return Ok(ConnectionView {
                    config,
                    status: TunnelStatus::Running,
                });
            }
            children.remove(&config.id);
        }
    }

    start_ssh_child(runtime, &config, None)?;

    Ok(ConnectionView {
        config,
        status: TunnelStatus::Running,
    })
}

fn start_ssh_child(
    runtime: &RuntimeState,
    config: &SshConfig,
    local_port_override: Option<u16>,
) -> Result<(), String> {
    {
        let mut children = runtime.children.lock().expect("runtime lock poisoned");
        if let Some(child) = children.get_mut(&config.id) {
            if child.try_wait().map_err(|err| err.to_string())?.is_none() {
                return Ok(());
            }
            children.remove(&config.id);
        }
    }

    let child = spawn_ssh(config, local_port_override)?;
    runtime
        .children
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), child);
    runtime
        .last_activity
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), Instant::now());
    runtime
        .needs_auth
        .lock()
        .expect("runtime lock poisoned")
        .remove(&config.id);
    Ok(())
}

fn start_on_demand_listener(
    runtime: &RuntimeState,
    config: SshConfig,
    app: AppHandle,
) -> Result<(), String> {
    if has_on_demand_listener(runtime, &config.id) {
        return Ok(());
    }

    let listener = TcpListener::bind(("127.0.0.1", config.local_port))
        .map_err(|err| format!("Could not listen on local port {}: {err}", config.local_port))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;

    let stop = Arc::new(AtomicBool::new(false));
    runtime
        .on_demand
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), OnDemandHandle { stop: stop.clone() });

    let id = config.id.clone();
    let listener_app = app.clone();
    thread::spawn(move || loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        match listener.accept() {
            Ok((client, _)) => {
                let app = app.clone();
                let id = id.clone();
                thread::spawn(move || {
                    if let Err(error) = handle_on_demand_client(&app, &id, client) {
                        eprintln!("on-demand tunnel failed for {id}: {error}");
                    }
                    update_tray_status(&app);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let runtime = listener_app.state::<RuntimeState>();
                stop_on_demand_listener(&runtime, &id);
                break;
            }
        }
    });

    Ok(())
}

fn stop_on_demand_listener(runtime: &RuntimeState, id: &str) {
    if let Some(handle) = runtime
        .on_demand
        .lock()
        .expect("runtime lock poisoned")
        .remove(id)
    {
        handle.stop.store(true, Ordering::Relaxed);
    }
    runtime
        .upstream_ports
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);
    runtime
        .needs_auth
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);
}

fn handle_on_demand_client(app: &AppHandle, id: &str, client: TcpStream) -> Result<(), String> {
    let config = find_config(id)?;
    if matches!(config.auth_profile, AuthProfile::Mfa) {
        return Err("MFA tunnels must be started manually.".to_string());
    }
    let runtime = app.state::<RuntimeState>();
    let upstream_port = ensure_on_demand_upstream(&runtime, &config)?;
    let upstream = TcpStream::connect(("127.0.0.1", upstream_port))
        .map_err(|err| format!("Could not connect to local tunnel endpoint: {err}"))?;

    runtime
        .last_activity
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), Instant::now());
    let result = proxy_streams(client, upstream);
    runtime
        .last_activity
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), Instant::now());
    result
}

fn ensure_on_demand_upstream(runtime: &RuntimeState, config: &SshConfig) -> Result<u16, String> {
    let upstream_port = {
        let mut ports = runtime
            .upstream_ports
            .lock()
            .expect("runtime lock poisoned");
        if let Some(port) = ports.get(&config.id).copied() {
            port
        } else {
            let port = allocate_loopback_port()?;
            ports.insert(config.id.clone(), port);
            port
        }
    };

    if let Err(error) = start_ssh_child(runtime, config, Some(upstream_port))
        .and_then(|_| wait_for_loopback_port(upstream_port))
    {
        stop_ssh_child(runtime, &config.id);
        runtime
            .upstream_ports
            .lock()
            .expect("runtime lock poisoned")
            .remove(&config.id);
        return Err(error);
    }

    Ok(upstream_port)
}

fn allocate_loopback_port() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|err| err.to_string())?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|err| err.to_string())
}

fn wait_for_loopback_port(port: u16) -> Result<(), String> {
    for _ in 0..ON_DEMAND_READY_ATTEMPTS {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream.shutdown(Shutdown::Both);
            return Ok(());
        }
        thread::sleep(ON_DEMAND_READY_SLEEP);
    }
    Err(format!("Timed out waiting for local tunnel endpoint on {port}."))
}

fn proxy_streams(client: TcpStream, upstream: TcpStream) -> Result<(), String> {
    let mut client_reader = client.try_clone().map_err(|err| err.to_string())?;
    let mut client_writer = client;
    let mut upstream_reader = upstream.try_clone().map_err(|err| err.to_string())?;
    let mut upstream_writer = upstream;

    let upload = thread::spawn(move || {
        let _ = io::copy(&mut client_reader, &mut upstream_writer);
        let _ = upstream_writer.flush();
        let _ = upstream_writer.shutdown(Shutdown::Write);
    });
    let download = thread::spawn(move || {
        let _ = io::copy(&mut upstream_reader, &mut client_writer);
        let _ = client_writer.flush();
        let _ = client_writer.shutdown(Shutdown::Write);
    });

    let _ = upload.join();
    let _ = download.join();
    Ok(())
}

fn stop_tunnel_by_id(runtime: &RuntimeState, id: &str) -> Result<(), String> {
    runtime
        .desired
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);
    runtime
        .needs_auth
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);
    stop_on_demand_listener(runtime, id);

    let child = runtime
        .children
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);

    if let Some(mut child) = child {
        child.kill().map_err(|err| err.to_string())?;
        let _ = child.wait();
    }

    if let Ok(config) = find_config(id) {
        stop_config_listener(&config)?;
    }

    Ok(())
}

fn start_service_with_runtime(runtime: &RuntimeState, app: Option<AppHandle>) -> ServiceReport {
    let connections = config::load_state().connections;
    let total = connections.len();
    let mut started = 0;
    let mut failed = Vec::new();

    for config in connections {
        let name = config.name.clone();
        match start_config(runtime, config, app.clone()) {
            Ok(view) => {
                if matches!(view.status, TunnelStatus::Running | TunnelStatus::Dormant) {
                    started += 1;
                }
            }
            Err(error) => failed.push(format!("{name}: {error}")),
        }
    }

    let status = service_status_with_runtime(runtime);

    ServiceReport {
        total,
        running: status.running,
        started,
        clients: status.clients,
        failed,
    }
}

fn stop_service_with_runtime(runtime: &RuntimeState) -> ServiceReport {
    let connections = config::load_state().connections;
    let child_ids: HashSet<String> = runtime
        .children
        .lock()
        .expect("runtime lock poisoned")
        .keys()
        .cloned()
        .collect();
    let total = connections.len();
    let mut failed = Vec::new();
    let mut stopped_ids = HashSet::new();

    for config in connections {
        let name = config.name.clone();
        if let Err(error) = stop_tunnel_by_id(runtime, &config.id) {
            failed.push(format!("{name}: {error}"));
        }
        stopped_ids.insert(config.id);
    }

    for id in child_ids.difference(&stopped_ids) {
        if let Err(error) = stop_tunnel_by_id(runtime, &id) {
            failed.push(format!("{id}: {error}"));
        }
    }

    let status = service_status_with_runtime(runtime);

    ServiceReport {
        total,
        running: status.running,
        started: 0,
        clients: status.clients,
        failed,
    }
}

fn stop_config_listener(config: &SshConfig) -> Result<(), String> {
    if matches!(config.tunnel_type, TunnelType::Remote) {
        return Ok(());
    }

    let ports = HashSet::from([config.local_port]);
    let pids = listening_local_port_pids(&ports);

    for pid in pids.get(&config.local_port).into_iter().flatten() {
        let _ = kill_pid(*pid);
    }

    Ok(())
}

fn kill_pid(pid: u32) -> Result<(), String> {
    let status = Command::new("kill")
        .arg(pid.to_string())
        .status()
        .map_err(|err| err.to_string())?;

    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("kill exited with {status}"))
}

fn service_status_with_runtime(runtime: &RuntimeState) -> ServiceStatus {
    let connections = config::load_state().connections;
    apply_idle_policy(runtime, &connections);
    let active_ids = active_tunnel_ids(runtime);
    let local_ports: HashSet<u16> = connections
        .iter()
        .filter(|connection| !matches!(connection.tunnel_type, TunnelType::Remote))
        .map(|connection| connection.local_port)
        .collect();
    let listening_ports = listening_local_ports(&local_ports);
    let running_by_port = connections
        .iter()
        .filter(|connection| {
            !matches!(connection.tunnel_type, TunnelType::Remote)
                && !has_on_demand_listener(runtime, &connection.id)
                && listening_ports.contains(&connection.local_port)
        })
        .count();
    let running = active_ids.len().max(running_by_port);
    let traffic = sample_tunnel_traffic(runtime, &local_ports);

    ServiceStatus {
        total: connections.len(),
        running,
        clients: count_local_clients(&local_ports),
        traffic_bytes_per_second: traffic.0,
        traffic_bytes_total: traffic.1,
    }
}

fn apply_idle_policy(runtime: &RuntimeState, connections: &[SshConfig]) {
    let client_counts = established_local_port_counts();
    let now = Instant::now();

    for config in connections {
        if matches!(config.auth_profile, AuthProfile::Mfa)
            || !matches!(config.start_mode, StartMode::OnDemand)
            || matches!(config.tunnel_type, TunnelType::Remote)
        {
            continue;
        }

        if client_counts.get(&config.local_port).copied().unwrap_or(0) > 0 {
            runtime
                .last_activity
                .lock()
                .expect("runtime lock poisoned")
                .insert(config.id.clone(), now);
            continue;
        }

        let idle_for = runtime
            .last_activity
            .lock()
            .expect("runtime lock poisoned")
            .get(&config.id)
            .map(|last_seen| now.duration_since(*last_seen))
            .unwrap_or_default();

        if idle_for.as_secs() >= config.idle_timeout_seconds {
            stop_ssh_child(runtime, &config.id);
        }
    }
}

fn stop_ssh_child(runtime: &RuntimeState, id: &str) {
    let child = runtime
        .children
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);

    if let Some(mut child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn reconcile_runtime(app: &AppHandle) {
    let runtime = app.state::<RuntimeState>();
    let connections = config::load_state().connections;
    let by_id: HashMap<String, SshConfig> = connections
        .iter()
        .cloned()
        .map(|config| (config.id.clone(), config))
        .collect();
    let desired = runtime
        .desired
        .lock()
        .expect("runtime lock poisoned")
        .clone();

    for id in desired {
        let Some(config) = by_id.get(&id) else {
            continue;
        };
        if matches!(config.auth_profile, AuthProfile::Mfa)
            || !config.auto_reconnect
            || matches!(config.start_mode, StartMode::OnDemand)
        {
            continue;
        }
        if !child_is_running(&runtime, &config.id) {
            let _ = start_ssh_child(&runtime, config, None);
        }
    }

    apply_idle_policy(&runtime, &connections);
}

fn child_is_running(runtime: &RuntimeState, id: &str) -> bool {
    let mut children = runtime.children.lock().expect("runtime lock poisoned");
    if let Some(child) = children.get_mut(id) {
        match child.try_wait() {
            Ok(None) => true,
            Ok(Some(_)) | Err(_) => {
                children.remove(id);
                false
            }
        }
    } else {
        false
    }
}

fn sample_tunnel_traffic(runtime: &RuntimeState, local_ports: &HashSet<u16>) -> (u64, u64) {
    let pids = tunnel_process_pids(runtime, local_ports);
    let bytes_total = traffic_bytes_for_pids(&pids).unwrap_or(0);
    let now = Instant::now();
    let mut traffic = runtime.traffic.lock().expect("runtime lock poisoned");
    let bytes_per_second = traffic
        .as_ref()
        .and_then(|previous| {
            let elapsed = now.duration_since(previous.captured_at).as_secs_f64();
            (elapsed > 0.0)
                .then(|| bytes_total.saturating_sub(previous.bytes_total) as f64 / elapsed)
        })
        .unwrap_or(0.0)
        .round() as u64;

    *traffic = Some(TrafficSnapshot {
        captured_at: now,
        bytes_total,
    });

    (bytes_per_second, bytes_total)
}

fn tunnel_process_pids(runtime: &RuntimeState, local_ports: &HashSet<u16>) -> HashSet<u32> {
    let mut pids: HashSet<u32> = runtime
        .children
        .lock()
        .expect("runtime lock poisoned")
        .values()
        .map(Child::id)
        .collect();

    for pid in listening_local_port_pids(local_ports).values().flatten() {
        pids.insert(*pid);
    }

    pids
}

fn traffic_bytes_for_pids(pids: &HashSet<u32>) -> Option<u64> {
    if pids.is_empty() {
        return Some(0);
    }

    let mut command = Command::new("nettop");
    command
        .arg("-P")
        .arg("-x")
        .arg("-L")
        .arg("1")
        .arg("-J")
        .arg("bytes_in,bytes_out");

    for pid in pids {
        command.arg("-p").arg(pid.to_string());
    }

    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }

    Some(parse_nettop_traffic(
        &String::from_utf8_lossy(&output.stdout),
        pids,
    ))
}

fn parse_nettop_traffic(output: &str, pids: &HashSet<u32>) -> u64 {
    output
        .lines()
        .filter_map(|line| parse_nettop_process_bytes(line, pids))
        .sum()
}

fn parse_nettop_process_bytes(line: &str, pids: &HashSet<u32>) -> Option<u64> {
    let fields: Vec<&str> = line.split(',').map(str::trim).collect();
    let pid_fields: HashSet<String> = pids.iter().map(u32::to_string).collect();
    let process_field = fields.first().copied().unwrap_or_default();

    let has_matching_pid = fields.iter().any(|field| pid_fields.contains(*field))
        || pids
            .iter()
            .any(|pid| process_field.ends_with(&format!(".{pid}")));

    if !has_matching_pid {
        return None;
    }

    let numeric_values: Vec<u64> = fields
        .iter()
        .filter(|field| !pid_fields.contains(**field))
        .filter_map(|field| field.parse::<u64>().ok())
        .collect();

    let byte_fields = numeric_values.iter().rev().take(2).sum();
    Some(byte_fields)
}

fn listening_local_ports(local_ports: &HashSet<u16>) -> HashSet<u16> {
    if local_ports.is_empty() {
        return HashSet::new();
    }

    let output = match Command::new("lsof")
        .arg("-nP")
        .arg("-iTCP")
        .arg("-sTCP:LISTEN")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return HashSet::new(),
    };

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(local_listen_port_from_lsof_line)
        .filter(|port| local_ports.contains(port))
        .collect()
}

fn listening_local_port_pids(local_ports: &HashSet<u16>) -> HashMap<u16, Vec<u32>> {
    if local_ports.is_empty() {
        return HashMap::new();
    }

    let output = match Command::new("lsof")
        .arg("-nP")
        .arg("-iTCP")
        .arg("-sTCP:LISTEN")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return HashMap::new(),
    };

    let mut pids: HashMap<u16, Vec<u32>> = HashMap::new();
    for (port, pid) in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(local_listener_pid_from_lsof_line)
        .filter(|(port, _)| local_ports.contains(port))
    {
        pids.entry(port).or_default().push(pid);
    }
    pids
}

fn count_local_clients(local_ports: &HashSet<u16>) -> usize {
    if local_ports.is_empty() {
        return 0;
    }

    established_local_port_counts()
        .into_iter()
        .filter(|(port, _)| local_ports.contains(port))
        .map(|(_, count)| count)
        .sum()
}

fn established_local_port_counts() -> HashMap<u16, usize> {
    let output = match Command::new("lsof")
        .arg("-nP")
        .arg("-iTCP")
        .arg("-sTCP:ESTABLISHED")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return HashMap::new(),
    };

    let mut counts = HashMap::new();
    for port in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(local_port_from_lsof_line)
    {
        *counts.entry(port).or_insert(0) += 1;
    }
    counts
}

fn local_port_from_lsof_line(line: &str) -> Option<u16> {
    if !line.contains("TCP ") || !line.contains("->") || !line.contains("(ESTABLISHED)") {
        return None;
    }

    let before_arrow = line.split("->").next()?;
    let port_text = before_arrow.rsplit(':').next()?.trim();
    port_text.parse().ok()
}

fn local_listen_port_from_lsof_line(line: &str) -> Option<u16> {
    if !line.contains("TCP ") || !line.contains("(LISTEN)") {
        return None;
    }

    let before_state = line.split(" (LISTEN)").next()?;
    let port_text = before_state.rsplit(':').next()?.trim();
    port_text.parse().ok()
}

fn local_listener_pid_from_lsof_line(line: &str) -> Option<(u16, u32)> {
    if !line.contains("TCP ") || !line.contains("(LISTEN)") {
        return None;
    }

    let mut columns = line.split_whitespace();
    let command = columns.next()?;
    if command != "ssh" {
        return None;
    }
    let pid = columns.next()?.parse().ok()?;
    let port = local_listen_port_from_lsof_line(line)?;
    Some((port, pid))
}

fn show_main_window(app: &AppHandle) {
    let _ = app.set_dock_visibility(true);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn hide_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
    let _ = app.set_dock_visibility(false);
}

fn quit_app(app: &AppHandle) {
    let runtime = app.state::<RuntimeState>();
    let _ = stop_service_with_runtime(&runtime);
    app.exit(0);
}

fn toggle_quick_panel(app: &AppHandle, position: PhysicalPosition<f64>) {
    let x = (position.x - QUICK_PANEL_WIDTH + 18.0).max(8.0);
    let y = (position.y + 12.0).max(8.0);

    if let Some(window) = app.get_webview_window(QUICK_PANEL_LABEL) {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
            return;
        }
        let _ = window.set_position(PhysicalPosition::new(x, y));
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }

    if let Ok(window) = WebviewWindowBuilder::new(
        app,
        QUICK_PANEL_LABEL,
        WebviewUrl::App("index.html?panel=quick".into()),
    )
    .title("Wormhole Quick Panel")
    .inner_size(QUICK_PANEL_WIDTH, QUICK_PANEL_HEIGHT)
    .position(x, y)
    .resizable(false)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .focused(true)
    .build()
    {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn hide_quick_panel_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(QUICK_PANEL_LABEL) {
        let _ = window.hide();
    }
}

fn emit_service_report(app: &AppHandle, action: &str, report: ServiceReport) {
    let _ = app.emit(format!("service:{action}").as_str(), report);
}

fn draw_pixel(rgba: &mut [u8], x: i32, y: i32, color: [u8; 4]) {
    if x < 0 || y < 0 || x >= TRAY_ICON_SIZE as i32 || y >= TRAY_ICON_SIZE as i32 {
        return;
    }
    let index = ((y as usize * TRAY_ICON_SIZE + x as usize) * 4) as usize;
    rgba[index] = color[0];
    rgba[index + 1] = color[1];
    rgba[index + 2] = color[2];
    rgba[index + 3] = color[3];
}

fn draw_brush(rgba: &mut [u8], x: i32, y: i32, radius: i32, color: [u8; 4]) {
    for dy in -radius..=radius {
        for dx in -radius..=radius {
            if dx * dx + dy * dy <= radius * radius {
                draw_pixel(rgba, x + dx, y + dy, color);
            }
        }
    }
}

fn draw_line(
    rgba: &mut [u8],
    mut x0: i32,
    mut y0: i32,
    x1: i32,
    y1: i32,
    width: i32,
    color: [u8; 4],
) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        draw_brush(rgba, x0, y0, width / 2, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

fn draw_rounded_link(
    rgba: &mut [u8],
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    color: [u8; 4],
) {
    draw_line(rgba, left + 2, top, right - 2, top, 2, color);
    draw_line(rgba, left + 2, bottom, right - 2, bottom, 2, color);
    draw_line(rgba, left, top + 2, left, bottom - 2, 2, color);
    draw_line(rgba, right, top + 2, right, bottom - 2, 2, color);
    draw_pixel(rgba, left + 1, top + 1, color);
    draw_pixel(rgba, right - 1, top + 1, color);
    draw_pixel(rgba, left + 1, bottom - 1, color);
    draw_pixel(rgba, right - 1, bottom - 1, color);
}

fn tray_status_icon(connected: bool) -> Image<'static> {
    let mut rgba = vec![0; TRAY_ICON_SIZE * TRAY_ICON_SIZE * 4];
    let upper_link = if connected {
        [244, 180, 28, 255]
    } else {
        [148, 163, 184, 255]
    };
    let lower_link = if connected {
        [0, 150, 185, 255]
    } else {
        [100, 116, 139, 255]
    };
    let disconnected_color = [220, 38, 38, 255];

    draw_rounded_link(&mut rgba, 7, 2, 12, 8, upper_link);
    draw_rounded_link(&mut rgba, 2, 10, 8, 15, lower_link);
    draw_line(&mut rgba, 7, 10, 10, 7, 2, lower_link);
    draw_line(&mut rgba, 8, 11, 11, 8, 2, upper_link);

    if !connected {
        draw_line(&mut rgba, 11, 10, 15, 14, 2, disconnected_color);
        draw_line(&mut rgba, 15, 10, 11, 14, 2, disconnected_color);
    }

    Image::new_owned(rgba, TRAY_ICON_SIZE as u32, TRAY_ICON_SIZE as u32)
}

fn update_tray_status(app: &AppHandle) {
    reconcile_runtime(app);
    let runtime = app.state::<RuntimeState>();
    let status = service_status_with_runtime(&runtime);

    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(tray_status_icon(status.running > 0)));
        let _ = tray.set_icon_as_template(false);
        let _ = tray.set_title(Some(status.clients.to_string()));
        let _ = tray.set_tooltip(Some(format!(
            "Wormhole · {} client(s), {} tunnel(s) running",
            status.clients, status.running
        )));
    }

    let _ = app.emit("service:status", status);
}

fn start_tray_status_updater(app: AppHandle) {
    thread::spawn(move || loop {
        update_tray_status(&app);
        thread::sleep(Duration::from_secs(5));
    });
}

fn setup_tray(app: &mut tauri::App) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .text(MENU_SHOW, "Show Wormhole")
        .text(MENU_HIDE, "Hide Window")
        .separator()
        .text(MENU_START_SERVICE, "Start Service")
        .text(MENU_STOP_SERVICE, "Stop Service")
        .build()?;

    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("Wormhole")
        .title("0")
        .icon(tray_status_icon(false))
        .icon_as_template(false)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            MENU_SHOW => show_main_window(app),
            MENU_HIDE => hide_main_window(app),
            MENU_START_SERVICE => {
                let runtime = app.state::<RuntimeState>();
                let report = start_service_with_runtime(&runtime, Some(app.clone()));
                emit_service_report(app, "started", report);
                update_tray_status(app);
            }
            MENU_STOP_SERVICE => {
                let runtime = app.state::<RuntimeState>();
                let report = stop_service_with_runtime(&runtime);
                emit_service_report(app, "stopped", report);
                update_tray_status(app);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                position,
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_quick_panel(tray.app_handle(), position);
            }
        });

    tray.build(app)?;
    update_tray_status(app.handle());
    start_tray_status_updater(app.handle().clone());
    Ok(())
}

#[tauri::command]
fn list_connections(runtime: State<'_, RuntimeState>) -> Vec<ConnectionView> {
    let connections = config::load_state().connections;
    let local_ports: HashSet<u16> = connections
        .iter()
        .filter(|connection| !matches!(connection.tunnel_type, TunnelType::Remote))
        .map(|connection| connection.local_port)
        .collect();
    let listening_ports = listening_local_ports(&local_ports);

    connections
        .into_iter()
        .map(|config| connection_view(&runtime, config, &listening_ports))
        .collect()
}

#[tauri::command]
fn save_connection(input: ConnectionInput) -> Result<ConnectionView, String> {
    let config = to_config(input.clone());
    validate_config(&config)?;

    if let Some(password) = input.password.as_deref().filter(|value| !value.is_empty()) {
        keychain::set_password(&config.id, password).map_err(|err| err.to_string())?;
    }
    if let Some(passphrase) = input
        .key_passphrase
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        keychain::set_key_passphrase(&config.id, passphrase).map_err(|err| err.to_string())?;
    }

    let mut state = config::load_state();
    if let Some(existing) = state
        .connections
        .iter_mut()
        .find(|connection| connection.id == config.id)
    {
        *existing = config.clone();
    } else {
        state.connections.push(config.clone());
    }
    config::save_state(&state).map_err(|err| err.to_string())?;

    Ok(ConnectionView {
        config,
        status: TunnelStatus::Stopped,
    })
}

#[tauri::command]
fn delete_connection(
    id: String,
    runtime: State<'_, RuntimeState>,
    app: AppHandle,
) -> Result<(), String> {
    let _ = stop_tunnel_by_id(&runtime, &id);
    let mut state = config::load_state();
    state.connections.retain(|connection| connection.id != id);
    config::save_state(&state).map_err(|err| err.to_string())?;
    keychain::delete_credentials(&id);
    update_tray_status(&app);
    Ok(())
}

#[tauri::command]
fn start_tunnel(
    id: String,
    runtime: State<'_, RuntimeState>,
    app: AppHandle,
) -> Result<ConnectionView, String> {
    let config = find_config(&id)?;
    let view = start_config(&runtime, config, Some(app.clone()))?;
    update_tray_status(&app);
    Ok(view)
}

#[tauri::command]
fn stop_tunnel(id: String, runtime: State<'_, RuntimeState>, app: AppHandle) -> Result<(), String> {
    stop_tunnel_by_id(&runtime, &id)?;
    update_tray_status(&app);
    Ok(())
}

#[tauri::command]
fn start_service(runtime: State<'_, RuntimeState>, app: AppHandle) -> ServiceReport {
    let report = start_service_with_runtime(&runtime, Some(app.clone()));
    update_tray_status(&app);
    report
}

#[tauri::command]
fn stop_service(runtime: State<'_, RuntimeState>, app: AppHandle) -> ServiceReport {
    let report = stop_service_with_runtime(&runtime);
    update_tray_status(&app);
    report
}

#[tauri::command]
fn service_status(runtime: State<'_, RuntimeState>) -> ServiceStatus {
    service_status_with_runtime(&runtime)
}

#[tauri::command]
fn choose_private_key() -> Result<Option<String>, String> {
    let ssh_dir = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".ssh");
    let default_location = ssh_dir.to_string_lossy();
    let script = format!(
        "POSIX path of (choose file with prompt \"Select private key\" default location POSIX file \"{}\")",
        default_location.replace('\\', "\\\\").replace('"', "\\\"")
    );

    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|err| err.to_string())?;

    if output.status.success() {
        let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok((!path.is_empty()).then_some(path))
    } else {
        Ok(None)
    }
}

#[tauri::command]
fn open_full_config(id: String, app: AppHandle) {
    show_main_window(&app);
    let _ = app.emit("connection:open", id);
    hide_quick_panel_window(&app);
}

#[tauri::command]
fn quit_from_quick_panel(app: AppHandle) {
    quit_app(&app);
}

#[tauri::command]
fn restart_app(app: AppHandle) {
    app.request_restart();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(RuntimeState {
            children: Mutex::new(HashMap::new()),
            traffic: Mutex::new(None),
            desired: Mutex::new(HashSet::new()),
            on_demand: Mutex::new(HashMap::new()),
            upstream_ports: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(HashMap::new()),
            needs_auth: Mutex::new(HashSet::new()),
        })
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Wormhole");
                let _ = window.show();
                let _ = window.set_focus();
            }
            setup_tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::Focused(false) = event {
                if window.label() == QUICK_PANEL_LABEL {
                    let _ = window.hide();
                }
            } else if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" || window.label() == QUICK_PANEL_LABEL {
                    api.prevent_close();
                    let _ = window.hide();
                    if window.label() == "main" {
                        let _ = window.app_handle().set_dock_visibility(false);
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            list_connections,
            save_connection,
            delete_connection,
            start_tunnel,
            stop_tunnel,
            start_service,
            stop_service,
            service_status,
            choose_private_key,
            open_full_config,
            quit_from_quick_panel,
            restart_app
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> SshConfig {
        SshConfig {
            id: "test-id".to_string(),
            name: "Test tunnel".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "me".to_string(),
            auth_method: AuthMethod::Key,
            key_path: Some("/Users/me/.ssh/id_ed25519".to_string()),
            tunnel_type: TunnelType::Local,
            local_port: 18080,
            remote_host: Some("127.0.0.1".to_string()),
            remote_port: Some(80),
            auth_profile: AuthProfile::Normal,
            start_mode: StartMode::Manual,
            auto_reconnect: true,
            idle_timeout_seconds: 600,
        }
    }

    #[test]
    fn validates_required_connection_fields() {
        let mut config = base_config();
        assert!(validate_config(&config).is_ok());

        config.host = " ".to_string();
        assert_eq!(
            validate_config(&config),
            Err("SSH host is required.".into())
        );
    }

    #[test]
    fn validates_tunnel_specific_fields() {
        let mut local = base_config();
        local.remote_host = None;
        assert_eq!(
            validate_config(&local),
            Err("Remote host is required for local and remote tunnels.".into())
        );

        let mut dynamic = base_config();
        dynamic.tunnel_type = TunnelType::Dynamic;
        dynamic.remote_host = None;
        dynamic.remote_port = None;
        assert!(validate_config(&dynamic).is_ok());
    }

    #[test]
    fn normalizes_on_demand_policy_for_mfa_and_remote_tunnels() {
        let base = ConnectionInput {
            id: Some("test-id".to_string()),
            name: "Test tunnel".to_string(),
            host: "example.com".to_string(),
            port: 22,
            username: "me".to_string(),
            auth_method: AuthMethod::Key,
            password: None,
            key_path: Some("/Users/me/.ssh/id_ed25519".to_string()),
            key_passphrase: None,
            tunnel_type: TunnelType::Local,
            local_port: 18080,
            remote_host: Some("127.0.0.1".to_string()),
            remote_port: Some(80),
            auth_profile: AuthProfile::Mfa,
            start_mode: StartMode::OnDemand,
            auto_reconnect: true,
            idle_timeout_seconds: 10,
        };

        let mfa = to_config(base.clone());
        assert_eq!(mfa.start_mode, StartMode::Always);
        assert_eq!(mfa.idle_timeout_seconds, 30);

        let mut remote = base;
        remote.auth_profile = AuthProfile::Normal;
        remote.tunnel_type = TunnelType::Remote;
        let remote = to_config(remote);
        assert_eq!(remote.start_mode, StartMode::Always);
    }

    #[test]
    fn builds_tunnel_arguments() {
        let local = base_config();
        assert_eq!(tunnel_arg(&local), "18080:127.0.0.1:80");

        let mut dynamic = base_config();
        dynamic.tunnel_type = TunnelType::Dynamic;
        assert_eq!(tunnel_arg(&dynamic), "18080");
    }

    #[test]
    fn parses_lsof_established_local_port() {
        let line =
            "ssh 12345 me 7u IPv4 0xabc 0t0 TCP 127.0.0.1:18080->127.0.0.1:53122 (ESTABLISHED)";

        assert_eq!(local_port_from_lsof_line(line), Some(18080));
        assert_eq!(local_port_from_lsof_line("COMMAND PID USER"), None);
    }

    #[test]
    fn parses_lsof_listening_port() {
        let line = "ssh 12345 me 7u IPv4 0xabc 0t0 TCP 127.0.0.1:18080 (LISTEN)";

        assert_eq!(local_listen_port_from_lsof_line(line), Some(18080));
        assert_eq!(
            local_listener_pid_from_lsof_line(line),
            Some((18080, 12345))
        );
    }

    #[test]
    fn ignores_non_ssh_lsof_listeners() {
        let line = "node 12345 me 7u IPv4 0xabc 0t0 TCP 127.0.0.1:18080 (LISTEN)";

        assert_eq!(local_listener_pid_from_lsof_line(line), None);
    }

    #[test]
    fn parses_nettop_bytes_for_matching_pids_only() {
        let pids = HashSet::from([12345]);
        let output = "\
process,pid,bytes_in,bytes_out
ssh,12345,1200,800
ssh,912345,9999,9999
ssh.12345,300,200
node,22222,500,500
";

        assert_eq!(parse_nettop_traffic(output, &pids), 2500);
    }

    #[test]
    fn parses_nettop_bytes_without_counting_pid_as_traffic() {
        let pids = HashSet::from([12345]);
        let line = "ssh,12345,10,20";

        assert_eq!(parse_nettop_process_bytes(line, &pids), Some(30));
    }

    #[test]
    fn parses_nettop_process_name_pid_format() {
        let pids = HashSet::from([51844]);
        let line = "ssh.51844,10978619,14543350";

        assert_eq!(parse_nettop_process_bytes(line, &pids), Some(25_521_969));
    }
}
