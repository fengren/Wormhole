mod config;
mod keychain;
mod known_hosts;

use config::{AuthMethod, AuthProfile, SshConfig, TunnelType};
use known_hosts::{reset_known_host_for_config, verify_known_host};
use serde::{Deserialize, Serialize};
use ssh2::{Channel, Session};
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    path::Path,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};
use tauri::{
    image::Image,
    menu::MenuBuilder,
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalRect, Rect, RunEvent, State, WebviewUrl,
    WebviewWindowBuilder, WindowEvent,
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
const QUICK_PANEL_EDGE_GAP: f64 = 8.0;
const QUICK_PANEL_TRAY_X_OFFSET: f64 = 18.0;
const QUICK_PANEL_TRAY_Y_OFFSET: f64 = 12.0;
const MAX_ACTIVE_CONNECTIONS: usize = 128;
const REMOTE_FORWARD_BIND_HOST: &str = "0.0.0.0";
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum TunnelStatus {
    Stopped,
    Running,
    Exited,
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
    auto_reconnect: bool,
}

struct RuntimeState {
    tunnels: Mutex<HashMap<String, TunnelHandle>>,
    traffic: Mutex<Option<TrafficSnapshot>>,
    desired: Mutex<HashSet<String>>,
    needs_auth: Mutex<HashSet<String>>,
}

struct TunnelHandle {
    stop: Arc<AtomicBool>,
    bytes_total: Arc<AtomicU64>,
    active_connections: ActiveConnections,
    ssh_shutdown: Option<TcpStream>,
    listener_port: Option<u16>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Clone, Default)]
struct ActiveConnections {
    next_id: Arc<AtomicU64>,
    streams: Arc<Mutex<HashMap<u64, TcpStream>>>,
}

struct SshConnection {
    session: Session,
    shutdown: TcpStream,
}

impl ActiveConnections {
    fn try_track(&self, stream: &TcpStream) -> Result<u64, String> {
        let tracked = stream.try_clone().map_err(|err| err.to_string())?;
        let mut streams = self
            .streams
            .lock()
            .expect("active connections lock poisoned");
        if streams.len() >= MAX_ACTIVE_CONNECTIONS {
            return Err(format!(
                "Too many active tunnel connections. Limit is {MAX_ACTIVE_CONNECTIONS}."
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        streams.insert(id, tracked);
        Ok(id)
    }

    fn untrack(&self, id: Option<u64>) {
        if let Some(id) = id {
            self.streams
                .lock()
                .expect("active connections lock poisoned")
                .remove(&id);
        }
    }

    fn shutdown_all(&self) {
        let streams: Vec<TcpStream> = self
            .streams
            .lock()
            .expect("active connections lock poisoned")
            .values()
            .filter_map(|stream| stream.try_clone().ok())
            .collect();

        for stream in streams {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn len(&self) -> usize {
        self.streams
            .lock()
            .expect("active connections lock poisoned")
            .len()
    }
}

impl TunnelHandle {
    fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.active_connections.shutdown_all();
        if let Some(stream) = &self.ssh_shutdown {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(port) = self.listener_port {
            let _ = TcpStream::connect(("127.0.0.1", port));
        }
    }

    fn join(mut self) {
        self.stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    fn active_count(&self) -> usize {
        self.active_connections.len()
    }
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
    failed: Vec<ServiceFailure>,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceStatus {
    total: usize,
    running: usize,
    clients: usize,
    traffic_bytes_per_second: u64,
    traffic_bytes_total: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ServiceFailureKind {
    HostKeyMismatch,
    Auth,
    Other,
}

#[derive(Debug, Clone, Serialize)]
struct ServiceFailure {
    id: String,
    name: String,
    error: String,
    kind: ServiceFailureKind,
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
    let is_mfa = matches!(&input.auth_profile, AuthProfile::Mfa);

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
        auth_profile: input.auth_profile,
        auto_reconnect: input.auto_reconnect && !is_mfa,
    }
}

fn mark_status(runtime: &RuntimeState, id: &str) -> TunnelStatus {
    let stopped = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        if let Some(tunnel) = tunnels.get(id) {
            if tunnel.is_running() {
                return TunnelStatus::Running;
            }
            tunnels.remove(id)
        } else {
            return TunnelStatus::Stopped;
        }
    };

    if let Some(tunnel) = stopped {
        tunnel.join();
    }
    TunnelStatus::Exited
}

fn find_config(id: &str) -> Result<SshConfig, String> {
    config::load_state()
        .connections
        .into_iter()
        .find(|connection| connection.id == id)
        .ok_or_else(|| "Connection not found.".to_string())
}

fn connection_view(runtime: &RuntimeState, config: SshConfig) -> ConnectionView {
    let status = tunnel_status(runtime, &config);
    ConnectionView { config, status }
}

fn tunnel_status(runtime: &RuntimeState, config: &SshConfig) -> TunnelStatus {
    match mark_status(runtime, &config.id) {
        TunnelStatus::Running => TunnelStatus::Running,
        _ if runtime
            .needs_auth
            .lock()
            .expect("runtime lock poisoned")
            .contains(&config.id) =>
        {
            TunnelStatus::NeedsAuth
        }
        TunnelStatus::Exited if matches!(config.auth_profile, AuthProfile::Mfa) => {
            runtime
                .needs_auth
                .lock()
                .expect("runtime lock poisoned")
                .insert(config.id.clone());
            TunnelStatus::NeedsAuth
        }
        status => status,
    }
}

fn active_tunnel_ids(runtime: &RuntimeState) -> HashSet<String> {
    let inactive = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        let inactive_ids: Vec<String> = tunnels
            .iter()
            .filter(|(_, tunnel)| !tunnel.is_running())
            .map(|(id, _)| id.clone())
            .collect();

        let mut inactive = Vec::new();
        for id in inactive_ids {
            if let Some(tunnel) = tunnels.remove(&id) {
                inactive.push(tunnel);
            }
        }
        inactive
    };

    for tunnel in inactive {
        tunnel.join();
    }

    runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .keys()
        .cloned()
        .collect()
}

fn tunnel_bind_addr(config: &SshConfig) -> (&'static str, u16) {
    ("127.0.0.1", config.local_port)
}

fn connect_ssh_session(config: &SshConfig) -> Result<SshConnection, String> {
    let address = resolve_ssh_address(config)?;
    let tcp = TcpStream::connect_timeout(&address, Duration::from_secs(12))
        .map_err(|err| format!("Could not connect to SSH host: {err}"))?;
    let shutdown = tcp.try_clone().map_err(|err| err.to_string())?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(30))).ok();

    let mut session = Session::new().map_err(|err| err.to_string())?;
    session.set_timeout(30_000);
    session.set_tcp_stream(tcp);
    session.handshake().map_err(|err| err.to_string())?;
    verify_known_host(&session, config)?;
    authenticate_session(&session, config)?;
    session.set_keepalive(true, 30);
    Ok(SshConnection { session, shutdown })
}

fn resolve_ssh_address(config: &SshConfig) -> Result<SocketAddr, String> {
    (config.host.as_str(), config.port)
        .to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| "Could not resolve SSH host.".to_string())
}

fn authenticate_session(session: &Session, config: &SshConfig) -> Result<(), String> {
    match config.auth_method {
        AuthMethod::Password => {
            let password = keychain::get_password(&config.id)
                .map_err(|_| "Password is missing. Save the connection with a password first.")?;
            session
                .userauth_password(&config.username, &password)
                .map_err(|err| err.to_string())?;
        }
        AuthMethod::Key => {
            let key_path = config
                .key_path
                .as_deref()
                .ok_or_else(|| "Key path is required for key authentication.".to_string())?;
            let passphrase = keychain::get_key_passphrase(&config.id).ok();
            if let Err(key_error) = session.userauth_pubkey_file(
                &config.username,
                None,
                Path::new(key_path),
                passphrase.as_deref(),
            ) {
                session.userauth_agent(&config.username).map_err(|agent_error| {
                    format!("SSH key authentication failed: {key_error}; agent fallback failed: {agent_error}")
                })?;
            }
        }
    }

    session
        .authenticated()
        .then_some(())
        .ok_or_else(|| "SSH authentication failed.".to_string())
}

fn start_config(runtime: &RuntimeState, config: SshConfig) -> Result<ConnectionView, String> {
    validate_config(&config)?;

    runtime
        .desired
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone());

    let stopped = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        if let Some(tunnel) = tunnels.get(&config.id) {
            if tunnel.is_running() {
                return Ok(ConnectionView {
                    config,
                    status: TunnelStatus::Running,
                });
            }
            tunnels.remove(&config.id)
        } else {
            None
        }
    };
    if let Some(tunnel) = stopped {
        tunnel.join();
    }

    ensure_local_port_available(&config)?;

    start_ssh_tunnel(runtime, &config).inspect_err(|error| {
        log::error!(
            "Failed to start tunnel '{}' ({}@{}:{}): {}",
            config.name,
            config.username,
            config.host,
            config.port,
            error
        );
        runtime
            .desired
            .lock()
            .expect("runtime lock poisoned")
            .remove(&config.id);
        if should_mark_needs_auth(&config, error) {
            runtime
                .needs_auth
                .lock()
                .expect("runtime lock poisoned")
                .insert(config.id.clone());
        }
    })?;

    Ok(ConnectionView {
        config,
        status: TunnelStatus::Running,
    })
}

#[cfg(test)]
fn start_config_preflight(runtime: &RuntimeState, config: &SshConfig) -> Result<(), String> {
    validate_config(config)?;

    let stopped = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        if let Some(tunnel) = tunnels.get(&config.id) {
            if tunnel.is_running() {
                return Ok(());
            }
            tunnels.remove(&config.id)
        } else {
            None
        }
    };
    if let Some(tunnel) = stopped {
        tunnel.join();
    }

    ensure_local_port_available(config)?;

    Ok(())
}

fn should_mark_needs_auth(config: &SshConfig, error: &str) -> bool {
    matches!(
        service_failure_kind(config, error),
        ServiceFailureKind::Auth
    )
}

fn service_failure_kind(config: &SshConfig, error: &str) -> ServiceFailureKind {
    let lowered = error.to_ascii_lowercase();
    if lowered.contains("host key mismatch") {
        return ServiceFailureKind::HostKeyMismatch;
    }

    if lowered.contains("auth")
        || lowered.contains("password")
        || lowered.contains("passphrase")
        || lowered.contains("publickey")
        || (matches!(config.auth_profile, AuthProfile::Mfa) && lowered.contains("keyboard"))
    {
        return ServiceFailureKind::Auth;
    }

    ServiceFailureKind::Other
}

fn service_failure(config: &SshConfig, error: String) -> ServiceFailure {
    ServiceFailure {
        id: config.id.clone(),
        name: config.name.clone(),
        kind: service_failure_kind(config, &error),
        error,
    }
}

fn ensure_local_port_available(config: &SshConfig) -> Result<(), String> {
    if matches!(config.tunnel_type, TunnelType::Remote) {
        return Ok(());
    }

    TcpListener::bind(tunnel_bind_addr(config))
        .map(|_| ())
        .map_err(|err| format!("Local port {} is already in use: {err}", config.local_port))
}

fn start_ssh_tunnel(runtime: &RuntimeState, config: &SshConfig) -> Result<(), String> {
    let stopped = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        if let Some(tunnel) = tunnels.get(&config.id) {
            if tunnel.is_running() {
                return Ok(());
            }
            tunnels.remove(&config.id)
        } else {
            None
        }
    };
    if let Some(tunnel) = stopped {
        tunnel.join();
    }

    let handle = match config.tunnel_type {
        TunnelType::Local => start_local_tunnel(config)?,
        TunnelType::Dynamic => start_dynamic_tunnel(config)?,
        TunnelType::Remote => start_remote_tunnel(config)?,
    };
    runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .insert(config.id.clone(), handle);
    runtime
        .needs_auth
        .lock()
        .expect("runtime lock poisoned")
        .remove(&config.id);
    Ok(())
}

fn start_local_tunnel(config: &SshConfig) -> Result<TunnelHandle, String> {
    let target_host = config
        .remote_host
        .clone()
        .ok_or_else(|| "Remote host is required for local tunnels.".to_string())?;
    let target_port = config
        .remote_port
        .ok_or_else(|| "Remote port is required for local tunnels.".to_string())?;
    let listener = bind_local_listener(config)?;
    let initial_connection = Arc::new(Mutex::new(Some(connect_ssh_session(config)?)));
    let stop = Arc::new(AtomicBool::new(false));
    let bytes_total = Arc::new(AtomicU64::new(0));
    let active_connections = ActiveConnections::default();
    let thread = spawn_listener_thread(
        listener,
        stop.clone(),
        bytes_total.clone(),
        active_connections.clone(),
        config.clone(),
        move |client, config, bytes_total, stop| {
            let (connection, from_initial) =
                take_initial_ssh_connection(&initial_connection, &config)?;
            let (connection, channel) = open_direct_channel(connection, &target_host, target_port)
                .or_else(|error| {
                    if from_initial {
                        let connection = connect_ssh_session(&config)?;
                        open_direct_channel(connection, &target_host, target_port)
                    } else {
                        Err(error)
                    }
                })?;
            connection.session.set_blocking(false);
            proxy_channel(client, channel, bytes_total, stop)?;
            Ok(())
        },
    );

    Ok(TunnelHandle {
        stop,
        bytes_total,
        active_connections,
        ssh_shutdown: None,
        listener_port: Some(config.local_port),
        thread: Some(thread),
    })
}

fn start_dynamic_tunnel(config: &SshConfig) -> Result<TunnelHandle, String> {
    let listener = bind_local_listener(config)?;
    let initial_connection = Arc::new(Mutex::new(Some(connect_ssh_session(config)?)));
    let stop = Arc::new(AtomicBool::new(false));
    let bytes_total = Arc::new(AtomicU64::new(0));
    let active_connections = ActiveConnections::default();
    let thread = spawn_listener_thread(
        listener,
        stop.clone(),
        bytes_total.clone(),
        active_connections.clone(),
        config.clone(),
        move |mut client, config, bytes_total, stop| {
            let Some(request) = read_proxy_request(&mut client)? else {
                return Ok(());
            };
            let (connection, from_initial) =
                take_initial_ssh_connection(&initial_connection, &config)?;
            let (connection, channel) =
                open_direct_channel(connection, &request.host, request.port).or_else(|error| {
                    if from_initial {
                        let connection = connect_ssh_session(&config)?;
                        open_direct_channel(connection, &request.host, request.port)
                    } else {
                        Err(error)
                    }
                })?;
            connection.session.set_blocking(false);
            write_proxy_success(&mut client, request.protocol)?;
            if !request.preface.is_empty() {
                let mut channel = channel;
                write_all_nonblocking(&mut channel, &request.preface, &stop)
                    .map_err(|err| err.to_string())?;
                proxy_channel(client, channel, bytes_total, stop)?;
                return Ok(());
            }
            proxy_channel(client, channel, bytes_total, stop)?;
            Ok(())
        },
    );

    Ok(TunnelHandle {
        stop,
        bytes_total,
        active_connections,
        ssh_shutdown: None,
        listener_port: Some(config.local_port),
        thread: Some(thread),
    })
}

fn take_initial_ssh_connection(
    initial_connection: &Arc<Mutex<Option<SshConnection>>>,
    config: &SshConfig,
) -> Result<(SshConnection, bool), String> {
    if let Some(connection) = initial_connection
        .lock()
        .map_err(|_| "initial SSH connection lock poisoned".to_string())?
        .take()
    {
        return Ok((connection, true));
    }

    connect_ssh_session(config).map(|connection| (connection, false))
}

fn open_direct_channel(
    connection: SshConnection,
    host: &str,
    port: u16,
) -> Result<(SshConnection, Channel), String> {
    let channel = connection
        .session
        .channel_direct_tcpip(host, port, None)
        .map_err(|err| err.to_string())?;
    Ok((connection, channel))
}

fn start_remote_tunnel(config: &SshConfig) -> Result<TunnelHandle, String> {
    let target_host = config
        .remote_host
        .clone()
        .ok_or_else(|| "Target host is required for remote tunnels.".to_string())?;
    let target_port = config
        .remote_port
        .ok_or_else(|| "Target port is required for remote tunnels.".to_string())?;
    let SshConnection {
        session,
        shutdown: ssh_shutdown,
    } = connect_ssh_session(config)?;
    let (mut listener, _) = match session.channel_forward_listen(
        config.local_port,
        Some(REMOTE_FORWARD_BIND_HOST),
        Some(32),
    ) {
        Ok(listener) => listener,
        Err(public_bind_error) => {
            log::warn!(
                "Remote tunnel public bind {}:{} failed: {}. Falling back to SSH server default bind. Configure GatewayPorts clientspecified on the SSH server to expose the port publicly.",
                REMOTE_FORWARD_BIND_HOST,
                config.local_port,
                public_bind_error
            );
            session
                .channel_forward_listen(config.local_port, None, Some(32))
                .map_err(|default_bind_error| {
                    format!(
                        "Could not listen on remote port {}. The remote port may already be in use; choose another remote listen port and try again. Public bind {} failed: {}; default bind failed: {}. If the port is free, check AllowTcpForwarding and GatewayPorts on the SSH server.",
                        config.local_port,
                        REMOTE_FORWARD_BIND_HOST,
                        public_bind_error,
                        default_bind_error
                    )
                })?
        }
    };
    session.set_blocking(false);
    let stop = Arc::new(AtomicBool::new(false));
    let bytes_total = Arc::new(AtomicU64::new(0));
    let active_connections = ActiveConnections::default();
    let stop_for_thread = stop.clone();
    let bytes_for_thread = bytes_total.clone();
    let active_for_thread = active_connections.clone();
    let thread = thread::spawn(move || {
        let _session = session;
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok(channel) => match connect_target_stream(&target_host, target_port) {
                    Ok(local) => {
                        let bytes = bytes_for_thread.clone();
                        let stop = stop_for_thread.clone();
                        let active = active_for_thread.clone();
                        let id = match active.try_track(&local) {
                            Ok(id) => id,
                            Err(error) => {
                                log::warn!("Remote tunnel rejected client: {error}");
                                let _ = local.shutdown(Shutdown::Both);
                                let mut channel = channel;
                                let _ = channel.close();
                                continue;
                            }
                        };
                        thread::spawn(move || {
                            if let Err(error) = proxy_channel(local, channel, bytes, stop) {
                                log::warn!("Remote tunnel proxy ended with error: {error}");
                            }
                            active.untrack(Some(id));
                        });
                    }
                    Err(_) => {
                        let mut channel = channel;
                        let _ = channel.close();
                    }
                },
                Err(_) => thread::sleep(Duration::from_millis(40)),
            }
        }
    });

    Ok(TunnelHandle {
        stop,
        bytes_total,
        active_connections,
        ssh_shutdown: Some(ssh_shutdown),
        listener_port: None,
        thread: Some(thread),
    })
}

fn bind_local_listener(config: &SshConfig) -> Result<TcpListener, String> {
    let (host, port) = tunnel_bind_addr(config);
    let listener = TcpListener::bind((host, port))
        .map_err(|err| format!("Local port {} is already in use: {err}", config.local_port))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| err.to_string())?;
    Ok(listener)
}

fn connect_target_stream(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, Duration::from_secs(8)) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target host did not resolve")))
}

fn spawn_listener_thread<F>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    bytes_total: Arc<AtomicU64>,
    active_connections: ActiveConnections,
    config: SshConfig,
    handler: F,
) -> JoinHandle<()>
where
    F: Fn(TcpStream, SshConfig, Arc<AtomicU64>, Arc<AtomicBool>) -> Result<(), String>
        + Send
        + Sync
        + 'static,
{
    let handler = Arc::new(handler);
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((client, _)) => {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let config = config.clone();
                    let bytes_total = bytes_total.clone();
                    let stop_for_client = stop.clone();
                    let active = active_connections.clone();
                    let id = match active.try_track(&client) {
                        Ok(id) => id,
                        Err(error) => {
                            log::warn!("Tunnel rejected client: {error}");
                            let _ = client.shutdown(Shutdown::Both);
                            continue;
                        }
                    };
                    let handler = handler.clone();
                    thread::spawn(move || {
                        if let Err(error) = handler(client, config, bytes_total, stop_for_client) {
                            log::warn!("Tunnel client handler ended with error: {error}");
                        }
                        active.untrack(Some(id));
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    })
}

#[derive(Debug, Clone, Copy)]
enum ProxyProtocol {
    Socks5,
    HttpConnect,
    HttpForward,
}

#[derive(Debug, Clone)]
struct ProxyRequest {
    protocol: ProxyProtocol,
    host: String,
    port: u16,
    preface: Vec<u8>,
}

fn read_proxy_request(client: &mut TcpStream) -> Result<Option<ProxyRequest>, String> {
    client
        .set_nonblocking(false)
        .map_err(|err| err.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(8)))
        .map_err(|err| err.to_string())?;
    let mut first = [0_u8; 1];
    if client.read_exact(&mut first).is_err() {
        return Ok(None);
    }

    if first[0] == 0x05 {
        read_socks5_request(client)
    } else {
        read_http_connect_request(client, first[0])
    }
}

fn read_socks5_request(client: &mut TcpStream) -> Result<Option<ProxyRequest>, String> {
    let mut method_count = [0_u8; 1];
    client
        .read_exact(&mut method_count)
        .map_err(|err| err.to_string())?;
    let mut methods = vec![0_u8; method_count[0] as usize];
    client
        .read_exact(&mut methods)
        .map_err(|err| err.to_string())?;
    if !methods.contains(&0x00) {
        client.write_all(&[0x05, 0xff]).ok();
        return Ok(None);
    }
    client
        .write_all(&[0x05, 0x00])
        .map_err(|err| err.to_string())?;

    let mut header = [0_u8; 4];
    client
        .read_exact(&mut header)
        .map_err(|err| err.to_string())?;
    if header[0] != 0x05 || header[1] != 0x01 {
        write_socks5_failure(client).ok();
        return Ok(None);
    }

    let host = match header[3] {
        0x01 => {
            let mut octets = [0_u8; 4];
            client
                .read_exact(&mut octets)
                .map_err(|err| err.to_string())?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut len = [0_u8; 1];
            client.read_exact(&mut len).map_err(|err| err.to_string())?;
            let mut domain = vec![0_u8; len[0] as usize];
            client
                .read_exact(&mut domain)
                .map_err(|err| err.to_string())?;
            String::from_utf8(domain).map_err(|_| "Invalid SOCKS5 domain.".to_string())?
        }
        0x04 => {
            let mut octets = [0_u8; 16];
            client
                .read_exact(&mut octets)
                .map_err(|err| err.to_string())?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => {
            write_socks5_failure(client).ok();
            return Ok(None);
        }
    };
    let mut port_bytes = [0_u8; 2];
    client
        .read_exact(&mut port_bytes)
        .map_err(|err| err.to_string())?;
    let port = u16::from_be_bytes(port_bytes);

    Ok(Some(ProxyRequest {
        protocol: ProxyProtocol::Socks5,
        host,
        port,
        preface: Vec::new(),
    }))
}

fn read_http_connect_request(
    client: &mut TcpStream,
    first_byte: u8,
) -> Result<Option<ProxyRequest>, String> {
    let mut request = vec![first_byte];
    let mut buf = [0_u8; 512];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        if request.len() > 8192 {
            write_http_proxy_error(client, "413 Payload Too Large").ok();
            return Ok(None);
        }
        let read = client.read(&mut buf).map_err(|err| err.to_string())?;
        if read == 0 {
            return Ok(None);
        }
        request.extend_from_slice(&buf[..read]);
    }

    let request_text = String::from_utf8_lossy(&request);
    let first_line = request_text.lines().next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or("HTTP/1.1");
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443)?;
        return Ok(Some(ProxyRequest {
            protocol: ProxyProtocol::HttpConnect,
            host,
            port,
            preface: Vec::new(),
        }));
    }

    let Some(stripped) = target.strip_prefix("http://") else {
        write_http_proxy_error(client, "400 Bad Request").ok();
        return Ok(None);
    };
    let (authority, path) = stripped
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((stripped, "/".to_string()));
    let (host, port) = parse_host_port(authority, 80)?;
    let mut preface = format!("{method} {path} {version}\r\n").into_bytes();
    preface.extend_from_slice(&forwardable_http_headers(&request)?);

    Ok(Some(ProxyRequest {
        protocol: ProxyProtocol::HttpForward,
        host,
        port,
        preface,
    }))
}

fn forwardable_http_headers(request: &[u8]) -> Result<Vec<u8>, String> {
    let request_text = String::from_utf8_lossy(request);
    let Some((_, headers)) = request_text.split_once("\r\n") else {
        return Err("Invalid HTTP proxy request.".to_string());
    };
    let mut output = Vec::new();

    for line in headers.split("\r\n") {
        if line.is_empty() {
            output.extend_from_slice(b"\r\n");
            break;
        }
        let header_name = line.split_once(':').map(|(name, _)| name).unwrap_or(line);
        if is_proxy_only_header(header_name) {
            continue;
        }
        output.extend_from_slice(line.as_bytes());
        output.extend_from_slice(b"\r\n");
    }

    Ok(output)
}

fn is_proxy_only_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16), String> {
    if let Some(host) = value.strip_prefix('[') {
        let Some((host, rest)) = host.split_once(']') else {
            return Err("Invalid IPv6 CONNECT target.".into());
        };
        let port = rest
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return Ok((host.to_string(), port));
        }
    }
    Ok((value.to_string(), default_port))
}

fn write_proxy_success(client: &mut TcpStream, protocol: ProxyProtocol) -> Result<(), String> {
    match protocol {
        ProxyProtocol::Socks5 => client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .map_err(|err| err.to_string()),
        ProxyProtocol::HttpConnect => client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|err| err.to_string()),
        ProxyProtocol::HttpForward => Ok(()),
    }
}

fn write_socks5_failure(client: &mut TcpStream) -> io::Result<()> {
    client.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
}

fn write_http_proxy_error(client: &mut TcpStream, status: &str) -> io::Result<()> {
    write!(
        client,
        "HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
}

fn proxy_channel(
    mut client: TcpStream,
    mut channel: Channel,
    bytes_total: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    client.set_nonblocking(true).ok();
    let mut client_closed = false;
    let mut channel_closed = false;
    let mut client_buffer = [0_u8; 32 * 1024];
    let mut channel_buffer = [0_u8; 32 * 1024];

    while !stop.load(Ordering::SeqCst) && !(client_closed && channel_closed) {
        let mut progressed = false;

        if !client_closed {
            match client.read(&mut client_buffer) {
                Ok(0) => {
                    client_closed = true;
                    let _ = channel.send_eof();
                }
                Ok(read) => {
                    write_channel_nonblocking(&mut channel, &client_buffer[..read], &stop)
                        .map_err(|error| format!("write to SSH channel failed: {error}"))?;
                    bytes_total.fetch_add(read as u64, Ordering::Relaxed);
                    progressed = true;
                }
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(format!("read from client failed: {error}")),
            }
        }

        if !channel_closed {
            match channel.read(&mut channel_buffer) {
                Ok(0) => {
                    if channel.eof() {
                        channel_closed = true;
                        let _ = client.shutdown(Shutdown::Write);
                    }
                }
                Ok(read) => {
                    write_all_nonblocking(&mut client, &channel_buffer[..read], &stop)
                        .map_err(|error| format!("write to client failed: {error}"))?;
                    bytes_total.fetch_add(read as u64, Ordering::Relaxed);
                    progressed = true;
                }
                Err(error) if is_would_block(&error) => {}
                Err(error) => return Err(format!("read from SSH channel failed: {error}")),
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(5));
        }
    }

    let _ = channel.close();
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

fn write_channel_nonblocking(
    channel: &mut Channel,
    mut data: &[u8],
    stop: &AtomicBool,
) -> io::Result<()> {
    while !data.is_empty() {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tunnel is stopping",
            ));
        }
        match channel.write(data) {
            Ok(0) if !channel.eof() => thread::sleep(Duration::from_millis(5)),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ssh channel closed",
                ))
            }
            Ok(written) => data = &data[written..],
            Err(error) if is_would_block(&error) => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tunnel is stopping",
            ));
        }
        match channel.flush() {
            Ok(()) => return Ok(()),
            Err(error) if is_would_block(&error) => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
}

fn write_all_nonblocking<W: Write>(
    writer: &mut W,
    mut data: &[u8],
    stop: &AtomicBool,
) -> io::Result<()> {
    while !data.is_empty() {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tunnel is stopping",
            ));
        }
        match writer.write(data) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "write returned zero",
                ))
            }
            Ok(written) => data = &data[written..],
            Err(error) if is_would_block(&error) => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
    loop {
        if stop.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "tunnel is stopping",
            ));
        }
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error) if is_would_block(&error) => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
}

fn is_would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
        || error.to_string().contains("EAGAIN")
        || error.to_string().contains("WouldBlock")
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

    let tunnel = runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .remove(id);

    if let Some(tunnel) = tunnel {
        tunnel.join();
    }

    Ok(())
}

fn start_service_with_runtime(runtime: &RuntimeState) -> ServiceReport {
    let connections = config::load_state().connections;
    let total = connections.len();
    let mut started = 0;
    let mut failed = Vec::new();

    for config in connections {
        match start_config(runtime, config.clone()) {
            Ok(view) => {
                if matches!(view.status, TunnelStatus::Running) {
                    started += 1;
                }
            }
            Err(error) => failed.push(service_failure(&config, error)),
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
    let tunnel_ids: HashSet<String> = runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .keys()
        .cloned()
        .collect();
    let total = connections.len();
    let mut failed = Vec::new();
    let mut stopped_ids = HashSet::new();

    for config in connections {
        if let Err(error) = stop_tunnel_by_id(runtime, &config.id) {
            failed.push(ServiceFailure {
                id: config.id.clone(),
                name: config.name.clone(),
                error,
                kind: ServiceFailureKind::Other,
            });
        }
        stopped_ids.insert(config.id);
    }

    for id in tunnel_ids.difference(&stopped_ids) {
        if let Err(error) = stop_tunnel_by_id(runtime, &id) {
            failed.push(ServiceFailure {
                id: id.clone(),
                name: id.clone(),
                error,
                kind: ServiceFailureKind::Other,
            });
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

fn terminate_managed_children(runtime: &RuntimeState) {
    let tunnels: Vec<TunnelHandle> = runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .drain()
        .map(|(_, tunnel)| tunnel)
        .collect();

    runtime
        .desired
        .lock()
        .expect("runtime lock poisoned")
        .clear();
    runtime
        .needs_auth
        .lock()
        .expect("runtime lock poisoned")
        .clear();

    for tunnel in tunnels {
        tunnel.join();
    }
}

fn service_status_with_runtime(runtime: &RuntimeState) -> ServiceStatus {
    let connections = config::load_state().connections;
    let active_ids = active_tunnel_ids(runtime);
    let traffic = sample_tunnel_traffic(runtime);

    ServiceStatus {
        total: connections.len(),
        running: active_ids.len(),
        clients: active_tunnel_connection_count(runtime),
        traffic_bytes_per_second: traffic.0,
        traffic_bytes_total: traffic.1,
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
        if matches!(config.auth_profile, AuthProfile::Mfa) || !config.auto_reconnect {
            continue;
        }
        if !tunnel_is_running(&runtime, &config.id) {
            let _ = start_ssh_tunnel(&runtime, config);
        }
    }
}

fn tunnel_is_running(runtime: &RuntimeState, id: &str) -> bool {
    let stopped = {
        let mut tunnels = runtime.tunnels.lock().expect("runtime lock poisoned");
        if let Some(tunnel) = tunnels.get(id) {
            if tunnel.is_running() {
                return true;
            }
            tunnels.remove(id)
        } else {
            None
        }
    };

    if let Some(tunnel) = stopped {
        tunnel.join();
    }
    false
}

fn sample_tunnel_traffic(runtime: &RuntimeState) -> (u64, u64) {
    let bytes_total = tunnel_bytes_total(runtime);
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

fn tunnel_bytes_total(runtime: &RuntimeState) -> u64 {
    runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .values()
        .map(|tunnel| tunnel.bytes_total.load(Ordering::Relaxed))
        .sum()
}

fn active_tunnel_connection_count(runtime: &RuntimeState) -> usize {
    runtime
        .tunnels
        .lock()
        .expect("runtime lock poisoned")
        .values()
        .map(TunnelHandle::active_count)
        .sum()
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

fn cleanup_ssh_processes(app: &AppHandle) {
    let runtime = app.state::<RuntimeState>();
    terminate_managed_children(&runtime);
}

fn quick_panel_position(
    click: PhysicalPosition<f64>,
    work_area: Option<&PhysicalRect<i32, u32>>,
) -> PhysicalPosition<f64> {
    let (min_x, min_y, max_x, max_y) = if let Some(area) = work_area {
        (
            area.position.x as f64 + QUICK_PANEL_EDGE_GAP,
            area.position.y as f64 + QUICK_PANEL_EDGE_GAP,
            area.position.x as f64 + area.size.width as f64
                - QUICK_PANEL_WIDTH
                - QUICK_PANEL_EDGE_GAP,
            area.position.y as f64 + area.size.height as f64
                - QUICK_PANEL_HEIGHT
                - QUICK_PANEL_EDGE_GAP,
        )
    } else {
        (
            QUICK_PANEL_EDGE_GAP,
            QUICK_PANEL_EDGE_GAP,
            f64::INFINITY,
            f64::INFINITY,
        )
    };
    let max_x = max_x.max(min_x);
    let max_y = max_y.max(min_y);
    let x = (click.x - QUICK_PANEL_WIDTH + QUICK_PANEL_TRAY_X_OFFSET).clamp(min_x, max_x);
    let y = (click.y + QUICK_PANEL_TRAY_Y_OFFSET).clamp(min_y, max_y);

    PhysicalPosition::new(x, y)
}

fn quick_panel_work_area(
    app: &AppHandle,
    click: PhysicalPosition<f64>,
) -> Option<PhysicalRect<i32, u32>> {
    let click_x = click.x.round() as i32;
    let click_y = click.y.round() as i32;
    app.available_monitors().ok().and_then(|monitors| {
        monitors
            .into_iter()
            .find(|monitor| {
                let area = monitor.work_area();
                let right = area.position.x + area.size.width as i32;
                let bottom = area.position.y + area.size.height as i32;
                click_x >= area.position.x
                    && click_x < right
                    && click_y >= area.position.y
                    && click_y < bottom
            })
            .map(|monitor| *monitor.work_area())
    })
}

fn tray_anchor_position(position: PhysicalPosition<f64>, rect: Rect) -> PhysicalPosition<f64> {
    let rect_position = rect.position.to_physical::<f64>(1.0);
    let rect_size = rect.size.to_physical::<f64>(1.0);

    if rect_size.width == 0.0 || rect_size.height == 0.0 {
        return position;
    }

    PhysicalPosition::new(
        rect_position.x + rect_size.width / 2.0,
        rect_position.y + rect_size.height,
    )
}

fn toggle_quick_panel(app: &AppHandle, position: PhysicalPosition<f64>, rect: Rect) {
    let anchor = tray_anchor_position(position, rect);
    let work_area = quick_panel_work_area(app, anchor);
    let position = quick_panel_position(anchor, work_area.as_ref());

    if let Some(window) = app.get_webview_window(QUICK_PANEL_LABEL) {
        if window.is_visible().unwrap_or(false) {
            let _ = window.hide();
            return;
        }
        let _ = window.set_position(position);
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
    .position(position.x, position.y)
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
                let report = start_service_with_runtime(&runtime);
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
                rect,
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                toggle_quick_panel(tray.app_handle(), position, rect);
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

    connections
        .into_iter()
        .map(|config| connection_view(&runtime, config))
        .collect()
}

#[tauri::command]
fn save_connection(input: ConnectionInput, app: AppHandle) -> Result<ConnectionView, String> {
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
    update_tray_status(&app);

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
fn reset_known_host(id: String) -> Result<bool, String> {
    let config = find_config(&id)?;
    reset_known_host_for_config(&config)
}

#[tauri::command]
fn start_tunnel(
    id: String,
    runtime: State<'_, RuntimeState>,
    app: AppHandle,
) -> Result<ConnectionView, String> {
    let config = find_config(&id)?;
    let view = start_config(&runtime, config)?;
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
    let report = start_service_with_runtime(&runtime);
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
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(RuntimeState {
            tunnels: Mutex::new(HashMap::new()),
            traffic: Mutex::new(None),
            desired: Mutex::new(HashSet::new()),
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
            reset_known_host,
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
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            cleanup_ssh_processes(app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn work_area(x: i32, y: i32, width: u32, height: u32) -> PhysicalRect<i32, u32> {
        PhysicalRect {
            position: PhysicalPosition::new(x, y),
            size: tauri::PhysicalSize::new(width, height),
        }
    }

    fn tray_rect(x: f64, y: f64, width: u32, height: u32) -> Rect {
        Rect {
            position: PhysicalPosition::new(x, y).into(),
            size: tauri::PhysicalSize::new(width, height).into(),
        }
    }

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
            auto_reconnect: true,
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
    fn formats_known_host_names_for_default_and_custom_ports() {
        assert_eq!(
            known_hosts::known_host_name("example.com", 22),
            "example.com"
        );
        assert_eq!(
            known_hosts::known_host_name("example.com", 55222),
            "[example.com]:55222"
        );
    }

    #[test]
    fn positions_quick_panel_on_clicked_monitor() {
        let area = work_area(0, 0, 1440, 900);
        let position = quick_panel_position(PhysicalPosition::new(1200.0, 24.0), Some(&area));

        assert_eq!(position, PhysicalPosition::new(858.0, 36.0));
    }

    #[test]
    fn positions_quick_panel_on_left_monitor_with_negative_coordinates() {
        let area = work_area(-1920, 0, 1920, 1080);
        let position = quick_panel_position(PhysicalPosition::new(-40.0, 24.0), Some(&area));

        assert_eq!(position, PhysicalPosition::new(-382.0, 36.0));
    }

    #[test]
    fn keeps_quick_panel_inside_clicked_monitor_work_area() {
        let area = work_area(1440, 0, 1280, 720);
        let position = quick_panel_position(PhysicalPosition::new(1500.0, 690.0), Some(&area));

        assert_eq!(position, PhysicalPosition::new(1448.0, 232.0));
    }

    #[test]
    fn anchors_quick_panel_to_tray_rect_when_available() {
        let anchor = tray_anchor_position(
            PhysicalPosition::new(100.0, 100.0),
            tray_rect(-54.0, 0.0, 36, 24),
        );

        assert_eq!(anchor, PhysicalPosition::new(-36.0, 24.0));
    }

    #[test]
    fn preflight_rejects_external_local_port_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut config = base_config();
        config.local_port = listener.local_addr().unwrap().port();
        let runtime = RuntimeState {
            tunnels: Mutex::new(HashMap::new()),
            traffic: Mutex::new(None),
            desired: Mutex::new(HashSet::new()),
            needs_auth: Mutex::new(HashSet::new()),
        };

        let error = start_config_preflight(&runtime, &config).unwrap_err();
        assert!(error.contains(&format!(
            "Local port {} is already in use",
            config.local_port
        )));
    }

    #[test]
    fn stop_handle_shuts_down_active_connections() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let active_connections = ActiveConnections::default();
        active_connections.try_track(&server).unwrap();
        let handle = TunnelHandle {
            stop: Arc::new(AtomicBool::new(false)),
            bytes_total: Arc::new(AtomicU64::new(0)),
            active_connections,
            ssh_shutdown: None,
            listener_port: None,
            thread: None,
        };

        handle.stop();

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn parses_socks5_probe_and_connect_request() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_proxy_request(&mut stream).unwrap().unwrap())
                .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).unwrap();
        let mut response = [0_u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response, [0x05, 0x00]);
        client
            .write_all(&[
                0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm', 0x01, 0xbb,
            ])
            .unwrap();

        let request = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();

        assert!(matches!(request.protocol, ProxyProtocol::Socks5));
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 443);
        assert!(request.preface.is_empty());
    }

    #[test]
    fn parses_http_connect_proxy_request() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_proxy_request(&mut stream).unwrap().unwrap())
                .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com:8443\r\n\r\n")
            .unwrap();

        let request = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();

        assert!(matches!(request.protocol, ProxyProtocol::HttpConnect));
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 8443);
        assert!(request.preface.is_empty());
    }

    #[test]
    fn rewrites_plain_http_proxy_request_to_origin_form() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            tx.send(read_proxy_request(&mut stream).unwrap().unwrap())
                .unwrap();
        });

        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(
                b"GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Connection: keep-alive\r\n\r\n",
            )
            .unwrap();

        let request = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        server.join().unwrap();

        assert!(matches!(request.protocol, ProxyProtocol::HttpForward));
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 8080);
        let preface = String::from_utf8(request.preface).unwrap();
        assert!(preface.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(!preface.to_ascii_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn matches_known_hosts_lines_for_reset() {
        assert!(known_hosts::known_hosts_line_matches(
            "[example.com]:55222 ssh-ed25519 AAAA",
            "[example.com]:55222"
        ));
        assert!(known_hosts::known_hosts_line_matches(
            "example.com,192.0.2.1 ssh-ed25519 AAAA",
            "192.0.2.1"
        ));
        assert!(!known_hosts::known_hosts_line_matches(
            "other.example.com ssh-ed25519 AAAA",
            "example.com"
        ));
    }

    #[test]
    fn terminate_managed_children_clears_runtime_state() {
        let runtime = RuntimeState {
            tunnels: Mutex::new(HashMap::new()),
            traffic: Mutex::new(None),
            desired: Mutex::new(HashSet::from(["test-id".to_string()])),
            needs_auth: Mutex::new(HashSet::from(["test-id".to_string()])),
        };

        terminate_managed_children(&runtime);

        assert!(runtime
            .tunnels
            .lock()
            .expect("runtime lock poisoned")
            .is_empty());
        assert!(runtime
            .desired
            .lock()
            .expect("runtime lock poisoned")
            .is_empty());
        assert!(runtime
            .needs_auth
            .lock()
            .expect("runtime lock poisoned")
            .is_empty());
    }

    #[test]
    fn counts_active_connections_from_runtime_state() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let active_connections = ActiveConnections::default();
        active_connections.try_track(&server).unwrap();
        let runtime = RuntimeState {
            tunnels: Mutex::new(HashMap::from([(
                "test-id".to_string(),
                TunnelHandle {
                    stop: Arc::new(AtomicBool::new(false)),
                    bytes_total: Arc::new(AtomicU64::new(0)),
                    active_connections,
                    ssh_shutdown: None,
                    listener_port: None,
                    thread: None,
                },
            )])),
            traffic: Mutex::new(None),
            desired: Mutex::new(HashSet::new()),
            needs_auth: Mutex::new(HashSet::new()),
        };

        assert_eq!(active_tunnel_connection_count(&runtime), 1);
        drop(client);
    }

    #[test]
    fn rejects_clients_when_active_connection_limit_is_reached() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let active_connections = ActiveConnections::default();
        {
            let mut streams = active_connections
                .streams
                .lock()
                .expect("active connections lock poisoned");
            for id in 0..MAX_ACTIVE_CONNECTIONS as u64 {
                streams.insert(id, server.try_clone().unwrap());
            }
        }

        assert!(active_connections.try_track(&server).is_err());
        drop(client);
    }

    #[test]
    fn classifies_host_key_mismatch_failures() {
        assert_eq!(
            service_failure_kind(
                &base_config(),
                "SSH host key mismatch in Wormhole known_hosts"
            ),
            ServiceFailureKind::HostKeyMismatch
        );
    }

    #[test]
    fn does_not_classify_all_mfa_failures_as_auth_failures() {
        let mut config = base_config();
        config.auth_profile = AuthProfile::Mfa;

        assert_eq!(
            service_failure_kind(&config, "Local port 18080 is already in use"),
            ServiceFailureKind::Other
        );
    }
}
