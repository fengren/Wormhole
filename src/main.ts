import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { check } from "@tauri-apps/plugin-updater";
import {
  Activity,
  Download,
  KeyRound,
  Languages,
  LayoutDashboard,
  Network,
  Plus,
  Power,
  RefreshCw,
  Route,
  Router,
  Save,
  Settings,
  Trash2,
  Users,
  Waypoints,
  Worm,
  createIcons,
} from "lucide";

type TunnelType = "local" | "remote" | "dynamic";
type AuthMethod = "password" | "key";
type AuthProfile = "normal" | "mfa";
type TunnelStatus = "stopped" | "running" | "exited" | "needs_auth";
type ViewMode = "overview" | "new" | "edit" | "settings";
type UpdateState = "idle" | "checking" | "downloading" | "installed";

type Connection = {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_method: AuthMethod;
  key_path?: string;
  tunnel_type: TunnelType;
  local_port: number;
  remote_host?: string;
  remote_port?: number;
  auth_profile: AuthProfile;
  auto_reconnect: boolean;
  status: TunnelStatus;
};

type ConnectionInput = Omit<Connection, "id" | "status"> & {
  id?: string;
  password?: string;
  key_passphrase?: string;
};

type ServiceReport = {
  total: number;
  running: number;
  started: number;
  clients: number;
  failed: string[];
};

type ServiceStatus = {
  total: number;
  running: number;
  clients: number;
  traffic_bytes_per_second: number;
  traffic_bytes_total: number;
};

type MessageAction = {
  label: string;
  action: string;
  id?: string;
};

type MonitorSample = {
  time: number;
  clients: number;
  traffic: number;
};

const emptyDraft: ConnectionInput = {
  name: "",
  host: "",
  port: 22,
  username: "",
  auth_method: "key",
  key_path: "",
  tunnel_type: "local",
  local_port: 8080,
  remote_host: "127.0.0.1",
  remote_port: 80,
  auth_profile: "normal",
  auto_reconnect: true,
  password: "",
  key_passphrase: "",
};

let connections: Connection[] = [];
let selectedId: string | null = null;
let viewMode: ViewMode = "overview";
let draft: ConnectionInput = { ...emptyDraft };
let busyId: string | null = null;
let serviceStatus: ServiceStatus = {
  total: 0,
  running: 0,
  clients: 0,
  traffic_bytes_per_second: 0,
  traffic_bytes_total: 0,
};
let message = "";
let messageKind: "info" | "error" = "info";
let messageAction: MessageAction | null = null;
let monitorSamples: MonitorSample[] = [];
let updateState: UpdateState = "idle";
let updateProgress = 0;
let appVersion = "";

const app = document.querySelector<HTMLDivElement>("#app");
const lucideIcons = {
  Activity,
  Download,
  KeyRound,
  Languages,
  LayoutDashboard,
  Network,
  Plus,
  Power,
  RefreshCw,
  Route,
  Router,
  Save,
  Settings,
  Trash2,
  Users,
  Waypoints,
  Worm,
};

const isQuickPanel =
  new URLSearchParams(window.location.search).get("panel") === "quick";
document.body.classList.toggle("quick-panel-mode", isQuickPanel);

type Language = "en" | "zh";
type I18nKey =
  | "app.subtitle"
  | "newTunnel"
  | "noTunnels"
  | "settings"
  | "overview.title"
  | "overview.available"
  | "metric.service"
  | "metric.clients"
  | "metric.tunnels"
  | "metric.traffic"
  | "metric.total"
  | "monitor.traffic"
  | "monitor.throughput"
  | "monitor.connections"
  | "monitor.clientLinks"
  | "status.running"
  | "status.stopped"
  | "status.exited"
  | "status.needsAuth"
  | "status.needsAttention"
  | "form.editTitle"
  | "form.newTitle"
  | "form.createHint"
  | "form.name"
  | "form.sshHost"
  | "form.sshPort"
  | "form.username"
  | "form.key"
  | "form.password"
  | "form.privateKeyPath"
  | "form.choose"
  | "form.keyPassphrase"
  | "form.sshPassword"
  | "form.keepExisting"
  | "form.connectionPolicy"
  | "form.authProfile"
  | "form.authNormal"
  | "form.authMfa"
  | "form.autoReconnect"
  | "form.autoReconnectHint"
  | "form.remoteListenPort"
  | "form.localListenPort"
  | "form.targetHost"
  | "form.targetPort"
  | "form.save"
  | "form.delete"
  | "tunnel.local.description"
  | "tunnel.local.hint"
  | "tunnel.remote.description"
  | "tunnel.remote.hint"
  | "tunnel.socks.description"
  | "tunnel.socks.hint"
  | "quick.running"
  | "quick.openConfig"
  | "quick.quit"
  | "quick.noTunnels"
  | "quick.openFullApp"
  | "message.deleted"
  | "message.tunnelStopped"
  | "message.serviceStarted"
  | "message.serviceStopped"
  | "message.withIssues"
  | "message.serviceStartedDetail"
  | "message.serviceStoppedDetail"
  | "message.resetKnownHost"
  | "message.knownHostReset"
  | "message.knownHostMissing"
  | "settings.title"
  | "settings.subtitle"
  | "settings.language"
  | "settings.languageHint"
  | "settings.version"
  | "settings.versionHint"
  | "settings.updates"
  | "settings.updatesHint"
  | "update.check"
  | "update.checking"
  | "update.available"
  | "update.notAvailable"
  | "update.downloading"
  | "update.downloadingUnknown"
  | "update.installed"
  | "update.restart"
  | "update.failed";

const translations: Record<Language, Record<I18nKey, string>> = {
  en: {
    "app.subtitle": "SSH tunnels",
    newTunnel: "New tunnel",
    noTunnels: "No tunnels yet.",
    settings: "Settings",
    "overview.title": "Service overview",
    "overview.available": "{running} of {total} tunnel(s) available.",
    "metric.service": "Service",
    "metric.clients": "Clients",
    "metric.tunnels": "Tunnels",
    "metric.traffic": "Traffic",
    "metric.total": "{value} total",
    "monitor.traffic": "Traffic monitor",
    "monitor.throughput": "Throughput",
    "monitor.connections": "Connection monitor",
    "monitor.clientLinks": "Client links",
    "status.running": "Running",
    "status.stopped": "Stopped",
    "status.exited": "Exited",
    "status.needsAuth": "Needs auth",
    "status.needsAttention": "Needs attention",
    "form.editTitle": "Edit tunnel",
    "form.newTitle": "New tunnel",
    "form.createHint": "Create an SSH forwarding rule.",
    "form.name": "Name",
    "form.sshHost": "SSH host",
    "form.sshPort": "SSH port",
    "form.username": "Username",
    "form.key": "Key",
    "form.password": "Password",
    "form.privateKeyPath": "Private key path",
    "form.choose": "Choose",
    "form.keyPassphrase": "Key passphrase",
    "form.sshPassword": "SSH password",
    "form.keepExisting": "Leave blank to keep existing",
    "form.connectionPolicy": "Advanced settings",
    "form.authProfile": "Authentication profile",
    "form.authNormal": "Normal",
    "form.authMfa": "MFA",
    "form.autoReconnect": "Auto reconnect",
    "form.autoReconnectHint": "Only normal authentication can reconnect automatically. MFA tunnels require manual re-authentication.",
    "form.remoteListenPort": "Remote listen port",
    "form.localListenPort": "Local listen port",
    "form.targetHost": "Target host",
    "form.targetPort": "Target port",
    "form.save": "Save",
    "form.delete": "Delete",
    "tunnel.local.description": "Map a remote service to a local port.",
    "tunnel.local.hint": "Useful for internal databases or services, for example localhost:8080 -> remote:80.",
    "tunnel.remote.description": "Expose a local service on the remote host.",
    "tunnel.remote.hint": "Useful when a remote server needs to reach a development service on this Mac.",
    "tunnel.socks.description": "Create a local SOCKS proxy port.",
    "tunnel.socks.hint": "Useful for browser or system proxy traffic through SSH.",
    "quick.running": "{running}/{total} tunnel(s) running",
    "quick.openConfig": "Open config",
    "quick.quit": "Quit",
    "quick.noTunnels": "No tunnels",
    "quick.openFullApp": "Open the full app to add a tunnel.",
    "message.deleted": "Deleted.",
    "message.tunnelStopped": "Tunnel stopped.",
    "message.serviceStarted": "Started",
    "message.serviceStopped": "Stopped",
    "message.withIssues": "{action} with {count} issue(s): {issues}",
    "message.serviceStartedDetail": "Service started. {running}/{total} tunnel(s) running, {clients} client(s) connected.",
    "message.serviceStoppedDetail": "Service stopped. {total} tunnel(s) stopped, {clients} client(s) connected.",
    "message.resetKnownHost": "Reset host key",
    "message.knownHostReset": "Host key reset. Start the tunnel again to trust the new key.",
    "message.knownHostMissing": "No saved host key was found for this tunnel.",
    "settings.title": "Settings",
    "settings.subtitle": "Language, version, and update controls.",
    "settings.language": "Language",
    "settings.languageHint": "Choose the display language for the main app window.",
    "settings.version": "Version",
    "settings.versionHint": "Current installed Wormhole version.",
    "settings.updates": "Updates",
    "settings.updatesHint": "Check GitHub Releases for a signed Wormhole update.",
    "update.check": "Check updates",
    "update.checking": "Checking for updates...",
    "update.available": "Version {version} is available. Downloading...",
    "update.notAvailable": "Wormhole is up to date.",
    "update.downloading": "Downloading update: {progress}%",
    "update.downloadingUnknown": "Downloading update...",
    "update.installed": "Update installed. Restart Wormhole to apply it.",
    "update.restart": "Restart",
    "update.failed": "Update failed: {error}",
  },
  zh: {
    "app.subtitle": "SSH 隧道",
    newTunnel: "新建",
    noTunnels: "还没有隧道。",
    settings: "设置",
    "overview.title": "服务概览",
    "overview.available": "{running}/{total} 个隧道可用。",
    "metric.service": "服务",
    "metric.clients": "客户端",
    "metric.tunnels": "隧道",
    "metric.traffic": "流量",
    "metric.total": "累计 {value}",
    "monitor.traffic": "流量监控",
    "monitor.throughput": "吞吐量",
    "monitor.connections": "连接监控",
    "monitor.clientLinks": "客户端连接",
    "status.running": "运行中",
    "status.stopped": "已停止",
    "status.exited": "已退出",
    "status.needsAuth": "需要认证",
    "status.needsAttention": "需要处理",
    "form.editTitle": "编辑",
    "form.newTitle": "新建",
    "form.createHint": "创建一条 SSH 转发规则。",
    "form.name": "名称",
    "form.sshHost": "SSH 主机",
    "form.sshPort": "SSH 端口",
    "form.username": "用户名",
    "form.key": "密钥",
    "form.password": "密码",
    "form.privateKeyPath": "私钥路径",
    "form.choose": "选择",
    "form.keyPassphrase": "密钥口令",
    "form.sshPassword": "SSH 密码",
    "form.keepExisting": "留空则保持现有值",
    "form.connectionPolicy": "高级设置",
    "form.authProfile": "认证模式",
    "form.authNormal": "普通",
    "form.authMfa": "MFA",
    "form.autoReconnect": "自动重连",
    "form.autoReconnectHint": "仅普通认证支持自动重连。MFA 隧道断开后需要手动重新认证。",
    "form.remoteListenPort": "远端监听端口",
    "form.localListenPort": "本地监听端口",
    "form.targetHost": "目标主机",
    "form.targetPort": "目标端口",
    "form.save": "保存",
    "form.delete": "删除",
    "tunnel.local.description": "把远端服务映射到本机端口。",
    "tunnel.local.hint": "常用于访问内网数据库、后台服务，例如 localhost:8080 -> remote:80。",
    "tunnel.remote.description": "把本机服务暴露到远端机器端口。",
    "tunnel.remote.hint": "常用于让远端服务器访问你本机正在运行的开发服务。",
    "tunnel.socks.description": "在本机创建 SOCKS 代理端口。",
    "tunnel.socks.hint": "常用于浏览器或系统代理，通过 SSH 转发任意目标连接。",
    "quick.running": "{running}/{total} 个隧道运行中",
    "quick.openConfig": "打开配置",
    "quick.quit": "退出",
    "quick.noTunnels": "没有隧道",
    "quick.openFullApp": "打开完整应用添加隧道。",
    "message.deleted": "已删除。",
    "message.tunnelStopped": "隧道已停止。",
    "message.serviceStarted": "启动",
    "message.serviceStopped": "停止",
    "message.withIssues": "{action}完成，但有 {count} 个问题：{issues}",
    "message.serviceStartedDetail": "服务已启动。{running}/{total} 个隧道运行中，{clients} 个客户端已连接。",
    "message.serviceStoppedDetail": "服务已停止。{total} 个隧道已停止，{clients} 个客户端已连接。",
    "message.resetKnownHost": "重置主机密钥",
    "message.knownHostReset": "主机密钥已重置，请重新启动隧道以信任新密钥。",
    "message.knownHostMissing": "没有找到这条隧道已保存的主机密钥。",
    "settings.title": "设置",
    "settings.subtitle": "语言、版本信息和更新控制。",
    "settings.language": "语言",
    "settings.languageHint": "选择主应用窗口的显示语言。",
    "settings.version": "版本",
    "settings.versionHint": "当前安装的 Wormhole 版本。",
    "settings.updates": "更新",
    "settings.updatesHint": "从 GitHub Releases 检查签名更新包。",
    "update.check": "检查更新",
    "update.checking": "正在检查更新...",
    "update.available": "发现版本 {version}，正在下载...",
    "update.notAvailable": "Wormhole 已是最新版本。",
    "update.downloading": "正在下载更新：{progress}%",
    "update.downloadingUnknown": "正在下载更新...",
    "update.installed": "更新已安装，重启 Wormhole 后生效。",
    "update.restart": "重启",
    "update.failed": "更新失败：{error}",
  },
};

let language: Language =
  localStorage.getItem("wormhole.language") === "zh" ? "zh" : "en";

function t(key: I18nKey, values: Record<string, string | number> = {}) {
  return Object.entries(values).reduce(
    (text, [name, value]) => text.split(`{${name}}`).join(String(value)),
    translations[language][key],
  );
}

function icon(name: string, label = "") {
  return `<i class="icon" data-lucide="${name}" aria-hidden="${label ? "false" : "true"}" ${label ? `aria-label="${escapeHtml(label)}"` : ""}></i>`;
}

function hydrateIcons() {
  createIcons({
    icons: lucideIcons,
    attrs: {
      "stroke-width": 2,
      "aria-hidden": "true",
    },
  });
}

function field<K extends keyof ConnectionInput>(key: K): ConnectionInput[K] {
  return draft[key] ?? emptyDraft[key];
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function connectionSummary(connection: Connection): string {
  const destination =
    connection.tunnel_type === "dynamic"
      ? `SOCKS :${connection.local_port}`
      : `${connection.remote_host}:${connection.remote_port}`;
  return `${connection.username}@${connection.host}:${connection.port} -> ${destination}`;
}

function statusText(status: TunnelStatus): string {
  if (status === "running") return t("status.running");
  if (status === "needs_auth") return t("status.needsAuth");
  if (status === "exited") return t("status.exited");
  return t("status.stopped");
}

function serviceStateText() {
  if (serviceStatus.running > 0) return t("status.running");
  if (connections.some((connection) => connection.status === "needs_auth")) return t("status.needsAuth");
  if (connections.some((connection) => connection.status === "exited")) return t("status.needsAttention");
  return t("status.stopped");
}

function serviceStateClass() {
  if (serviceStatus.running > 0) return "running";
  if (connections.some((connection) => connection.status === "needs_auth")) return "exited";
  if (connections.some((connection) => connection.status === "exited")) return "exited";
  return "stopped";
}

function recordMonitorSample() {
  const next: MonitorSample = {
    time: Date.now(),
    clients: serviceStatus.clients,
    traffic: serviceStatus.traffic_bytes_per_second,
  };
  const last = monitorSamples[monitorSamples.length - 1];

  if (
    last &&
    Date.now() - last.time < 900 &&
    last.clients === next.clients &&
    last.traffic === next.traffic
  ) {
    return;
  }

  monitorSamples = [...monitorSamples, next].slice(-30);
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const precision = value >= 10 || unit === 0 ? 0 : 1;
  return `${value.toFixed(precision)} ${units[unit]}`;
}

function formatSampleTime(timestamp: number): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(timestamp));
}

function showMessage(
  nextMessage: string,
  kind: "info" | "error" = "info",
  action: MessageAction | null = null,
) {
  message = nextMessage;
  messageKind = kind;
  messageAction = action;
  const target = document.querySelector<HTMLDivElement>("#message");
  if (target) {
    target.innerHTML = renderMessageContent();
    target.dataset.kind = kind;
    hydrateIcons();
  }
}

function renderMessageContent() {
  if (!message) return "";
  const actionMarkup = messageAction
    ? `<button type="button" class="message-action" data-action="${escapeHtml(messageAction.action)}" ${messageAction.id ? `data-id="${escapeHtml(messageAction.id)}"` : ""}>${icon("key-round")} ${escapeHtml(messageAction.label)}</button>`
    : "";
  return `<span>${escapeHtml(message)}</span>${actionMarkup}`;
}

function hostKeyMismatchAction(error: unknown, id: string): MessageAction | null {
  return String(error).toLowerCase().includes("host key mismatch")
    ? { label: t("message.resetKnownHost"), action: "reset-known-host", id }
    : null;
}

function serviceMessage(action: "started" | "stopped", report: ServiceReport): string {
  if (report.failed.length > 0) {
    return t("message.withIssues", {
      action: action === "started" ? t("message.serviceStarted") : t("message.serviceStopped"),
      count: report.failed.length,
      issues: report.failed.join("; "),
    });
  }
  if (action === "started") {
    return t("message.serviceStartedDetail", {
      running: report.running,
      total: report.total,
      clients: report.clients,
    });
  }
  return t("message.serviceStoppedDetail", {
    total: report.total,
    clients: report.clients,
  });
}

function readInput(form: HTMLFormElement): ConnectionInput {
  const data = new FormData(form);
  const value = (name: string) => String(data.get(name) ?? "").trim();
  const numeric = (name: string, fallback: number) => {
    const parsed = Number(value(name));
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  const tunnelType = value("tunnel_type") as TunnelType;
  const authProfile = value("auth_profile") as AuthProfile;

  return {
    id: selectedId ?? undefined,
    name: value("name"),
    host: value("host"),
    port: numeric("port", 22),
    username: value("username"),
    auth_method: value("auth_method") as AuthMethod,
    password: value("password"),
    key_path: value("key_path"),
    key_passphrase: value("key_passphrase"),
    tunnel_type: tunnelType,
    local_port: numeric("local_port", 8080),
    remote_host: tunnelType === "dynamic" ? undefined : value("remote_host"),
    remote_port:
      tunnelType === "dynamic" ? undefined : numeric("remote_port", 80),
    auth_profile: authProfile,
    auto_reconnect: authProfile === "normal" && data.get("auto_reconnect") === "on",
  };
}

function syncDraftFromCurrentForm() {
  const form = document.querySelector<HTMLFormElement>("#connection-form");
  if (!form || viewMode === "overview") return;
  draft = readInput(form);
}

function isEditingConnectionForm() {
  const form = document.querySelector<HTMLFormElement>("#connection-form");
  const activeElement = document.activeElement;
  return !!form && !!activeElement && form.contains(activeElement);
}

function selectConnection(id: string | null) {
  selectedId = id;
  const selected = connections.find((connection) => connection.id === id);
  viewMode = selected ? "edit" : "overview";
  draft = selected
    ? {
        ...selected,
        password: "",
        key_passphrase: "",
      }
    : { ...emptyDraft };
  render();
}

function newConnection() {
  selectedId = null;
  viewMode = "new";
  draft = { ...emptyDraft };
  render();
}

function showOverview() {
  selectedId = null;
  viewMode = "overview";
  draft = { ...emptyDraft };
  render();
}

function showSettings() {
  syncDraftFromCurrentForm();
  selectedId = null;
  viewMode = "settings";
  render();
}

function setLanguage(nextLanguage: Language) {
  syncDraftFromCurrentForm();
  language = nextLanguage;
  localStorage.setItem("wormhole.language", language);
  render();
}

async function loadAppVersion() {
  appVersion = await getVersion();
  render();
}

async function loadConnections() {
  syncDraftFromCurrentForm();
  connections = await invoke<Connection[]>("list_connections");
  serviceStatus = await invoke<ServiceStatus>("service_status");
  recordMonitorSample();
  if (selectedId && !connections.some((connection) => connection.id === selectedId)) {
    selectedId = null;
    viewMode = "overview";
  }
  render();
}

async function saveConnection(event: SubmitEvent) {
  event.preventDefault();
  const form = event.target as HTMLFormElement;
  const input = readInput(form);
  try {
    const saved = await invoke<Connection>("save_connection", { input });
    selectedId = saved.id;
    viewMode = "edit";
    showMessage("");
    await loadConnections();
  } catch (error) {
    showMessage(String(error), "error");
  }
}

async function startTunnel(id: string) {
  busyId = id;
  render();
  try {
    await invoke<Connection>("start_tunnel", { id });
    await loadConnections();
  } catch (error) {
    showMessage(String(error), "error", hostKeyMismatchAction(error, id));
  } finally {
    busyId = null;
    render();
  }
}

async function resetKnownHost(id: string) {
  try {
    const removed = await invoke<boolean>("reset_known_host", { id });
    showMessage(removed ? t("message.knownHostReset") : t("message.knownHostMissing"));
  } catch (error) {
    showMessage(String(error), "error");
  }
}

async function stopTunnel(id: string) {
  busyId = id;
  render();
  try {
    await invoke("stop_tunnel", { id });
    showMessage(t("message.tunnelStopped"));
    await loadConnections();
  } catch (error) {
    showMessage(String(error), "error");
  } finally {
    busyId = null;
    render();
  }
}

async function toggleTunnel(id: string) {
  const connection = connections.find((item) => item.id === id);
  if (!connection || busyId) return;
  if (connection.status === "running") {
    await stopTunnel(id);
    return;
  }
  await startTunnel(id);
}

async function deleteConnection(id: string) {
  if (!connections.some((connection) => connection.id === id)) return;
  try {
    await invoke("delete_connection", { id });
    selectedId = null;
    viewMode = "overview";
    showMessage(t("message.deleted"));
    await loadConnections();
  } catch (error) {
    showMessage(String(error), "error");
  }
}

async function openFullConfig(id: string) {
  await invoke("open_full_config", { id });
}

async function openSelectedQuickConfig() {
  const targetId = selectedId ?? connections[0]?.id;
  if (targetId) await openFullConfig(targetId);
}

async function choosePrivateKey() {
  syncDraftFromCurrentForm();
  const path = await invoke<string | null>("choose_private_key");
  if (!path) return;
  draft = { ...draft, key_path: path };
  render();
}

async function quitFromQuickPanel() {
  await invoke("quit_from_quick_panel");
}

function updateButtonText() {
  if (updateState === "checking") return t("update.checking");
  if (updateState === "downloading") {
    if (updateProgress <= 0) return t("update.downloadingUnknown");
    return t("update.downloading", { progress: updateProgress });
  }
  if (updateState === "installed") return t("update.restart");
  return t("update.check");
}

function updateButtonIcon() {
  if (updateState === "installed") return "refresh-cw";
  if (updateState === "idle") return "download";
  return "refresh-cw";
}

async function checkForUpdates() {
  if (updateState === "checking" || updateState === "downloading") return;
  updateState = "checking";
  updateProgress = 0;
  render();
  showMessage(t("update.checking"));

  try {
    const update = await check();
    if (!update) {
      showMessage(t("update.notAvailable"));
      updateState = "idle";
      return;
    }

    showMessage(t("update.available", { version: update.version }));
    let downloaded = 0;
    let total = 0;
    await update.downloadAndInstall((event) => {
      if (event.event === "Started") {
        updateState = "downloading";
        total = event.data.contentLength ?? 0;
        downloaded = 0;
        updateProgress = 0;
        render();
      } else if (event.event === "Progress") {
        downloaded += event.data.chunkLength;
        if (total > 0) {
          updateProgress = Math.min(100, Math.round((downloaded / total) * 100));
        }
        render();
      }
    });
    updateState = "installed";
    updateProgress = 100;
    showMessage(t("update.installed"));
  } catch (error) {
    updateState = "idle";
    updateProgress = 0;
    showMessage(t("update.failed", { error: String(error) }), "error");
  } finally {
    render();
  }
}

async function restartApp() {
  await invoke("restart_app");
}

function renderList() {
  if (connections.length === 0) {
    return `<div class="empty">${escapeHtml(t("noTunnels"))}</div>`;
  }

  return connections
    .map(
      (connection) => `
        <div class="connection-row ${connection.id === selectedId ? "selected" : ""}">
          <button class="connection-select" type="button" data-action="select" data-id="${escapeHtml(connection.id)}">
            <span class="connection-icon ${connection.status}">
              ${icon(connection.tunnel_type === "dynamic" ? "router" : "waypoints")}
            </span>
            <span class="connection-main">
              <span class="connection-name">${escapeHtml(connection.name)}</span>
              <span class="connection-summary">${escapeHtml(connectionSummary(connection))}</span>
            </span>
          </button>
          ${renderTunnelSwitch(connection)}
        </div>
      `,
    )
    .join("");
}

function renderOverview() {
  const runningConnections = connections.filter((connection) => connection.status === "running");

  return `
    <section class="overview">
      <div class="overview-heading">
        <span class="overview-logo brand-mark">${icon("route")}</span>
        <div>
          <h2>${escapeHtml(t("overview.title"))}</h2>
        </div>
      </div>

      <div class="metric-grid">
        <div class="metric">
          <span>${icon("power")} ${escapeHtml(t("metric.service"))}</span>
          <strong class="${serviceStateClass()}">${serviceStateText()}</strong>
        </div>
        <div class="metric">
          <span>${icon("users")} ${escapeHtml(t("metric.clients"))}</span>
          <strong>${serviceStatus.clients}</strong>
        </div>
        <div class="metric">
          <span>${icon("network")} ${escapeHtml(t("metric.tunnels"))}</span>
          <strong>${runningConnections.length}/${connections.length}</strong>
        </div>
        <div class="metric">
          <span>${icon("activity")} ${escapeHtml(t("metric.traffic"))}</span>
          <strong>${escapeHtml(formatBytes(serviceStatus.traffic_bytes_per_second))}/s</strong>
          <small>${escapeHtml(t("metric.total", { value: formatBytes(serviceStatus.traffic_bytes_total) }))}</small>
        </div>
      </div>

      <div class="monitor-grid">
        ${renderMonitorChart({
          title: t("monitor.traffic"),
          subtitle: t("monitor.throughput"),
          iconName: "activity",
          metric: "traffic",
          value: serviceStatus.traffic_bytes_per_second,
          formatter: (value) => `${formatBytes(value)}/s`,
        })}
        ${renderMonitorChart({
          title: t("monitor.connections"),
          subtitle: t("monitor.clientLinks"),
          iconName: "users",
          metric: "clients",
          value: serviceStatus.clients,
          formatter: (value) => `${value} ${language === "zh" ? "个客户端" : "client(s)"}`,
        })}
      </div>
    </section>
  `;
}

function renderMonitorChart(options: {
  title: string;
  subtitle: string;
  iconName: string;
  metric: "traffic" | "clients";
  value: number;
  formatter: (value: number) => string;
}) {
  const samples = monitorSamples.length
    ? monitorSamples
    : [
        {
          time: Date.now(),
          clients: serviceStatus.clients,
          traffic: serviceStatus.traffic_bytes_per_second,
        },
      ];
  const values = samples.map((sample) => sample[options.metric]);
  const max = Math.max(1, ...values);
  const width = 360;
  const height = 104;
  const points = values
    .map((value, index) => {
      const x = values.length === 1 ? width : (index / (values.length - 1)) * width;
      const y = height - (value / max) * (height - 14) - 7;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const areaPoints = `0,${height} ${points} ${width},${height}`;
  const startTime = samples[0]?.time ?? Date.now();
  const endTime = samples[samples.length - 1]?.time ?? startTime;

  return `
    <section class="monitor-card">
      <div class="monitor-heading">
        <div>
          <h3>${icon(options.iconName)} ${options.title}</h3>
          <span>${escapeHtml(options.subtitle)}</span>
        </div>
        <strong>${escapeHtml(options.formatter(options.value))}</strong>
      </div>
      <svg class="monitor-chart" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(options.title)}">
        <line x1="0" y1="25%" x2="${width}" y2="25%" />
        <line x1="0" y1="50%" x2="${width}" y2="50%" />
        <line x1="0" y1="75%" x2="${width}" y2="75%" />
        <polygon points="${areaPoints}" />
        <polyline points="${points}" />
      </svg>
      <div class="monitor-foot">
        <span>${escapeHtml(formatSampleTime(startTime))}</span>
        <span>${escapeHtml(formatSampleTime(endTime))}</span>
      </div>
    </section>
  `;
}

function renderTunnelSwitch(connection: Connection) {
  const isRunning = connection.status === "running";
  const busy = busyId === connection.id;
  const label = `${isRunning ? t("message.serviceStopped") : t("message.serviceStarted")} ${connection.name}, ${statusText(connection.status)}`;

  return `
    <button
      type="button"
      class="tunnel-toggle ${isRunning ? "is-on" : "is-off"} ${connection.status}"
      data-action="toggle-tunnel"
      data-id="${escapeHtml(connection.id)}"
      aria-pressed="${isRunning}"
      aria-label="${escapeHtml(label)}"
      ${busy ? "disabled" : ""}
    >
      <span class="toggle-track">
        <span class="toggle-thumb"></span>
      </span>
    </button>
  `;
}

function renderTunnelTypeHelp(activeType: TunnelType) {
  const items: Array<{
    type: TunnelType;
    title: string;
    description: string;
    hint: string;
  }> = [
    {
      type: "local",
      title: "Local",
      description: t("tunnel.local.description"),
      hint: t("tunnel.local.hint"),
    },
    {
      type: "remote",
      title: "Remote",
      description: t("tunnel.remote.description"),
      hint: t("tunnel.remote.hint"),
    },
    {
      type: "dynamic",
      title: "SOCKS",
      description: t("tunnel.socks.description"),
      hint: t("tunnel.socks.hint"),
    },
  ];

  return `
    <div class="tunnel-help-grid">
      ${items
        .map(
          (item) => `
            <label class="tunnel-help ${item.type === activeType ? "active" : ""}">
              <input type="radio" name="tunnel_type" value="${item.type}" ${item.type === activeType ? "checked" : ""} />
              <strong>${escapeHtml(item.title)}</strong>
              <span>${escapeHtml(item.description)}</span>
              <small>${escapeHtml(item.hint)}</small>
            </label>
          `,
        )
        .join("")}
    </div>
  `;
}

function renderLanguageToggle() {
  return `
    <div class="language-toggle" role="group" aria-label="Language">
      <span>${icon("languages")}</span>
      <button type="button" class="${language === "en" ? "active" : ""}" data-action="language" data-lang="en">
        EN
      </button>
      <button type="button" class="${language === "zh" ? "active" : ""}" data-action="language" data-lang="zh">
        中文
      </button>
    </div>
  `;
}

function renderUpdateButton() {
  const busy = updateState === "checking" || updateState === "downloading";
  const action = updateState === "installed" ? "restart-app" : "check-update";

  return `
    <button type="button" class="update-button" data-action="${action}" ${busy ? "disabled" : ""}>
      ${icon(updateButtonIcon())} ${escapeHtml(updateButtonText())}
    </button>
  `;
}

function renderSettings() {
  return `
    <section class="settings-panel">
      <div class="settings-heading">
        <span class="overview-logo brand-mark">${icon("settings")}</span>
        <div>
          <h2>${escapeHtml(t("settings.title"))}</h2>
          <p>${escapeHtml(t("settings.subtitle"))}</p>
        </div>
      </div>

      <div class="settings-list">
        <section class="settings-row">
          <div>
            <h3>${icon("languages")} ${escapeHtml(t("settings.language"))}</h3>
            <p>${escapeHtml(t("settings.languageHint"))}</p>
          </div>
          ${renderLanguageToggle()}
        </section>

        <section class="settings-row">
          <div>
            <h3>${icon("route")} ${escapeHtml(t("settings.version"))}</h3>
            <p>${escapeHtml(t("settings.versionHint"))}</p>
          </div>
          <strong class="version-value">${escapeHtml(appVersion || "-")}</strong>
        </section>

        <section class="settings-row">
          <div>
            <h3>${icon("download")} ${escapeHtml(t("settings.updates"))}</h3>
            <p>${escapeHtml(t("settings.updatesHint"))}</p>
          </div>
          ${renderUpdateButton()}
        </section>
      </div>
    </section>
  `;
}

function renderQuickPanel() {
  const activeId = selectedId ?? connections[0]?.id ?? null;

  if (!app) return;
  app.innerHTML = `
    <main class="quick-panel">
      <header class="quick-header">
        <div>
          <h1>${icon("route")} Wormhole</h1>
        </div>
      </header>

      <section class="quick-list">
        ${renderQuickRows()}
      </section>

      <footer class="quick-footer">
        <button type="button" class="quick-config-button" data-action="open-selected-config" ${activeId ? "" : "disabled"}>
          ${icon("settings")} ${escapeHtml(t("quick.openConfig"))}
        </button>
        <button type="button" class="quick-quit-button" data-action="quit-app">
          ${icon("power")} ${escapeHtml(t("quick.quit"))}
        </button>
      </footer>
    </main>
  `;

  hydrateIcons();
  bindRenderedControls();
}

function renderQuickRows() {
  if (connections.length === 0) {
    return `
      <div class="quick-empty">
        <strong>${escapeHtml(t("quick.noTunnels"))}</strong>
        <span>${escapeHtml(t("quick.openFullApp"))}</span>
      </div>
    `;
  }

  return connections
    .map(
      (connection) => `
        <article class="quick-row ${connection.status} ${connection.id === (selectedId ?? connections[0]?.id) ? "selected" : ""}">
          <button type="button" class="quick-row-main" data-action="select-quick" data-id="${escapeHtml(connection.id)}">
            <span class="connection-icon ${connection.status}">
              ${icon(connection.tunnel_type === "dynamic" ? "router" : "waypoints")}
            </span>
            <span>
              <strong>${escapeHtml(connection.name)}</strong>
              <small>${escapeHtml(connectionSummary(connection))}</small>
            </span>
          </button>
          <div class="quick-row-actions">
            ${renderTunnelSwitch(connection)}
          </div>
        </article>
      `,
    )
    .join("");
}

function renderForm() {
  const authMethod = field("auth_method");
  const tunnelType = field("tunnel_type");
  const authProfile = field("auth_profile");
  const isDynamic = tunnelType === "dynamic";
  const canAutoReconnect = authProfile === "normal";
  const selected = selectedId
    ? connections.find((connection) => connection.id === selectedId)
    : null;

  return `
    <form id="connection-form" class="editor">
      <div class="editor-heading">
        <div>
          <h2>${escapeHtml(viewMode === "edit" && selected ? t("form.editTitle") : t("form.newTitle"))}</h2>
          <p>${selected ? escapeHtml(connectionSummary(selected)) : escapeHtml(t("form.createHint"))}</p>
        </div>
      </div>

      <div class="form-grid">
        <label>
          ${escapeHtml(t("form.name"))}
          <input name="name" value="${escapeHtml(field("name"))}" autocomplete="off" required />
        </label>
        <label>
          ${escapeHtml(t("form.sshHost"))}
          <input name="host" value="${escapeHtml(field("host"))}" placeholder="example.com" required />
        </label>
        <label>
          ${escapeHtml(t("form.sshPort"))}
          <input name="port" type="number" min="1" max="65535" value="${escapeHtml(field("port"))}" required />
        </label>
        <label>
          ${escapeHtml(t("form.username"))}
          <input name="username" value="${escapeHtml(field("username"))}" autocomplete="username" required />
        </label>
      </div>

      <div class="segmented" role="radiogroup" aria-label="Authentication method">
        <label class="${authMethod === "key" ? "active" : ""}">
          <input type="radio" name="auth_method" value="key" ${authMethod === "key" ? "checked" : ""} />
          ${escapeHtml(t("form.key"))}
        </label>
        <label class="${authMethod === "password" ? "active" : ""}">
          <input type="radio" name="auth_method" value="password" ${authMethod === "password" ? "checked" : ""} />
          ${escapeHtml(t("form.password"))}
        </label>
      </div>

      <div class="form-grid">
        <label class="${authMethod === "password" ? "hidden" : ""}">
          ${escapeHtml(t("form.privateKeyPath"))}
          <span class="input-with-action">
            <input name="key_path" value="${escapeHtml(field("key_path"))}" placeholder="~/.ssh/id_ed25519" />
            <button type="button" data-action="choose-key">${escapeHtml(t("form.choose"))}</button>
          </span>
        </label>
        <label class="${authMethod === "password" ? "hidden" : ""}">
          ${escapeHtml(t("form.keyPassphrase"))}
          <input name="key_passphrase" type="password" value="" autocomplete="new-password" placeholder="${escapeHtml(t("form.keepExisting"))}" />
        </label>
        <label class="${authMethod === "key" ? "hidden" : ""}">
          ${escapeHtml(t("form.sshPassword"))}
          <input name="password" type="password" value="" autocomplete="current-password" placeholder="${escapeHtml(t("form.keepExisting"))}" />
        </label>
      </div>

      ${renderTunnelTypeHelp(tunnelType)}

      <div class="form-grid">
        <label>
          ${escapeHtml(tunnelType === "remote" ? t("form.remoteListenPort") : t("form.localListenPort"))}
          <input name="local_port" type="number" min="1" max="65535" value="${escapeHtml(field("local_port"))}" required />
        </label>
        <label class="${isDynamic ? "hidden" : ""}">
          ${escapeHtml(t("form.targetHost"))}
          <input name="remote_host" value="${escapeHtml(field("remote_host"))}" />
        </label>
        <label class="${isDynamic ? "hidden" : ""}">
          ${escapeHtml(t("form.targetPort"))}
          <input name="remote_port" type="number" min="1" max="65535" value="${escapeHtml(field("remote_port") ?? 80)}" />
        </label>
      </div>

      <details class="policy-panel">
        <summary>${escapeHtml(t("form.connectionPolicy"))}</summary>
        <div class="form-grid">
          <label>
            ${escapeHtml(t("form.authProfile"))}
            <select name="auth_profile">
              <option value="normal" ${authProfile === "normal" ? "selected" : ""}>${escapeHtml(t("form.authNormal"))}</option>
              <option value="mfa" ${authProfile === "mfa" ? "selected" : ""}>${escapeHtml(t("form.authMfa"))}</option>
            </select>
          </label>
        </div>
        <label class="checkbox-row">
          <input name="auto_reconnect" type="checkbox" ${field("auto_reconnect") && canAutoReconnect ? "checked" : ""} ${canAutoReconnect ? "" : "disabled"} />
          <span>${escapeHtml(t("form.autoReconnect"))}</span>
        </label>
        <p>${escapeHtml(t("form.autoReconnectHint"))}</p>
      </details>

      <div class="actions">
        <button type="submit">${icon("save")} ${escapeHtml(t("form.save"))}</button>
        ${
          selected
            ? `<button type="button" class="danger" data-action="delete" data-id="${escapeHtml(selected.id)}">${icon("trash-2")} ${escapeHtml(t("form.delete"))}</button>`
            : ""
        }
      </div>
    </form>
  `;
}

function render() {
  if (isQuickPanel) {
    renderQuickPanel();
    return;
  }

  if (!app) return;
  const workspaceContent =
    viewMode === "overview"
      ? renderOverview()
      : viewMode === "settings"
        ? renderSettings()
        : renderForm();

  app.innerHTML = `
    <main class="shell">
      <aside class="sidebar">
        <div class="brand">
          <button type="button" class="brand-button" data-action="overview">
            <span class="brand-mark">${icon("route")}</span>
            <h1>Wormhole</h1>
          </button>
        </div>
        <button type="button" class="new-button" data-action="new">${icon("plus")} ${escapeHtml(t("newTunnel"))}</button>
        <button type="button" class="settings-button ${viewMode === "settings" ? "active" : ""}" data-action="settings">
          ${icon("settings")} ${escapeHtml(t("settings"))}
        </button>
        <div class="connection-list">${renderList()}</div>
      </aside>
      <section class="workspace">
        <div id="message" class="message" data-kind="${messageKind}">${renderMessageContent()}</div>
        ${workspaceContent}
      </section>
    </main>
  `;

  hydrateIcons();
  bindRenderedControls();
}

async function handleAction(action: string, id: string | null, lang: string | null = null) {
  if (action === "select") selectConnection(id);
  if (action === "select-quick" && id) {
    selectedId = id;
    render();
  }
  if (action === "new") newConnection();
  if (action === "overview") showOverview();
  if (action === "settings") showSettings();
  if (action === "toggle-tunnel" && id) await toggleTunnel(id);
  if (action === "delete" && id) await deleteConnection(id);
  if (action === "choose-key") await choosePrivateKey();
  if (action === "open-selected-config") await openSelectedQuickConfig();
  if (action === "quit-app") await quitFromQuickPanel();
  if (action === "check-update" && !isQuickPanel) await checkForUpdates();
  if (action === "restart-app" && !isQuickPanel) await restartApp();
  if (action === "language" && (lang === "en" || lang === "zh")) setLanguage(lang);
  if (action === "reset-known-host" && id) await resetKnownHost(id);
}

function bindRenderedControls() {
  if (!app) return;

  app.querySelectorAll<HTMLButtonElement>(".tunnel-toggle").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      if (button.disabled) return;
      const id = button.dataset.id;
      if (id) void toggleTunnel(id);
    });
  });

  app.querySelectorAll<HTMLButtonElement>(".danger[data-action='delete']").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopImmediatePropagation();
      const id = button.dataset.id;
      if (id) void deleteConnection(id);
    });
  });
}

function bindAppEvents() {
  if (!app) return;

  app.addEventListener("click", (event) => {
    const target = event.target as HTMLElement | null;
    const actionTarget = target?.closest<HTMLElement>("[data-action]");
    if (!actionTarget || !app.contains(actionTarget)) return;
    event.preventDefault();
    event.stopPropagation();
    void handleAction(
      actionTarget.dataset.action ?? "",
      actionTarget.dataset.id ?? null,
      actionTarget.dataset.lang ?? null,
    );
  });

  app.addEventListener("change", (event) => {
    const target = event.target;
    if (
      !(
        (target instanceof HTMLInputElement && target.type === "radio") ||
        target instanceof HTMLSelectElement
      )
    ) {
      return;
    }
    const form = target.form;
    if (!form) return;
    draft = readInput(form);
    render();
  });

  app.addEventListener("input", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || target.type === "radio") return;
    const form = target.form;
    if (!form || form.id !== "connection-form") return;
    draft = readInput(form);
  });

  app.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || form.id !== "connection-form") return;
    void saveConnection(event as SubmitEvent);
  });
}

window.addEventListener("DOMContentLoaded", () => {
  bindAppEvents();
  render();
  loadAppVersion().catch((error) => showMessage(String(error), "error"));
  loadConnections().catch((error) => showMessage(String(error), "error"));
  listen<ServiceReport>("service:started", async (event) => {
    showMessage(
      serviceMessage("started", event.payload),
      event.payload.failed.length ? "error" : "info",
    );
    await loadConnections();
  }).catch((error) => showMessage(String(error), "error"));
  listen<ServiceReport>("service:stopped", async (event) => {
    showMessage(
      serviceMessage("stopped", event.payload),
      event.payload.failed.length ? "error" : "info",
    );
    await loadConnections();
  }).catch((error) => showMessage(String(error), "error"));
  listen<ServiceStatus>("service:status", async (event) => {
    const keepCurrentFormFocus = !isQuickPanel && isEditingConnectionForm();
    syncDraftFromCurrentForm();
    serviceStatus = event.payload;
    connections = await invoke<Connection[]>("list_connections");
    recordMonitorSample();
    if (keepCurrentFormFocus) return;
    render();
  }).catch((error) => showMessage(String(error), "error"));
  listen<string>("connection:open", (event) => {
    if (!isQuickPanel) selectConnection(event.payload);
  }).catch((error) => showMessage(String(error), "error"));
});
