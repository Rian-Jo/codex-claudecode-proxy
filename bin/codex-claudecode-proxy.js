#!/usr/bin/env node
/* eslint-disable no-console */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { spawnSync } from "node:child_process";

const DEFAULT_PORT = 8317;
const DEFAULT_MODEL = "gpt-5.3-codex";

function nowTs() {
  return Date.now().toString();
}

function log(msg) {
  console.log(`[codex-claudecode-proxy] ${msg}`);
}

function warn(msg) {
  console.error(`[codex-claudecode-proxy][WARN] ${msg}`);
}

function fail(msg, code = 1) {
  console.error(`[codex-claudecode-proxy][FAIL] ${msg}`);
  process.exit(code);
}

function usage(code = 0) {
  const txt = `Usage:
  codex-claudecode-proxy [command]

Commands:
  install      Install + configure + start (default)
  start        Start proxy background services
  stop         Stop proxy background services
  status       Show status
  uninstall    Remove background services + restore Claude Code settings (keeps proxy files)
  purge        Uninstall + remove proxy files
  help         Show this help

Examples:
  npx -y codex-claudecode-proxy@latest
  npx -y codex-claudecode-proxy@latest status
  npx -y codex-claudecode-proxy@latest purge
`;
  console.log(txt);
  process.exit(code);
}

function currentPlatform() {
  return process.env.CODEX_PROXY_PLATFORM || process.platform;
}

function shouldSkipHealthcheck() {
  return process.env.CODEX_PROXY_SKIP_HEALTHCHECK === "1";
}

function parseArgs(argv) {
  const args = [...argv];
  const out = {
    command: "install",
  };

  if (args.length > 0 && !args[0].startsWith("-")) {
    out.command = args.shift();
  }

  while (args.length > 0) {
    const a = args.shift();
    if (a === "--help" || a === "-h" || a === "help") return { ...out, command: "help" };
    // Backward compatibility: allow legacy "non-interactive" flags as no-ops.
    if (a === "--yes" || a === "-y") continue;
    fail(`unknown arg: ${a}`);
  }

  return out;
}

function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function readText(p) {
  return fs.readFileSync(p, "utf8");
}

function writeFileAtomic(p, content, mode) {
  const dir = path.dirname(p);
  ensureDir(dir);
  const tmp = `${p}.tmp.${process.pid}.${nowTs()}`;
  fs.writeFileSync(tmp, content, "utf8");
  if (mode != null) fs.chmodSync(tmp, mode);
  fs.renameSync(tmp, p);
}

function backupFile(p) {
  if (!exists(p)) return null;
  const bak = `${p}.backup.${nowTs()}`;
  fs.copyFileSync(p, bak);
  return bak;
}

function run(cmd, args, opts = {}) {
  const {
    cwd,
    allowFail = false,
    captureStdout = true,
    captureStderr = true,
  } = opts;

  const r = spawnSync(cmd, args, {
    cwd,
    encoding: "utf8",
    stdio: [
      "ignore",
      captureStdout ? "pipe" : "inherit",
      captureStderr ? "pipe" : "inherit",
    ],
  });

  if (!allowFail && (r.error || r.status !== 0)) {
    const msg = [
      `${cmd} ${args.join(" ")}`,
      r.error ? String(r.error) : "",
      r.stdout ? `stdout:\n${r.stdout}` : "",
      r.stderr ? `stderr:\n${r.stderr}` : "",
    ].filter(Boolean).join("\n");
    fail(msg);
  }
  return r;
}

async function fetchJson(url) {
  const res = await fetch(url, {
    headers: { "user-agent": "codex-claudecode-proxy" },
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} ${res.statusText} (${url})`);
  }
  return await res.json();
}

async function downloadToFile(url, destPath) {
  const res = await fetch(url, {
    redirect: "follow",
    headers: { "user-agent": "codex-claudecode-proxy" },
  });
  if (!res.ok) throw new Error(`download failed: HTTP ${res.status} ${res.statusText}`);
  ensureDir(path.dirname(destPath));
  const tmp = `${destPath}.tmp.${process.pid}.${nowTs()}`;
  const ab = await res.arrayBuffer();
  fs.writeFileSync(tmp, Buffer.from(ab));
  fs.renameSync(tmp, destPath);
}

function findFileRecursive(rootDir, names) {
  /** @type {string[]} */
  const stack = [rootDir];
  while (stack.length > 0) {
    const dir = stack.pop();
    const items = fs.readdirSync(dir, { withFileTypes: true });
    for (const it of items) {
      const p = path.join(dir, it.name);
      if (it.isDirectory()) {
        stack.push(p);
        continue;
      }
      if (it.isFile() && names.includes(it.name)) {
        return p;
      }
    }
  }
  return null;
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function readPortFromProxyConfig(configFile) {
  if (!exists(configFile)) return null;
  try {
    const m = readText(configFile).match(/^\s*port:\s*(\d+)\s*$/m);
    if (!m) return null;
    const n = Number(m[1]);
    if (!Number.isInteger(n) || n <= 0 || n > 65535) return null;
    return n;
  } catch {
    return null;
  }
}

async function isLocalPortFree(port) {
  return await new Promise((resolve) => {
    const srv = net.createServer();
    // Don't keep the process alive just for this check.
    srv.unref();
    srv.once("error", () => resolve(false));
    srv.listen({ port, host: "127.0.0.1" }, () => {
      srv.close(() => resolve(true));
    });
  });
}

async function findAvailableLocalPort(preferredPort, scan = 20) {
  const start = Number(preferredPort);
  if (!Number.isInteger(start) || start <= 0 || start > 65535) return DEFAULT_PORT;

  for (let i = 0; i <= scan; i += 1) {
    const p = start + i;
    if (p <= 0 || p > 65535) break;
    // If our proxy is already responding, keep that port.
    if (await proxyHealthcheck(p)) return p;
    if (await isLocalPortFree(p)) return p;
  }

  // Fallback: ask the OS for an ephemeral free port.
  return await new Promise((resolve) => {
    const srv = net.createServer();
    srv.unref();
    srv.once("error", () => resolve(DEFAULT_PORT));
    srv.listen({ port: 0, host: "127.0.0.1" }, () => {
      const addr = srv.address();
      const p = addr && typeof addr === "object" ? addr.port : DEFAULT_PORT;
      srv.close(() => resolve(p));
    });
  });
}

async function resolveProxyPort({ configFile }) {
  const fromConfig = readPortFromProxyConfig(configFile);
  if (fromConfig) {
    // If the configured port is already healthy, keep it.
    if (await proxyHealthcheck(fromConfig)) return fromConfig;
    // If the port is free, keep it.
    if (await isLocalPortFree(fromConfig)) return fromConfig;
    warn(`configured port is busy (${fromConfig}); selecting a free port`);
  }
  return await findAvailableLocalPort(DEFAULT_PORT);
}

async function proxyHealthcheck(port) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2000);
    const res = await fetch(`http://127.0.0.1:${port}/v1/models`, { signal: ctrl.signal });
    clearTimeout(t);
    return res.ok;
  } catch {
    return false;
  }
}

async function verifyReasoningEffort(port, model) {
  for (let i = 0; i < 6; i += 1) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 20000);
      const res = await fetch(`http://127.0.0.1:${port}/v1/responses`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model, input: "say pong" }),
        signal: ctrl.signal,
      });
      clearTimeout(t);
      const json = await res.json();
      const effort = json?.reasoning?.effort;
      if (effort === "xhigh") return true;
      await sleep(1000);
    } catch {
      await sleep(1000);
    }
  }
  return false;
}

function proxyConfigYaml({ port }) {
  return `port: ${port}
auth-dir: "~/.cli-proxy-api/auths"

payload:
  override:
    - models:
        - name: "gpt-*"
          protocol: "codex"
      params:
        "reasoning.effort": "xhigh"
        "reasoning.summary": "auto"
`;
}

function tokenSyncScript() {
  return `#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const src = process.argv[2] || path.join(os.homedir(), ".codex", "auth.json");
const dst = process.argv[3] || path.join(os.homedir(), ".cli-proxy-api", "auths", "codex-from-codex-cli.json");

if (!fs.existsSync(src)) {
  console.error("missing " + src + " (Codex CLI login required)");
  process.exit(1);
}

const auth = JSON.parse(fs.readFileSync(src, "utf8"));
const accessToken = auth?.tokens?.access_token || "";
if (!accessToken) {
  console.error("tokens.access_token missing in " + src);
  process.exit(1);
}

const out = {
  access_token: accessToken,
  account_id: auth?.tokens?.account_id || "",
  disabled: false,
  email: "",
  expired: "",
  id_token: auth?.tokens?.id_token || "",
  last_refresh: String(auth?.last_refresh || ""),
  refresh_token: auth?.tokens?.refresh_token || "",
  type: "codex",
};

fs.mkdirSync(path.dirname(dst), { recursive: true });
const tmp = dst + ".tmp." + process.pid + "." + Date.now();
fs.writeFileSync(tmp, JSON.stringify(out, null, 2) + "\\n", "utf8");
fs.renameSync(tmp, dst);
try {
  fs.chmodSync(dst, 0o600);
} catch {
  // no-op on platforms that don't support POSIX file modes.
}
`;
}

function buildPlistSync({ labelSync, syncScriptPath, homeDir, tokenSyncLog }) {
  const authJsonPath = path.join(homeDir, ".codex", "auth.json");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${labelSync}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${process.execPath}</string>
    <string>${syncScriptPath}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>WatchPaths</key>
  <array>
    <string>${authJsonPath}</string>
  </array>
  <key>StandardOutPath</key><string>${tokenSyncLog}</string>
  <key>StandardErrorPath</key><string>${tokenSyncLog}</string>
</dict></plist>
`;
}

function buildLinuxTokenSyncService({ labelSync, syncScriptPath }) {
  return `[Unit]
Description=${labelSync}

[Service]
Type=oneshot
ExecStart=${process.execPath} ${syncScriptPath}
`;
}

function buildLinuxTokenSyncPath({ labelSync, homeDir }) {
  const authJsonPath = path.join(homeDir, ".codex", "auth.json");
  return `[Unit]
Description=${labelSync} watcher

[Path]
PathChanged=${authJsonPath}
Unit=${labelSync}.service

[Install]
WantedBy=default.target
`;
}

function buildLinuxProxyService({ labelProxy, proxyBin, configFile, homeDir, proxyLog }) {
  return `[Unit]
Description=${labelProxy}

[Service]
WorkingDirectory=${homeDir}
ExecStart=${proxyBin} --config ${configFile}
Restart=always
RestartSec=2
StandardOutput=append:${proxyLog}
StandardError=append:${proxyLog}

[Install]
WantedBy=default.target
`;
}

function buildPlistProxy({ labelProxy, proxyBin, configFile, homeDir, proxyLog }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${labelProxy}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${proxyBin}</string>
    <string>--config</string>
    <string>${configFile}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>${homeDir}</string>
  <key>StandardOutPath</key><string>${proxyLog}</string>
  <key>StandardErrorPath</key><string>${proxyLog}</string>
</dict></plist>
`;
}

async function installCliProxyApiBinary({ proxyBin }) {
  if (exists(proxyBin)) {
    log(`CLIProxyAPI already installed: ${proxyBin}`);
    return;
  }

  const arch = process.arch === "arm64" ? "arm64" : process.arch === "x64" ? "amd64" : null;
  if (!arch) fail(`unsupported architecture: ${process.arch}`);

  ensureDir(path.dirname(proxyBin));

  const platform = currentPlatform();
  const platformToken = platform === "darwin"
    ? "darwin"
    : platform === "linux"
      ? "linux"
      : platform === "win32"
        ? "windows"
        : null;
  if (!platformToken) fail(`unsupported platform for binary install: ${platform}`);

  log("Downloading CLIProxyAPI release from GitHub...");
  const rel = await fetchJson("https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest");
  const contains = `${platformToken}_${arch}`;
  const asset = (rel.assets || []).find((a) => typeof a?.name === "string" && a.name.toLowerCase().includes(contains));
  if (!asset?.browser_download_url) {
    fail(`could not find asset containing: ${contains} (platform=${platform}, arch=${process.arch})`);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "codex-claudecode-proxy-"));
  const downloaded = path.join(tmpDir, asset.name);
  await downloadToFile(asset.browser_download_url, downloaded);

  let found = null;
  if (downloaded.endsWith(".tar.gz")) {
    log("Extracting tarball...");
    run("tar", ["-xzf", downloaded, "-C", tmpDir]);
    found = findFileRecursive(tmpDir, ["cli-proxy-api", "CLIProxyAPI", "cli-proxy-api.exe", "CLIProxyAPI.exe"]);
  } else if (downloaded.endsWith(".zip")) {
    if (currentPlatform() !== "win32") {
      fail(`zip asset unsupported on this platform: ${downloaded}`);
    }
    run("powershell", ["-NoProfile", "-Command", `Expand-Archive -LiteralPath '${downloaded}' -DestinationPath '${tmpDir}' -Force`]);
    found = findFileRecursive(tmpDir, ["cli-proxy-api.exe", "CLIProxyAPI.exe", "cli-proxy-api", "CLIProxyAPI"]);
  } else {
    found = downloaded;
  }
  if (!found) fail("failed to locate extracted binary");

  fs.copyFileSync(found, proxyBin);
  fs.chmodSync(proxyBin, 0o755);
  fs.rmSync(tmpDir, { recursive: true, force: true });

  log(`Installed: ${proxyBin}`);
}

function updateClaudeSettings({ claudeSettingsPath, port, model }) {
  ensureDir(path.dirname(claudeSettingsPath));
  if (!exists(claudeSettingsPath)) {
    writeFileAtomic(claudeSettingsPath, "{}\n", 0o600);
  }

  backupFile(claudeSettingsPath);

  let json;
  try {
    json = JSON.parse(readText(claudeSettingsPath));
  } catch {
    fail(`failed to parse JSON: ${claudeSettingsPath}`);
  }

  if (!json || typeof json !== "object") json = {};
  if (!json.env || typeof json.env !== "object") json.env = {};

  json.model = model;
  json.env.ANTHROPIC_BASE_URL = `http://127.0.0.1:${port}`;
  // Placeholder token. Avoid secret-like prefixes (e.g., "sk-") to prevent false-positive secret scans.
  json.env.ANTHROPIC_AUTH_TOKEN = "proxy-local";
  json.env.ANTHROPIC_MODEL = model;
  json.env.ANTHROPIC_SMALL_FAST_MODEL = model;
  json.env.ANTHROPIC_DEFAULT_SONNET_MODEL = model;
  json.env.ANTHROPIC_DEFAULT_OPUS_MODEL = model;
  json.env.ANTHROPIC_DEFAULT_HAIKU_MODEL = model;

  writeFileAtomic(claudeSettingsPath, `${JSON.stringify(json, null, 2)}\n`, 0o600);
}

function cleanupClaudeSettings({ claudeSettingsPath, model }) {
  if (!exists(claudeSettingsPath)) return;

  backupFile(claudeSettingsPath);

  let json;
  try {
    json = JSON.parse(readText(claudeSettingsPath));
  } catch {
    fail(`failed to parse JSON: ${claudeSettingsPath}`);
  }

  if (!json || typeof json !== "object") return;

  if (json.model === model) delete json.model;

  if (json.env && typeof json.env === "object") {
    delete json.env.ANTHROPIC_BASE_URL;
    delete json.env.ANTHROPIC_AUTH_TOKEN;
    delete json.env.ANTHROPIC_MODEL;
    delete json.env.ANTHROPIC_SMALL_FAST_MODEL;
    delete json.env.ANTHROPIC_DEFAULT_SONNET_MODEL;
    delete json.env.ANTHROPIC_DEFAULT_OPUS_MODEL;
    delete json.env.ANTHROPIC_DEFAULT_HAIKU_MODEL;
  }

  writeFileAtomic(claudeSettingsPath, `${JSON.stringify(json, null, 2)}\n`, 0o600);
}

function getUsername() {
  // Prefer $USER for consistency with LaunchAgent labels.
  if (process.env.USER && process.env.USER.trim()) return process.env.USER.trim();
  return os.userInfo().username;
}

function getUid() {
  const r = run("id", ["-u"]);
  return Number(String(r.stdout || "").trim());
}

function launchctlBootout(uid, label) {
  run("launchctl", ["bootout", `gui/${uid}/${label}`], { allowFail: true });
}

function launchctlBootstrap(uid, plistPath) {
  run("launchctl", ["bootstrap", `gui/${uid}`, plistPath], { allowFail: true });
}

function launchctlKickstart(uid, label) {
  run("launchctl", ["kickstart", "-k", `gui/${uid}/${label}`], { allowFail: true });
}

function launchctlPrint(uid, label) {
  const r = run("launchctl", ["print", `gui/${uid}/${label}`], { allowFail: true });
  return r.status === 0;
}

async function waitForHealthy(port, msTotal = 8000) {
  const started = Date.now();
  while (Date.now() - started < msTotal) {
    if (await proxyHealthcheck(port)) return true;
    await sleep(250);
  }
  return false;
}

async function installFlow(opts) {
  const platform = currentPlatform();
  if (!["darwin", "linux", "win32"].includes(platform)) fail(`unsupported platform: ${platform}`);

  const homeDir = os.homedir();
  const username = getUsername();

  const proxyDir = path.join(homeDir, ".cli-proxy-api");
  const authDir = path.join(proxyDir, "auths");
  const configFile = path.join(proxyDir, "config.yaml");
  const syncScriptPath = path.join(proxyDir, "sync-codex-token.mjs");
  const proxyBin = platform === "win32"
    ? path.join(homeDir, "AppData", "Local", "codex-claudecode-proxy", "cli-proxy-api.exe")
    : path.join(homeDir, ".local", "bin", "cli-proxy-api");
  const proxyLog = path.join(proxyDir, "cli-proxy-api.log");
  const tokenSyncLog = path.join(proxyDir, "token-sync.log");
  const claudeSettingsPath = path.join(homeDir, ".claude", "settings.json");

  const port = await resolveProxyPort({ configFile });
  const model = DEFAULT_MODEL;

  const labelProxy = `com.${username}.cli-proxy-api`;
  const labelSync = `com.${username}.cli-proxy-api-token-sync`;
  const plistProxy = path.join(homeDir, "Library", "LaunchAgents", `${labelProxy}.plist`);
  const plistSync = path.join(homeDir, "Library", "LaunchAgents", `${labelSync}.plist`);
  const linuxSystemdDir = path.join(homeDir, ".config", "systemd", "user");
  const linuxProxySvc = path.join(linuxSystemdDir, `${labelProxy}.service`);
  const linuxSyncSvc = path.join(linuxSystemdDir, `${labelSync}.service`);
  const linuxSyncPath = path.join(linuxSystemdDir, `${labelSync}.path`);

  const codexAuth = path.join(homeDir, ".codex", "auth.json");
  if (!exists(codexAuth)) {
    fail(`missing ${codexAuth} (Codex CLI login required)`);
  }

  ensureDir(proxyDir);
  ensureDir(authDir);
  ensureDir(path.dirname(proxyBin));
  if (platform === "darwin") ensureDir(path.dirname(plistProxy));
  if (platform === "linux") ensureDir(linuxSystemdDir);

  await installCliProxyApiBinary({ proxyBin });

  log("Writing config + token sync script...");
  writeFileAtomic(configFile, proxyConfigYaml({ port }), 0o644);
  writeFileAtomic(syncScriptPath, tokenSyncScript(), 0o755);

  log("Syncing token once...");
  run(process.execPath, [syncScriptPath]);

  if (platform === "darwin") {
    const uid = getUid();
    log("Writing LaunchAgents...");
    writeFileAtomic(plistSync, buildPlistSync({ labelSync, syncScriptPath, homeDir, tokenSyncLog }), 0o644);
    writeFileAtomic(plistProxy, buildPlistProxy({ labelProxy, proxyBin, configFile, homeDir, proxyLog }), 0o644);

    log("Reloading LaunchAgents...");
    launchctlBootout(uid, labelProxy);
    launchctlBootout(uid, labelSync);
    launchctlBootstrap(uid, plistSync);
    launchctlBootstrap(uid, plistProxy);
    launchctlKickstart(uid, labelSync);
    launchctlKickstart(uid, labelProxy);
  } else if (platform === "linux") {
    log("Writing systemd user units...");
    writeFileAtomic(linuxSyncSvc, buildLinuxTokenSyncService({ labelSync, syncScriptPath }), 0o644);
    writeFileAtomic(linuxSyncPath, buildLinuxTokenSyncPath({ labelSync, homeDir }), 0o644);
    writeFileAtomic(linuxProxySvc, buildLinuxProxyService({ labelProxy, proxyBin, configFile, homeDir, proxyLog }), 0o644);
    run("systemctl", ["--user", "daemon-reload"]);
    run("systemctl", ["--user", "enable", "--now", `${labelSync}.path`]);
    run("systemctl", ["--user", "start", `${labelSync}.service`], { allowFail: true });
    run("systemctl", ["--user", "enable", "--now", `${labelProxy}.service`]);
  } else if (platform === "win32") {
    const syncTask = `${labelSync}`;
    const proxyTask = `${labelProxy}`;
    run("schtasks", ["/create", "/tn", syncTask, "/sc", "MINUTE", "/mo", "5", "/f", "/tr", `\"${process.execPath}\" \"${syncScriptPath}\"`]);
    run("schtasks", ["/run", "/tn", syncTask], { allowFail: true });
    run("schtasks", ["/create", "/tn", proxyTask, "/sc", "ONLOGON", "/f", "/tr", `\"${proxyBin}\" --config \"${configFile}\"`]);
    run("schtasks", ["/run", "/tn", proxyTask], { allowFail: true });
  }

  if (!shouldSkipHealthcheck()) {
    const healthy = await waitForHealthy(port, 10000);
    if (!healthy) fail(`proxy did not become healthy (check ${proxyLog})`);
  }

  log("Updating Claude Code settings...");
  updateClaudeSettings({ claudeSettingsPath, port, model });

  if (!shouldSkipHealthcheck()) {
    log("Verifying reasoning.effort=xhigh ...");
    const ok = await verifyReasoningEffort(port, model);
    if (!ok) fail("expected reasoning.effort=xhigh but verification failed");
  }

  log("");
  log("All done.");
  log(`- Proxy: http://127.0.0.1:${port}`);
  log(`- Config: ${configFile}`);
  log(`- Claude settings: ${claudeSettingsPath}`);
  log("- Next: run 'claude'");
}

async function startFlow(opts) {
  const platform = currentPlatform();
  if (!["darwin", "linux", "win32"].includes(platform)) fail(`unsupported platform: ${platform}`);
  const homeDir = os.homedir();
  const username = getUsername();
  const configFile = path.join(homeDir, ".cli-proxy-api", "config.yaml");
  const port = readPortFromProxyConfig(configFile) ?? DEFAULT_PORT;
  const labelProxy = `com.${username}.cli-proxy-api`;
  const plistProxy = path.join(homeDir, "Library", "LaunchAgents", `${labelProxy}.plist`);
  const labelSync = `com.${username}.cli-proxy-api-token-sync`;
  const plistSync = path.join(homeDir, "Library", "LaunchAgents", `${labelSync}.plist`);

  if (platform === "darwin") {
    const uid = getUid();
    if (exists(plistSync)) {
      launchctlBootstrap(uid, plistSync);
      launchctlKickstart(uid, labelSync);
    }
    if (!exists(plistProxy)) fail(`missing plist: ${plistProxy} (run install first)`);
    launchctlBootstrap(uid, plistProxy);
    launchctlKickstart(uid, labelProxy);
  } else if (platform === "linux") {
    run("systemctl", ["--user", "start", `${labelSync}.service`], { allowFail: true });
    run("systemctl", ["--user", "enable", "--now", `${labelSync}.path`], { allowFail: true });
    run("systemctl", ["--user", "enable", "--now", `${labelProxy}.service`]);
  } else {
    run("schtasks", ["/run", "/tn", `${labelSync}`], { allowFail: true });
    run("schtasks", ["/run", "/tn", `${labelProxy}`]);
  }

  if (!shouldSkipHealthcheck()) {
    const healthy = await waitForHealthy(port, 10000);
    if (!healthy) fail("proxy did not become healthy");
  }
  log("proxy started");
}

async function stopFlow() {
  const platform = currentPlatform();
  if (!["darwin", "linux", "win32"].includes(platform)) fail(`unsupported platform: ${platform}`);
  const username = getUsername();
  const labelProxy = `com.${username}.cli-proxy-api`;
  const labelSync = `com.${username}.cli-proxy-api-token-sync`;
  if (platform === "darwin") {
    const uid = getUid();
    launchctlBootout(uid, labelProxy);
    launchctlBootout(uid, labelSync);
    log("proxy stopped (launchagents unloaded)");
  } else if (platform === "linux") {
    run("systemctl", ["--user", "stop", `${labelProxy}.service`], { allowFail: true });
    run("systemctl", ["--user", "stop", `${labelSync}.path`], { allowFail: true });
    log("proxy stopped (systemd user units stopped)");
  } else {
    run("schtasks", ["/end", "/tn", `${labelProxy}`], { allowFail: true });
    log("proxy stop requested (windows scheduled task ended)");
  }
}

async function statusFlow(opts) {
  const homeDir = os.homedir();
  const configFile = path.join(homeDir, ".cli-proxy-api", "config.yaml");
  const port = readPortFromProxyConfig(configFile) ?? DEFAULT_PORT;
  const portOk = await proxyHealthcheck(port);
  log(`healthcheck: ${portOk ? "OK" : "NOT RUNNING"} (http://127.0.0.1:${port}/v1/models)`);
  const platform = currentPlatform();
  if (platform === "darwin") {
    const username = getUsername();
    const uid = getUid();
    const labelProxy = `com.${username}.cli-proxy-api`;
    const labelSync = `com.${username}.cli-proxy-api-token-sync`;
    log(`launchctl proxy job: ${launchctlPrint(uid, labelProxy) ? "loaded" : "not loaded"}`);
    log(`launchctl token-sync job: ${launchctlPrint(uid, labelSync) ? "loaded" : "not loaded"}`);
  } else if (platform === "linux") {
    const rProxy = run("systemctl", ["--user", "is-active", `${getUsername()}.cli-proxy-api.service`], { allowFail: true });
    const rSync = run("systemctl", ["--user", "is-active", `${getUsername()}.cli-proxy-api-token-sync.path`], { allowFail: true });
    log(`systemd proxy service: ${rProxy.status === 0 ? "active" : "inactive"}`);
    log(`systemd token-sync path: ${rSync.status === 0 ? "active" : "inactive"}`);
  } else if (platform === "win32") {
    const user = getUsername();
    log(`windows scheduled tasks: ${`com.${user}.cli-proxy-api`} / ${`com.${user}.cli-proxy-api-token-sync`}`);
  }
}

async function uninstallFlow(opts) {
  const platform = currentPlatform();
  if (!["darwin", "linux", "win32"].includes(platform)) fail(`unsupported platform: ${platform}`);
  const homeDir = os.homedir();
  const username = getUsername();
  const labelProxy = `com.${username}.cli-proxy-api`;
  const labelSync = `com.${username}.cli-proxy-api-token-sync`;
  const plistProxy = path.join(homeDir, "Library", "LaunchAgents", `${labelProxy}.plist`);
  const plistSync = path.join(homeDir, "Library", "LaunchAgents", `${labelSync}.plist`);
  const linuxSystemdDir = path.join(homeDir, ".config", "systemd", "user");
  const linuxProxySvc = path.join(linuxSystemdDir, `${labelProxy}.service`);
  const linuxSyncSvc = path.join(linuxSystemdDir, `${labelSync}.service`);
  const linuxSyncPath = path.join(linuxSystemdDir, `${labelSync}.path`);
  const claudeSettingsPath = path.join(homeDir, ".claude", "settings.json");
  const proxyDir = path.join(homeDir, ".cli-proxy-api");
  const proxyBin = platform === "win32"
    ? path.join(homeDir, "AppData", "Local", "codex-claudecode-proxy", "cli-proxy-api.exe")
    : path.join(homeDir, ".local", "bin", "cli-proxy-api");

  if (platform === "darwin") {
    const uid = getUid();
    launchctlBootout(uid, labelProxy);
    launchctlBootout(uid, labelSync);

    if (exists(plistProxy)) fs.rmSync(plistProxy, { force: true });
    if (exists(plistSync)) fs.rmSync(plistSync, { force: true });
  } else if (platform === "linux") {
    run("systemctl", ["--user", "disable", "--now", `${labelProxy}.service`], { allowFail: true });
    run("systemctl", ["--user", "disable", "--now", `${labelSync}.path`], { allowFail: true });
    run("systemctl", ["--user", "daemon-reload"], { allowFail: true });
    if (exists(linuxProxySvc)) fs.rmSync(linuxProxySvc, { force: true });
    if (exists(linuxSyncSvc)) fs.rmSync(linuxSyncSvc, { force: true });
    if (exists(linuxSyncPath)) fs.rmSync(linuxSyncPath, { force: true });
  } else {
    run("schtasks", ["/delete", "/tn", `${labelProxy}`, "/f"], { allowFail: true });
    run("schtasks", ["/delete", "/tn", `${labelSync}`, "/f"], { allowFail: true });
  }

  // Always restore Claude Code settings so "claude" doesn't keep pointing at a removed proxy.
  cleanupClaudeSettings({ claudeSettingsPath, model: DEFAULT_MODEL });

  if (opts.command === "purge") {
    // Remove proxy installation files (best-effort).
    if (exists(proxyDir)) fs.rmSync(proxyDir, { recursive: true, force: true });
    if (exists(proxyBin)) fs.rmSync(proxyBin, { force: true });
    log("purge completed (proxy files removed)");
    return;
  }

  log("uninstall completed (proxy files left in place)");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.command === "help") usage(0);

  try {
    switch (opts.command) {
      case "install":
        await installFlow(opts);
        break;
      case "start":
        await startFlow(opts);
        break;
      case "stop":
        await stopFlow();
        break;
      case "status":
        await statusFlow(opts);
        break;
      case "uninstall":
        await uninstallFlow(opts);
        break;
      case "purge":
        await uninstallFlow(opts);
        break;
      default:
        usage(1);
    }
  } catch (e) {
    fail(e?.stack || String(e));
  }
}

await main();
