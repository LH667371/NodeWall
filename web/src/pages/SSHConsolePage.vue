<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from "vue";
import {
  ArrowLeft,
  Check,
  ChevronLeft,
  ChevronRight,
  Download,
  File as FileIcon,
  Folder as FolderIcon,
  Upload,
} from "@lucide/vue";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import { downloadFile, request } from "@/lib/api";
import { useI18n } from "@/lib/i18n";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t } = useI18n();
const terminalHost = ref(null);
const terminal = ref(null);
const fitAddon = ref(null);
const socket = ref(null);
const status = ref("idle");
const message = ref("");
const pendingFingerprint = ref("");
const currentPath = ref(".");
const pathInput = ref(".");
const entries = ref([]);
const uploadInput = ref(null);
const webTransportPort = ref("");
const form = reactive({ host: "", port: 22, user: "root", fingerprint: "" });
let terminalResizeObserver = null;
let nodeSwitchSerial = 0;
let pageMounted = false;

const node = computed(() => (props.store.state.nodes || []).find((item) => item.id === props.store.state.sshConsole.nodeId) || null);
const sessionID = computed(() => props.store.state.sshConsole.sessionId || "");
const connected = computed(() => status.value === "connected" && !!sessionID.value);
const canGoParent = computed(() => connected.value && currentPath.value !== "/");

function resetTerminalForNode() {
  socket.value?.close();
  socket.value = null;
  status.value = "idle";
  message.value = "";
  pendingFingerprint.value = "";
  form.fingerprint = "";
  currentPath.value = ".";
  pathInput.value = ".";
  entries.value = [];
  terminal.value?.clear();
}

// The header node selector remains visible while this page is open. A node
// switch must close the old SSH session before creating a session for the new
// target; otherwise the terminal and SFTP panel can continue showing the
// previous host even though the header already changed.
watch(() => props.store.state.sshConsole.nodeId, async (nextNode, previousNode) => {
  if (!pageMounted || !nextNode || nextNode === previousNode) return;
  const serial = ++nodeSwitchSerial;
  resetTerminalForNode();
  await props.store.closeSSHConsoleSession();
  if (serial !== nodeSwitchSerial || nextNode !== props.store.state.sshConsole.nodeId) return;
  fillProfile();
  await nextTick();
  if (serial === nodeSwitchSerial && props.store.state.sshConsole.nodeId === nextNode) {
    await autoConnect();
  }
});

function fillProfile() {
  const profile = node.value?.ssh || {};
  form.host = profile.host || node.value?.advertise_ip || "";
  form.port = profile.port || 22;
  form.user = "root";
}

function appendTerminal(text) {
  terminal.value?.write(String(text || "").replace(/\n/g, "\r\n"));
}

function fitTerminal() {
  if (!fitAddon.value || !terminal.value) return;
  try {
    fitAddon.value.fit();
  } catch {
    // The host can briefly have zero size while the page is switching views.
    // The ResizeObserver will retry after the layout has settled.
    return;
  }
  sendResize();
}

function sendResize() {
	if (!socket.value || !terminal.value) return;
	sendTerminalMessage({ type: "resize", rows: terminal.value.rows, cols: terminal.value.cols });
}

function sendTerminalMessage(payload) {
	if (!socket.value) return false;
	if (socket.value.kind === "webtransport") {
		return socket.value.send(payload);
	}
	if (socket.value.readyState === WebSocket.OPEN) {
		socket.value.send(JSON.stringify(payload));
		return true;
	}
	return false;
}

function connectTerminalSocket() {
	const scheme = window.location.protocol === "https:" ? "wss" : "ws";
	const nextSocket = new WebSocket(`${scheme}://${window.location.host}/ssh-sessions/${encodeURIComponent(sessionID.value)}/terminal`);
	socket.value = nextSocket;
	nextSocket.onopen = () => {
		status.value = "connected";
    message.value = "";
    fitTerminal();
    terminal.value?.focus();
    loadFiles(".").catch((error) => { message.value = error.message; });
  };
  nextSocket.onmessage = (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      appendTerminal(event.data);
      return;
    }
    if (payload.type === "output") appendTerminal(payload.data);
    if (payload.type === "error") {
      status.value = "error";
      message.value = payload.data || t("sshConsoleConnectFailed");
      appendTerminal(`\r\n${message.value}\r\n`);
    }
    if (payload.type === "exit") {
      status.value = "closed";
      appendTerminal(`\r\n${t("sshConsoleClosed")}\r\n`);
    }
  };
  nextSocket.onerror = () => {
    status.value = "error";
    message.value = t("sshConsoleConnectFailed");
  };
  nextSocket.onclose = () => {
    if (status.value === "connected") status.value = "closed";
	};
}

function webTransportURL() {
	const url = new URL(`/ssh-sessions/${encodeURIComponent(sessionID.value)}/terminal-transport`, window.location.origin);
	url.protocol = "https:";
	if (webTransportPort.value) url.port = webTransportPort.value;
	return url.toString();
}

async function connectTerminalWebTransport() {
	if (typeof window.WebTransport !== "function" || !webTransportPort.value) throw new Error("WebTransport unavailable");
	let transport;
	try {
		transport = new window.WebTransport(webTransportURL());
		await transport.ready;
		const stream = await transport.createBidirectionalStream();
		const encoder = new TextEncoder();
		const decoder = new TextDecoder();
		const writer = stream.writable.getWriter();
		const reader = stream.readable.getReader();
		const connection = {
			kind: "webtransport",
			transport,
			writer,
			closed: false,
			send(payload) {
				if (this.closed) return false;
				writer.write(encoder.encode(`${JSON.stringify(payload)}\n`)).catch(() => {});
				return true;
			},
			close() {
				if (this.closed) return;
				this.closed = true;
				reader.cancel().catch(() => {});
				writer.close().catch(() => {});
				transport.close();
			},
		};
		socket.value = connection;
		status.value = "connected";
		message.value = "";
		void (async () => {
			let buffer = "";
			try {
				while (!connection.closed) {
					const result = await reader.read();
					if (result.done) break;
					buffer += decoder.decode(result.value, { stream: true });
					const lines = buffer.split("\n");
					buffer = lines.pop() || "";
					for (const line of lines) {
						if (!line.trim()) continue;
						const payload = JSON.parse(line);
						if (payload.type === "output") appendTerminal(payload.data);
						if (payload.type === "error") {
							status.value = "error";
							message.value = payload.data || t("sshConsoleConnectFailed");
							appendTerminal(`\r\n${message.value}\r\n`);
						}
						if (payload.type === "exit") {
							status.value = "closed";
							appendTerminal(`\r\n${t("sshConsoleClosed")}\r\n`);
						}
					}
				}
			} catch (error) {
				if (!connection.closed) {
					status.value = "error";
					message.value = error?.message || t("sshConsoleConnectFailed");
				}
			}
			if (!connection.closed && status.value === "connected") status.value = "closed";
		})();
		fitTerminal();
		terminal.value?.focus();
		loadFiles(".").catch((error) => { message.value = error.message; });
	} catch (error) {
		transport?.close();
		throw error;
	}
}

async function connectTerminal() {
	try {
		await connectTerminalWebTransport();
	} catch {
		// Older browsers, unavailable UDP, and certificate/network failures use
		// the existing WSS implementation without interrupting the SSH session.
		connectTerminalSocket();
	}
}

async function connect() {
  form.user = "root";
  if (!form.host) {
    message.value = t("sshConsoleRequired");
    return false;
  }
  status.value = "connecting";
  message.value = "";
  try {
    await props.store.closeSSHConsoleSession();
    await props.store.createSSHConsoleSession({
      host: form.host.trim(),
      port: Number(form.port || 22),
      user: form.user.trim(),
      fingerprint: form.fingerprint,
    });
    pendingFingerprint.value = "";
    await nextTick();
		await connectTerminal();
    return "connected";
  } catch (error) {
    const payload = error?.payload || {};
    if (payload.code === "SSH_HOST_KEY_CONFIRMATION_REQUIRED") {
      pendingFingerprint.value = payload.fingerprint || "";
      message.value = t("sshConsoleFingerprintHint");
      status.value = "fingerprint";
      return "fingerprint";
    }
    status.value = "error";
    message.value = error?.message || t("sshConsoleConnectFailed");
    return false;
  }
}

async function trustFingerprint() {
  form.fingerprint = pendingFingerprint.value;
  await connect();
}

async function discoverSSHPorts() {
  const nodeID = String(props.store.state.sshConsole.nodeId || "");
  const candidates = [];
  const add = (value) => {
    const port = Number(value);
    if (Number.isInteger(port) && port >= 1 && port <= 65535 && !candidates.includes(port)) candidates.push(port);
  };
  add(node.value?.ssh?.port);
  add(22);

  // The agent reports the ports owned by the running sshd master. Use it as
  // the authoritative source, then retain a small fallback list for nodes
  // whose agent is temporarily unreachable during console startup.
  try {
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection`, { timeoutMs: 4000 });
    for (const port of response?.ports || []) add(port);
  } catch {
    // The fallback below keeps console startup usable during an agent restart.
  }
  for (const port of [2222, 2200, 2022, 10022, 8022]) add(port);
  return candidates;
}

async function autoConnect() {
  fillProfile();
  pendingFingerprint.value = "";
  form.fingerprint = "";
  status.value = "discovering";
  message.value = t("sshConsoleDetecting");
  try {
    if (!form.host) throw new Error(t("sshConsoleRequired"));
    const ports = await discoverSSHPorts();
    let lastError = "";
    for (const port of ports) {
      if (!props.store.state.sshConsole.nodeId) throw new Error(t("sshConsoleRequired"));
      form.port = port;
      const result = await connect();
      if (result === "connected" || result === "fingerprint") return;
      lastError = message.value;
    }
    throw new Error(lastError || t("sshConsoleNoPort"));
  } catch (error) {
    status.value = "error";
    message.value = error?.message || t("sshConsoleConnectFailed");
  }
}

async function loadFiles(remotePath) {
  if (!sessionID.value) return;
  const query = new URLSearchParams({ path: remotePath || "." });
  const response = await request(`/ssh-sessions/${encodeURIComponent(sessionID.value)}/files?${query}`);
  currentPath.value = response.path || remotePath || ".";
  pathInput.value = currentPath.value;
  entries.value = Array.isArray(response.entries) ? response.entries : [];
}

function openEntry(entry) {
  if (entry.directory) loadFiles(entry.path).catch((error) => { message.value = error.message; });
}

function parentPath() {
  const value = String(currentPath.value || "/").trim().replace(/\/+$/, "") || "/";
  if (value === "/") return;
  const index = value.lastIndexOf("/");
  const target = index <= 0 ? "/" : value.slice(0, index);
  loadFiles(target).catch((error) => { message.value = error.message; });
}

function resolvePathInput(value) {
  const raw = String(value || "").trim();
  if (!raw || raw === "." || raw === "~") return currentPath.value || ".";
  if (raw.startsWith("/")) return raw;
  if (raw.startsWith("~/")) return `./${raw.slice(2)}`;
  const base = currentPath.value || ".";
  return base === "/" ? `/${raw}` : `${base}/${raw}`;
}

async function jumpToPath() {
  if (!connected.value) return;
  const requestedPath = pathInput.value;
  try {
    await loadFiles(resolvePathInput(requestedPath));
    message.value = "";
  } catch (error) {
    pathInput.value = currentPath.value;
    message.value = error?.message || t("sshConsolePathFailed");
  }
}

async function uploadFile(event) {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file || !sessionID.value) return;
  const target = currentPath.value === "." ? file.name : `${currentPath.value.replace(/\/$/, "")}/${file.name}`;
  const body = new FormData();
  body.append("file", file);
  body.append("path", target);
  const response = await fetch(`/ssh-sessions/${encodeURIComponent(sessionID.value)}/files`, { method: "POST", body });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || t("sshConsoleUploadFailed"));
  message.value = t("sshConsoleUploadDone");
  await loadFiles(currentPath.value);
}

async function downloadEntry(entry) {
  if (entry.directory) return;
  try {
    const result = await downloadFile(`/ssh-sessions/${encodeURIComponent(sessionID.value)}/files?download=1&path=${encodeURIComponent(entry.path)}`);
    const url = URL.createObjectURL(result.blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = result.filename || entry.name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    message.value = error?.message || t("sshConsoleDownloadFailed");
  }
}

function handleEntryDoubleClick(entry) {
  if (entry.directory) {
    openEntry(entry);
    return;
  }
  void downloadEntry(entry);
}

function formatFileSize(value) {
  const size = Number(value) || 0;
  if (size < 1024) return `${size} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = size;
  let unitIndex = -1;
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024;
    unitIndex += 1;
  }
  return `${scaled >= 10 || unitIndex === 0 ? scaled.toFixed(0) : scaled.toFixed(1)} ${units[unitIndex]}`;
}

async function closePage() {
  socket.value?.close();
  await props.store.closeSSHConsole();
}

onMounted(() => {
  pageMounted = true;
  fillProfile();
	request("/bootstrap").then((response) => { webTransportPort.value = response.h3_port || ""; }).catch(() => {});
  const nextTerminal = new Terminal({
    convertEol: true,
    cursorBlink: true,
    fontSize: 13,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    theme: { background: "#0b1726", foreground: "#d8f7f4", cursor: "#2dc0b6" },
  });
  const nextFitAddon = new FitAddon();
  nextTerminal.loadAddon(nextFitAddon);
  nextTerminal.open(terminalHost.value);
	nextTerminal.onData((data) => {
		sendTerminalMessage({ type: "input", data });
  });
  terminal.value = nextTerminal;
  fitAddon.value = nextFitAddon;
  terminalResizeObserver = new ResizeObserver(() => fitTerminal());
  terminalResizeObserver.observe(terminalHost.value);
  nextTick(() => {
    fitTerminal();
    void autoConnect();
  });
});

onBeforeUnmount(async () => {
	pageMounted = false;
	++nodeSwitchSerial;
	terminalResizeObserver?.disconnect();
	terminalResizeObserver = null;
  socket.value?.close();
  await props.store.closeSSHConsoleSession();
  terminal.value?.dispose();
});
</script>

<template>
  <section class="page-grid">
    <article class="panel panel-span-12 ssh-console-page">
      <div class="panel-head">
        <div>
          <p>{{ t("sshConsoleEyebrow") }}</p>
          <h3>{{ node?.name || node?.id || "-" }}</h3>
          <p class="ssh-console-context">
            {{ t("headerNodeSelect") }}：<code>{{ node?.id || "-" }}</code>
            <span>{{ form.host || node?.advertise_ip || "-" }}:{{ form.port || 22 }}</span>
          </p>
        </div>
        <div class="panel-actions">
          <span class="status-pill" :class="{ danger: status === 'error' || status === 'closed' }">{{ status === "connected" ? t("sshConsoleConnected") : (status === "discovering" || status === "connecting" ? t("sshConsoleConnecting") : t("sshConsoleDisconnected")) }}</span>
          <button class="ghost-button" @click="closePage">
            <ArrowLeft :size="15" stroke-width="1.9" aria-hidden="true" />
            {{ t("back") }}
          </button>
        </div>
      </div>

      <div v-if="!connected" class="ssh-console-connect ssh-console-auto-connect">
        <div class="ssh-console-target">
          <span>{{ t("sshConsoleTarget") }}</span>
          <strong>{{ form.user }}@{{ form.host || "-" }}</strong>
          <small>{{ form.port ? `SSH :${form.port}` : t("sshConsoleDetecting") }}</small>
        </div>
        <button v-if="status === 'error' || status === 'closed'" class="primary-button" :disabled="status === 'connecting' || status === 'discovering'" @click="autoConnect">
          {{ t("sshConsoleRetry") }}
        </button>
        <div v-if="pendingFingerprint" class="ssh-fingerprint-box">
          <strong>{{ t("sshConsoleFingerprintTitle") }}</strong>
          <code>{{ pendingFingerprint }}</code>
          <button class="primary-button" @click="trustFingerprint">
            <Check :size="16" stroke-width="2" aria-hidden="true" />
            {{ t("sshConsoleTrustFingerprint") }}
          </button>
        </div>
        <button v-else class="primary-button" :disabled="status === 'connecting'" @click="connect">{{ status === "connecting" ? t("sshConsoleConnecting") : t("sshConsoleConnect") }}</button>
      </div>

      <p v-if="message" class="panel-subcopy" :class="{ 'danger-text': status === 'error' || status === 'fingerprint' }">{{ message }}</p>

      <div class="ssh-console-layout">
        <div class="ssh-terminal-shell">
          <div ref="terminalHost" class="ssh-terminal"></div>
        </div>
        <aside class="ssh-file-panel">
          <div class="ssh-file-head">
            <strong>{{ t("sshConsoleFiles") }}</strong>
          </div>
          <div class="ssh-file-toolbar">
            <button
              class="ssh-file-icon-button"
              type="button"
              :disabled="!canGoParent"
              :title="t('sshConsoleGoParent')"
              :aria-label="t('sshConsoleGoParent')"
              @click="parentPath"
            >
              <ChevronLeft :size="17" stroke-width="2" aria-hidden="true" />
            </button>
            <input
              v-model="pathInput"
              class="ssh-current-path-input"
              type="text"
              :placeholder="t('sshConsolePathPlaceholder')"
              :title="t('sshConsolePathHint')"
              :aria-label="t('sshConsolePathHint')"
              :disabled="!connected"
              @keydown.enter.prevent="jumpToPath"
            />
            <button
              class="ssh-file-icon-button"
              type="button"
              :disabled="!connected"
              :title="t('sshConsoleUpload')"
              :aria-label="t('sshConsoleUpload')"
              @click="uploadInput?.click()"
            >
              <Upload :size="17" stroke-width="1.9" aria-hidden="true" />
            </button>
            <input ref="uploadInput" class="hidden-field" type="file" @change="uploadFile($event).catch((error) => { message = error.message; })" />
          </div>
          <div class="ssh-file-list">
            <div v-for="entry in entries" :key="entry.path" class="ssh-file-row" :class="{ directory: entry.directory }" @dblclick="handleEntryDoubleClick(entry)">
              <span class="ssh-file-name" :title="entry.name">
                <span class="ssh-file-kind" aria-hidden="true">
                  <FolderIcon v-if="entry.directory" :size="16" stroke-width="1.8" />
                  <FileIcon v-else :size="16" stroke-width="1.8" />
                </span>
                <span class="ssh-file-name-text">{{ entry.name }}</span>
              </span>
              <small>{{ entry.directory ? "DIR" : formatFileSize(entry.size) }}</small>
              <button
                class="ssh-file-action"
                type="button"
                :title="entry.directory ? t('sshConsoleOpenDirectory') : t('sshConsoleDownload')"
                :aria-label="entry.directory ? t('sshConsoleOpenDirectory') : t('sshConsoleDownload')"
                @click.stop="entry.directory ? openEntry(entry) : downloadEntry(entry)"
              >
                <ChevronRight v-if="entry.directory" :size="17" stroke-width="2" aria-hidden="true" />
                <Download v-else :size="16" stroke-width="1.9" aria-hidden="true" />
              </button>
            </div>
            <div v-if="!entries.length" class="empty-state">{{ t("sshConsoleFilesEmpty") }}</div>
          </div>
        </aside>
      </div>
    </article>
  </section>
</template>

<style scoped>
.ssh-console-context {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin: 4px 0 0;
  color: var(--muted-text);
  font-size: 12px;
}
.ssh-console-context code { color: var(--text-color); }
</style>
