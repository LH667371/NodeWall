import { computed, reactive } from "vue";
import { downloadFile, request, withDirection } from "@/lib/api";

function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(Number(value || 0));
}

function normalizeIPv4(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const direct = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
  const candidate = direct?.[1] || raw.match(/(\d{1,3}(?:\.\d{1,3}){3})/)?.[1] || "";
  if (!candidate) return "";
  const parts = candidate.split(".").map((item) => Number(item));
  if (parts.length !== 4 || parts.some((item) => !Number.isInteger(item) || item < 0 || item > 255)) return "";
  return parts.join(".");
}

function normalizeList(value, key) {
  return Array.isArray(value?.[key]) ? value[key] : [];
}

function normalizePortRules(value, rulesKey, portsKey) {
  if (Array.isArray(value?.[rulesKey]) && value[rulesKey].length) return value[rulesKey];
  const ports = Array.isArray(value?.[portsKey]) ? value[portsKey] : [];
  return ports.flatMap((port) => [{ protocol: "tcp", port }, { protocol: "udp", port }]);
}

function cloneArray(value) {
  return Array.isArray(value) ? [...value] : [];
}

function normalizeDirectionPolicyDraft(input, fallbackNonIPv4 = "drop") {
  return {
    enabled: input?.enabled ?? true,
    mode: input?.mode || "whitelist",
    default_action: input?.default_action || "drop",
    non_ipv4_action: input?.non_ipv4_action || fallbackNonIPv4 || "drop",
    bypass_cidrs: cloneArray(input?.bypass_cidrs),
    blocked_cidrs: cloneArray(input?.blocked_cidrs),
    icmp_allow_cidrs: cloneArray(input?.icmp_allow_cidrs),
    icmp_blocked_cidrs: cloneArray(input?.icmp_blocked_cidrs),
    public_ports: cloneArray(input?.public_ports),
    denied_ports: cloneArray(input?.denied_ports),
    allowed_ports: cloneArray(input?.allowed_ports),
    public_port_rules: cloneArray(input?.public_port_rules),
    denied_port_rules: cloneArray(input?.denied_port_rules),
    allowed_port_rules: cloneArray(input?.allowed_port_rules),
    challenge: input?.challenge || {},
    rules: cloneArray(input?.rules),
    rule_descriptions: cloneArray(input?.rule_descriptions),
    observe_only: !!input?.observe_only,
    pending_publish: input?.pending_publish || null,
  };
}

function normalizedPortRuleDraft(rules, ports) {
  if (Array.isArray(rules) && rules.length) {
    return rules.map((item) => ({
      protocol: String(item?.protocol || "tcp").toLowerCase(),
      port: Number(item?.port || 0),
    })).filter((item) => item.port > 0 || item.protocol === "icmp");
  }
  return (Array.isArray(ports) ? ports : []).flatMap((port) => [
    { protocol: "tcp", port: Number(port) },
    { protocol: "udp", port: Number(port) },
  ]).filter((item) => item.port > 0);
}

function collapsePortRuleDraft(rules) {
  return Array.from(new Set((rules || []).map((item) => Number(item?.port || 0)).filter((port) => port > 0))).sort((a, b) => a - b);
}

function uniqStrings(items = []) {
  return Array.from(new Set((items || []).map((item) => String(item || "").trim()).filter(Boolean)));
}

function logKey(item) {
  return [item.interface || "-", item.direction || "ingress", item.source_ip || "-", item.port || 0, item.timestamp || "-"].join("|");
}

function riskFromInsights(insights, stats) {
  if ((insights.top_attackers || []).some((item) => item.risk === "high")) return "high";
  if ((insights.top_attackers || []).some((item) => item.risk === "medium")) return "medium";
  if ((stats.dropped || 0) > 0) return "medium";
  return "low";
}

export function useNodewallConsole(i18n) {
  const t = i18n?.t || ((key) => key);
  let clusterEventSource = null;
  let clusterReconnectTimer = null;
  let clusterAuthCheckInFlight = null;
  let securityScanTimer = null;
  let refreshCurrentToken = 0;
  let refreshCurrentInFlight = null;
  let refreshCurrentQueued = false;
  let refreshCurrentQueuedAutoSwitch = null;
  let sectionRefreshInFlight = null;
  let sectionRefreshQueued = null;
  let clusterAggregateInFlight = null;
  let clusterAggregateLastAt = 0;
  let toastCounter = 0;
  const deleteEventSeen = new Set();
  const toastTimers = new Map();
  const CLUSTER_AGGREGATE_TTL_MS = 5000;
  const SECURITY_FEATURE_SET = new Set(["firewall", "malware", "ssh"]);
  const SECTION_SET = new Set(["overview", "cluster", "policy", "logs", "monitoring", "events", "management", "security", "ssh-console"]);

  function normalizeSecurityFeature(value) {
    const next = String(value || "").trim().toLowerCase();
    return SECURITY_FEATURE_SET.has(next) ? next : "firewall";
  }

  function normalizeSection(value) {
    const next = String(value || "").trim().toLowerCase();
    if (next === "malware" || next === "ssh" || next === "firewall") return "security";
    return SECTION_SET.has(next) ? next : "overview";
  }

  function sectionFromLocation() {
    if (typeof window === "undefined") return "overview";
    const hash = String(window.location.hash || "").replace(/^#/, "");
    if (SECTION_SET.has(hash)) return hash;
    if (SECURITY_FEATURE_SET.has(hash)) return "security";
    const query = new URLSearchParams(window.location.search || "");
    return normalizeSection(query.get("section"));
  }

  function securityFeatureFromLocation() {
    if (typeof window === "undefined") return "";
    const hash = String(window.location.hash || "").replace(/^#/, "");
    if (SECURITY_FEATURE_SET.has(hash)) return hash;
    const query = new URLSearchParams(window.location.search || "");
    const feature = String(query.get("feature") || query.get("section") || "").trim().toLowerCase();
    return SECURITY_FEATURE_SET.has(feature) ? feature : "";
  }

  function writeSectionToLocation(section) {
    if (typeof window === "undefined") return;
    const normalized = normalizeSection(section);
    if (window.location.hash === `#${normalized}`) return;
    window.location.hash = normalized;
  }

  function applySectionFromLocation(shouldRefresh = true) {
    const next = sectionFromLocation();
    const feature = securityFeatureFromLocation();
    if (feature) state.securityFeature = normalizeSecurityFeature(feature);
    if (next === state.section) return;
    state.section = next;
    state.error = "";
    if (shouldRefresh) {
      queueSectionRefresh(next).catch(handleError);
    }
  }

  const state = reactive({
    section: "overview",
    securityFeature: "firewall",
    eventsView: "logs",
    overviewScope: "all",
    direction: "ingress",
    nodeId: "node-01",
    nodes: [],
    defaultInterface: "",
    recommendedInterface: "",
    currentSourceIP: "",
    interfaces: [],
    selectedInterface: "",
    loading: false,
    error: "",
    actionBusy: {
      attach: false,
      detach: false,
      refresh: false,
    },
    toasts: [],
    errorDialog: {
      open: false,
      message: "",
    },
    nodeDeleteEvents: [],
    authEnabled: false,
    authAuthenticated: false,
    authUsername: "",
    authRole: "",
    loggingSettings: {
      enabled: true,
      retention_days: 7,
      flush_interval_seconds: 30,
      reply_flow_timeout_seconds: 60,
      log_dir: "",
    },
    authSettings: {
      max_failures: 5,
      window_seconds: 600,
      lock_duration_seconds: 900,
      active_locks: 0,
    },
    sshProtection: {
      loading: false,
      settings: {
        enabled: false,
        max_failures: 5,
        window_seconds: 600,
        ban_duration_seconds: 3600,
        trusted_cidrs: [],
        log_path: "/var/log/auth.log",
        transfer: {
          block_sftp: false,
          block_scp: false,
          audit_transfers: false,
          audit_sessions: false,
          audit_commands: false,
          scan_uploads: false,
        },
      },
      ports: [22],
      active_blocks: [],
      tracked_sources: 0,
      total_bans: 0,
      last_failure_at: null,
      last_ban_at: null,
      last_error: "",
      integrity: {
        enabled: false,
        paths: [],
        baseline_files: 0,
        added: 0,
        changed: 0,
        deleted: 0,
        last_error: "",
      },
      upload_security: {
        enabled: false,
        last_status: "",
        files_checked: 0,
        findings: 0,
        last_error: "",
      },
      activity: [],
    },
    sshConsole: {
      nodeId: "",
      sessionId: "",
    },
    securitySummary: {
      engine: "nodewall",
      checks: [],
      scan: { status: "idle", findings: [] },
      quarantine: { enabled: true, automatic: false },
    },
    securityQuarantine: {
      root: "",
      entries: [],
    },
    // Overview uses this lightweight per-node snapshot to show the health of
    // every protection capability without duplicating the detailed pages.
    securityOverviewNodes: [],
    users: [],
    inventory: { interfaces: [], recommended: "" },
    health: { interfaces: [] },
    policy: {},
    protectionTrial: null,
    stats: { passed: 0, dropped: 0 },
    recentStats: {
      window_seconds: 300,
      recent_passed: 0,
      recent_dropped: 0,
      passed_pps: 0,
      dropped_pps: 0,
      drop_rate: 0,
    },
    insights: {
      top_attackers: [],
      top_countries: [],
      top_ports: [],
      top_passed: [],
      trend: [],
      suggested_blocks: [],
    },
    clusterAggregate: {
      passed: 0,
      dropped: 0,
      recent_passed: 0,
      recent_dropped: 0,
      passed_pps: 0,
      dropped_pps: 0,
      drop_rate: 0,
      window_seconds: 300,
      trusted: 0,
      pendingRelease: 0,
      nodes: [],
      top_attackers: [],
      top_countries: [],
      top_ports: [],
      top_passed: [],
      trend: [],
      system: {
        node_count: 0,
        sampled_nodes: 0,
        average_cpu_percent: 0,
        average_memory_percent: 0,
        rx_bytes_per_second: 0,
        tx_bytes_per_second: 0,
      },
    },
    persistedLogs: [],
    interfaceLogs: [],
    temporaryBlocks: [],
    rateLimits: [],
    bypassCIDRs: [],
    blockedCIDRs: [],
    icmpAllowCIDRs: [],
    icmpBlockedCIDRs: [],
    allowlist: [],
    publicPorts: [],
    deniedPorts: [],
    allowedPorts: [],
    publicPortRules: [],
    deniedPortRules: [],
    allowedPortRules: [],
    filters: {
      logsQuery: "",
      logsInterface: "",
      logsDirection: "",
      logsReason: "",
      logsStatus: "",
      interfaceQuery: "",
      interfaceScope: "focus",
    },
    selection: new Set(),
    modal: {
      open: false,
      title: "",
      copy: "",
      fields: [],
      onConfirm: null,
    },
    forms: {
      allowlist: "",
      bypass: "",
      blocked: "",
      publicPort: "",
      deniedPort: "",
      allowedPort: "",
      nonIPv4: "drop",
      currentPassword: "",
      newPassword: "",
      createUsername: "",
      createPassword: "",
      createRole: "viewer",
      resetPassword: "",
    },
  });

  const currentInterface = computed(() => {
    if (state.selectedInterface) return state.selectedInterface;
    if (state.defaultInterface) return state.defaultInterface;
    if (state.recommendedInterface) return state.recommendedInterface;
    const physical = (state.interfaces || []).find((item) => item?.is_physical);
    return physical?.name || state.interfaces[0]?.name || "";
  });
  const currentInterfaceRecord = computed(() => (state.interfaces || []).find((item) => item.name === currentInterface.value) || null);
  const currentNode = computed(() => (state.nodes || []).find((item) => item.id === state.nodeId) || null);

  function resetNodeScopedSecurityData(nodeID = "") {
    // Clear data from the previous host immediately. Requests are guarded by
    // node ID below, but clearing here also prevents a brief cross-host view
    // while the newly selected Agent is still loading.
    state.securitySummary = {
      engine: "nodewall",
      node_id: nodeID,
      checks: [],
      scan: { status: "idle", findings: [], node_id: nodeID },
      quarantine: { enabled: true, automatic: false },
    };
    state.securityQuarantine = { root: "", entries: [], node_id: nodeID };
    state.sshProtection = {
      ...state.sshProtection,
      node_id: nodeID,
      loading: true,
      settings: {
        // A node switch temporarily has no authoritative value. Keeping an
        // explicit loading state avoids presenting the previous node's
        // setting as disabled while the new Agent is being queried.
        enabled: null,
        max_failures: 5,
        window_seconds: 600,
        ban_duration_seconds: 3600,
        trusted_cidrs: [],
        log_path: "/var/log/auth.log",
        transfer: {
          block_sftp: false,
          block_scp: false,
          audit_transfers: false,
          audit_sessions: false,
          audit_commands: false,
          scan_uploads: false,
        },
      },
      ports: [],
      active_blocks: [],
      tracked_sources: 0,
      total_bans: 0,
      last_failure_at: null,
      last_ban_at: null,
      last_error: "",
      integrity: {
        enabled: false,
        paths: [],
        baseline_files: 0,
        added: 0,
        changed: 0,
        deleted: 0,
        last_error: "",
      },
      upload_security: {
        enabled: false,
        last_status: "",
        files_checked: 0,
        findings: 0,
        last_error: "",
      },
      activity: [],
    };
  }

  const metrics = computed(() => ({
    passed: state.stats.passed || 0,
    dropped: state.stats.dropped || 0,
    trusted: state.allowlist.length + state.bypassCIDRs.length,
    risk: riskFromInsights(state.insights, state.stats),
  }));

  const filteredLogs = computed(() => {
    return state.persistedLogs.filter((item) => {
      if (state.filters.logsInterface && item.interface !== state.filters.logsInterface) return false;
      if (state.filters.logsDirection && (item.direction || "ingress") !== state.filters.logsDirection) return false;
      if (state.filters.logsReason && item.reason !== state.filters.logsReason) return false;
      const intercepted = Number(item?.drops ?? item?.count ?? 0) > 0;
      const handled = item?.disposition?.status && item.disposition.status !== "open";
      if (state.filters.logsStatus === "intercepted" && (!intercepted || handled)) return false;
      if (state.filters.logsStatus === "handled" && (!intercepted || !handled)) return false;
      const query = state.filters.logsQuery.trim().toLowerCase();
      if (!query) return true;
      return [
        item.source_ip,
        item.interface,
        item.reason,
        item.port,
        item.disposition?.status,
      ].join(" ").toLowerCase().includes(query);
    });
  });

  function formatLogReason(reason) {
    switch (reason) {
      case "reply_flow_allowed":
        return t("reasonReplyFlowAllowed");
      case "blocked_source":
        return t("reasonBlockedSource");
      case "denied_port":
        return t("reasonDeniedPort");
      case "restricted_policy":
        return t("reasonRestrictedPolicy");
      case "source_not_allowed":
        return t("reasonSourceNotAllowed");
      default:
        return reason || "-";
    }
  }

  const visibleInterfaces = computed(() => {
    const query = state.filters.interfaceQuery.trim().toLowerCase();
    const scope = state.filters.interfaceScope;
    return (state.inventory.interfaces || []).filter((item) => {
      if (scope === "attached" && !item.attached) return false;
      if (scope === "focus" && !(item.is_recommended || item.attached || (item.last_passed || item.last_dropped))) return false;
      if (!query) return true;
      return [item.name, ...(item.addresses || [])].join(" ").toLowerCase().includes(query);
    });
  });

  function setSection(section) {
    const requested = String(section || "").trim().toLowerCase();
    if (SECURITY_FEATURE_SET.has(requested)) state.securityFeature = requested;
    state.section = normalizeSection(requested);
    state.error = "";
    writeSectionToLocation(state.section);
    queueSectionRefresh(state.section).catch(handleError);
  }

  function setSecurityFeature(feature) {
    state.securityFeature = normalizeSecurityFeature(feature);
    // Keep the selected tool in the URL so a refresh returns to the same
    // security function instead of silently falling back to the firewall.
    if (typeof window !== "undefined" && state.section === "security") {
      const nextHash = `#${state.securityFeature}`;
      if (window.location.hash !== nextHash) window.location.hash = nextHash;
    }
  }

  function setEventsView(view) {
    state.eventsView = ["logs", "ssh"].includes(view) ? view : "logs";
  }

  function openSSHConsole(node) {
    const nodeID = String(node?.id || "");
    if (nodeID) state.nodeId = nodeID;
    state.sshConsole.nodeId = nodeID;
    state.sshConsole.sessionId = "";
    state.section = "ssh-console";
    writeSectionToLocation(state.section);
  }

  async function closeSSHConsole() {
    await closeSSHConsoleSession();
    state.section = "cluster";
    writeSectionToLocation(state.section);
  }

  async function createSSHConsoleSession(payload) {
    const nodeID = String(state.sshConsole.nodeId || state.nodeId || "");
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-sessions`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    });
    state.sshConsole.sessionId = response.id || "";
    return response;
  }

  async function closeSSHConsoleSession() {
    if (!state.sshConsole.sessionId) return;
    await request(`/ssh-sessions/${encodeURIComponent(state.sshConsole.sessionId)}`, { method: "DELETE" }).catch(() => {});
    state.sshConsole.sessionId = "";
  }

  function setDirection(direction) {
    state.direction = direction === "egress" ? "egress" : "ingress";
    state.error = "";
    const refreshCurrentFn = state.section === "overview" ? queueRefreshCurrent : queueRefreshCurrentLight;
    // A manually selected direction must remain selected even when it has no
    // rules yet. Automatic direction discovery is only appropriate during the
    // initial data load, otherwise an empty egress policy immediately jumps
    // back to ingress and makes the toggle appear broken.
    Promise.all([refreshCurrentFn(false), refreshClusterAggregate({ force: true })]).catch(handleError);
  }

  function setInterface(iface) {
    state.selectedInterface = iface;
    state.error = "";
    queueRefreshCurrent().catch(handleError);
  }

  async function setNode(nodeId) {
    if (!nodeId || nodeId === state.nodeId) return;
    if (state.section === "ssh-console" && state.sshConsole.sessionId) {
      await closeSSHConsoleSession();
    }
    state.nodeId = nodeId;
    if (state.section === "ssh-console") state.sshConsole.nodeId = nodeId;
    state.selectedInterface = "";
    state.defaultInterface = "";
    state.recommendedInterface = "";
    state.interfaces = [];
    if (securityScanTimer && typeof window !== "undefined") {
      window.clearTimeout(securityScanTimer);
      securityScanTimer = null;
    }
    resetNodeScopedSecurityData(nodeId);
    state.error = "";
    stopClusterEventStream();
    startClusterEventStream();
    try {
      await Promise.all([
        refreshNodes(),
        refreshInventory(),
        queueRefreshCurrentLight(false),
        refreshClusterAggregate({ force: true }),
      ]);
      await queueSectionRefresh(state.section);
    } catch (error) {
      handleError(error);
    }
  }

  function setOverviewScope(scope) {
    state.overviewScope = scope === "node" ? "node" : "all";
    // The scope is local UI state. Returning to the cluster view should
    // immediately remove node-only controls without a refresh or menu change.
    if (state.overviewScope === "all") state.error = "";
  }

  async function deleteNode(nodeId) {
    if (!nodeId) return;
    await request(`/nodes/${encodeURIComponent(nodeId)}?force=true`, { method: "DELETE" });
    if (state.nodeId === nodeId) {
      const fallback = (state.nodes || []).find((item) => item.id !== nodeId);
      state.nodeId = fallback?.id || "";
      state.selectedInterface = "";
    }
    await refreshAll();
  }

  function handleError(error) {
    if (error?.code === "SUPERSEDED" || error?.code === "ABORTED") return;
    const message = error?.message || String(error);
    if (message === "Request superseded" || message === "Request aborted") return;
    if (error?.code === "AUTH_REQUIRED") return;
    state.error = message === "Failed to fetch" ? t("requestErrorOffline") : message;
    state.errorDialog.open = true;
    state.errorDialog.message = state.error;
  }

  function closeErrorDialog() {
    state.errorDialog.open = false;
    state.errorDialog.message = "";
    state.error = "";
  }

  function dismissToast(id) {
    state.toasts = (state.toasts || []).filter((item) => item.id !== id);
    const timer = toastTimers.get(id);
    if (timer) {
      window.clearTimeout(timer);
      toastTimers.delete(id);
    }
  }

  function setNotice(text, type = "info") {
    const message = String(text || "").trim();
    if (!message) return;
    const id = `toast-${Date.now()}-${toastCounter++}`;
    state.toasts = [...(state.toasts || []), { id, text: message, type: type || "info" }].slice(-5);
    if (typeof window !== "undefined") {
      const timer = window.setTimeout(() => dismissToast(id), 3200);
      toastTimers.set(id, timer);
    }
  }

  async function withBusy(key, action) {
    state.actionBusy[key] = true;
    try {
      return await action();
    } finally {
      state.actionBusy[key] = false;
    }
  }

  function requireInterfaceEncoded() {
    if (!currentInterface.value) {
      throw new Error(t("requestErrorNoInterface"));
    }
    return encodeURIComponent(currentInterface.value);
  }

  function openModal(config) {
    state.modal.open = true;
    state.modal.title = config.title;
    state.modal.copy = config.copy;
    state.modal.fields = config.fields || [];
    state.modal.onConfirm = config.onConfirm || null;
  }

  function closeModal() {
    state.modal.open = false;
    state.modal.title = "";
    state.modal.copy = "";
    state.modal.fields = [];
    state.modal.onConfirm = null;
  }

  async function confirmModal(payload) {
    if (!state.modal.onConfirm) return;
    await state.modal.onConfirm(payload || {});
    closeModal();
  }

  async function bootstrap() {
    state.loading = true;
    try {
      applySectionFromLocation(false);
      const [session, bootstrapData] = await Promise.all([
        request("/auth/session").catch(() => ({ auth_enabled: false, authenticated: false })),
        request("/bootstrap"),
      ]);
      state.authEnabled = !!session.auth_enabled;
      state.authAuthenticated = !!session.authenticated;
      state.authUsername = session.username || "";
      state.authRole = session.role || "";
    state.nodeId = bootstrapData.node_id || state.nodeId;
      state.defaultInterface = bootstrapData.default_interface || "";
      state.recommendedInterface = bootstrapData.default_interface || "";
      state.currentSourceIP = bootstrapData.client_ip || "";
      startClusterEventStream();
      await refreshAll();
      if (state.section === "security") {
        await refreshSecurityData();
      }
      state.error = "";
      if (typeof window !== "undefined") {
        window.addEventListener("hashchange", () => applySectionFromLocation(true));
      }
    } finally {
      state.loading = false;
    }
  }

  function stopClusterEventStream() {
    if (clusterReconnectTimer) {
      window.clearTimeout(clusterReconnectTimer);
      clusterReconnectTimer = null;
    }
    if (clusterEventSource) {
      clusterEventSource.close();
      clusterEventSource = null;
    }
  }

  function startClusterEventStream() {
    stopClusterEventStream();
    if (typeof window === "undefined" || typeof window.EventSource === "undefined") return;
    clusterEventSource = new window.EventSource("/events/cluster");
    clusterEventSource.addEventListener("nodes", (event) => {
      try {
        const next = JSON.parse(event.data || "[]");
        if (!Array.isArray(next)) return;
        state.nodes = next;
        if (!state.nodes.some((item) => item.id === state.nodeId)) {
          state.nodeId = state.nodes[0]?.id || state.nodeId;
        }
      } catch (_) {
        // ignore parse errors from partial stream frames
      }
    });
    clusterEventSource.addEventListener("overview", (event) => {
      try {
        const payload = JSON.parse(event.data || "{}");
        const next = state.direction === "egress" ? payload?.egress : payload?.ingress;
        if (!next || typeof next !== "object") return;
        state.clusterAggregate = {
          passed: Number(next?.passed || 0),
          dropped: Number(next?.dropped || 0),
          recent_passed: Number(next?.recent_passed || 0),
          recent_dropped: Number(next?.recent_dropped || 0),
          passed_pps: Number(next?.passed_pps || 0),
          dropped_pps: Number(next?.dropped_pps || 0),
          drop_rate: Number(next?.drop_rate || 0),
          window_seconds: Number(next?.window_seconds || 300),
          trusted: Number(next?.trusted || 0),
          pendingRelease: Number(next?.pendingRelease || 0),
          nodes: Array.isArray(next?.nodes) ? next.nodes : state.clusterAggregate.nodes,
          top_attackers: Array.isArray(next?.top_attackers) ? next.top_attackers : [],
          top_countries: Array.isArray(next?.top_countries) ? next.top_countries : [],
          top_ports: Array.isArray(next?.top_ports) ? next.top_ports : [],
          top_passed: Array.isArray(next?.top_passed) ? next.top_passed : [],
          trend: Array.isArray(next?.trend) ? next.trend : [],
          system: next?.system && typeof next.system === "object" ? next.system : state.clusterAggregate.system,
        };
        clusterAggregateLastAt = Date.now();
      } catch (_) {
        // ignore parse errors from partial stream frames
      }
    });
    clusterEventSource.addEventListener("node_delete", (event) => {
      try {
        const next = JSON.parse(event.data || "[]");
        if (!Array.isArray(next)) return;
        state.nodeDeleteEvents = next;
        const recent = next.slice(-10);
        for (const item of recent) {
          const id = String(item?.id || "");
          if (!id || deleteEventSeen.has(id)) continue;
          deleteEventSeen.add(id);
          const nodeId = String(item?.node_id || "");
          const phase = String(item?.phase || "");
          const status = String(item?.status || "");
          const message = String(item?.message || "");
          if (!nodeId) continue;
          setNotice(`[${nodeId}] ${phase}/${status} ${message}`.trim(), status === "failed" ? "error" : "info");
        }
        if (deleteEventSeen.size > 5000) {
          const keep = new Set();
          for (const item of recent) {
            const id = String(item?.id || "");
            if (id) keep.add(id);
          }
          deleteEventSeen.clear();
          for (const id of keep) deleteEventSeen.add(id);
        }
      } catch (_) {
        // ignore parse errors from partial stream frames
      }
    });
    clusterEventSource.onerror = () => {
      stopClusterEventStream();
      // EventSource does not expose the HTTP status code to JavaScript. Check
      // the normal JSON session endpoint so an expired session follows the
      // same /login redirect as every other API request instead of retrying a
      // 401 stream forever.
      if (clusterAuthCheckInFlight) return;
      clusterAuthCheckInFlight = request("/auth/session", { timeoutMs: 3000 })
        .then(() => {
          clusterReconnectTimer = window.setTimeout(() => {
            clusterReconnectTimer = null;
            startClusterEventStream();
          }, 3000);
        })
        .catch((error) => {
          if (error?.code === "AUTH_REQUIRED") return;
          clusterReconnectTimer = window.setTimeout(() => {
            clusterReconnectTimer = null;
            startClusterEventStream();
          }, 5000);
        })
        .finally(() => {
          clusterAuthCheckInFlight = null;
        });
    };
  }

  async function refreshNodes() {
    const response = await request("/nodes").catch(() => ({ nodes: [] }));
    const nodes = Array.isArray(response) ? response : (Array.isArray(response?.nodes) ? response.nodes : []);
    state.nodes = nodes;
    if (!state.nodes.some((item) => item.id === state.nodeId)) {
      state.nodeId = state.nodes[0]?.id || state.nodeId;
    }
    return nodes;
  }

  async function refreshInventory() {
    const inventory = await (state.nodeId
      ? request(`/nodes/${state.nodeId}/interfaces`).catch(() => ({ interfaces: [], recommended: "" }))
      : Promise.resolve({ interfaces: [], recommended: "" }));
    state.inventory = inventory;
    state.interfaces = inventory.interfaces || [];
    state.recommendedInterface = inventory.recommended || state.recommendedInterface;
    return inventory;
  }

  async function refreshPersistedLogs() {
    const persistedLogs = await request("/logs/drop?limit=500").catch(() => ({ logs: [] }));
    state.persistedLogs = persistedLogs.logs || [];
    state.selection.clear();
    return persistedLogs;
  }

  async function refreshManagementSettings() {
    const nodeID = state.nodeId;
    const [loggingSettings, authSettings, usersResp, sshProtection, sshActivity] = await Promise.all([
      request("/settings/logging").catch(() => state.loggingSettings),
      request("/settings/auth").catch(() => state.authSettings),
      request("/auth/users").catch(() => ({ users: [] })),
      nodeID ? request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection`).catch(() => null) : Promise.resolve(null),
      nodeID ? request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/activity?limit=100`).catch(() => null) : Promise.resolve(null),
    ]);
    if (nodeID !== state.nodeId) return;
    state.loggingSettings = { ...state.loggingSettings, ...loggingSettings };
    state.authSettings = { ...state.authSettings, ...authSettings };
    state.users = Array.isArray(usersResp?.users) ? usersResp.users : [];
    state.sshProtection = {
      ...state.sshProtection,
      ...(sshProtection || {}),
      loading: false,
      node_id: nodeID,
      settings: { ...state.sshProtection.settings, ...(sshProtection?.settings || {}) },
      active_blocks: Array.isArray(sshProtection?.active_blocks) ? sshProtection.active_blocks : state.sshProtection.active_blocks,
      ports: Array.isArray(sshProtection?.ports) ? sshProtection.ports : state.sshProtection.ports,
      upload_security: { ...state.sshProtection.upload_security, ...(sshProtection?.upload_security || {}) },
      activity: Array.isArray(sshActivity?.records) ? sshActivity.records : state.sshProtection.activity,
    };
  }

  // SSH protection belongs to the selected Agent. Security-page refreshes
  // must load it explicitly because they do not load the broader management
  // settings endpoint.
  async function refreshSSHProtectionData(nodeID = state.nodeId) {
    if (!nodeID) return;
    const encodedNode = encodeURIComponent(nodeID);
    const [sshProtection, sshActivity] = await Promise.all([
      request(`/nodes/${encodedNode}/ssh-protection`).catch(() => null),
      request(`/nodes/${encodedNode}/ssh-protection/activity?limit=100`).catch(() => null),
    ]);
    if (nodeID !== state.nodeId) return;
    if (sshProtection && typeof sshProtection === "object") {
      state.sshProtection = {
        ...state.sshProtection,
        ...sshProtection,
        loading: false,
        node_id: nodeID,
        settings: { ...state.sshProtection.settings, ...(sshProtection.settings || {}) },
        active_blocks: Array.isArray(sshProtection.active_blocks) ? sshProtection.active_blocks : state.sshProtection.active_blocks,
        ports: Array.isArray(sshProtection.ports) ? sshProtection.ports : state.sshProtection.ports,
        upload_security: { ...state.sshProtection.upload_security, ...(sshProtection.upload_security || {}) },
      };
    }
    if (Array.isArray(sshActivity?.records)) {
      state.sshProtection.activity = sshActivity.records;
    }
    state.sshProtection.loading = false;
  }

  async function refreshSecurityData() {
    if (!state.nodeId) return;
    const nodeID = state.nodeId;
    const node = encodeURIComponent(nodeID);
    const [summary, scan, quarantine] = await Promise.all([
      request(`/nodes/${node}/security/summary`).catch(() => state.securitySummary),
      request(`/nodes/${node}/security/scan`).catch(() => state.securitySummary.scan),
      request(`/nodes/${node}/security/quarantine`).catch(() => state.securityQuarantine),
    ]);
    if (nodeID !== state.nodeId || (summary?.node_id && summary.node_id !== nodeID) || (scan?.node_id && scan.node_id !== nodeID) || (quarantine?.node_id && quarantine.node_id !== nodeID)) return;
    state.securitySummary = {
      ...state.securitySummary,
      ...summary,
      checks: Array.isArray(summary?.checks) ? summary.checks : state.securitySummary.checks,
      scan: scan?.status ? scan : (summary?.scan || state.securitySummary.scan),
    };
    state.securityQuarantine = {
      root: quarantine?.root || "",
      entries: Array.isArray(quarantine?.entries) ? quarantine.entries : [],
      node_id: nodeID,
    };
    if (state.securitySummary.scan?.status === "running") scheduleSecurityScanPoll();
    return state.securitySummary;
  }

  async function refreshOverviewSecurityData() {
    const nodes = (state.nodes || []).filter((item) => item?.id);
    if (!nodes.length) {
      state.securityOverviewNodes = [];
      return [];
    }

    const snapshots = await Promise.all(nodes.map(async (item) => {
      const node = encodeURIComponent(item.id);
      const [summary, scan, ssh, activity] = await Promise.all([
        request(`/nodes/${node}/security/summary`).catch(() => null),
        request(`/nodes/${node}/security/scan`).catch(() => null),
        request(`/nodes/${node}/ssh-protection`).catch(() => null),
        request(`/nodes/${node}/ssh-protection/activity?limit=100`).catch(() => null),
      ]);
      return {
        id: item.id,
        name: item.name || item.id,
        summary: summary || {},
        scan: scan?.status ? scan : (summary?.scan || { status: "idle", findings: [] }),
        ssh: ssh || {},
        activity: Array.isArray(activity?.records) ? activity.records : [],
      };
    }));

    state.securityOverviewNodes = snapshots;
    const current = snapshots.find((item) => item.id === state.nodeId);
    if (current) {
      state.securitySummary = {
        ...state.securitySummary,
        ...current.summary,
        checks: Array.isArray(current.summary?.checks) ? current.summary.checks : state.securitySummary.checks,
        scan: current.scan,
      };
      state.sshProtection = {
        ...state.sshProtection,
        ...current.ssh,
        loading: false,
        node_id: current.id,
        settings: { ...state.sshProtection.settings, ...(current.ssh?.settings || {}) },
        active_blocks: Array.isArray(current.ssh?.active_blocks) ? current.ssh.active_blocks : state.sshProtection.active_blocks,
        ports: Array.isArray(current.ssh?.ports) ? current.ssh.ports : state.sshProtection.ports,
        upload_security: { ...state.sshProtection.upload_security, ...(current.ssh?.upload_security || {}) },
        activity: current.activity,
      };
      if (current.scan?.status === "running") scheduleSecurityScanPoll();
    }
    return snapshots;
  }

  async function refreshSecurityScan() {
    if (!state.nodeId) return;
    const nodeID = state.nodeId;
    const payload = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan`, { timeoutMs: 12000 });
    if (nodeID !== state.nodeId || (payload?.node_id && payload.node_id !== nodeID)) return;
    state.securitySummary.scan = payload;
    if (payload?.status === "running") scheduleSecurityScanPoll();
    return payload;
  }

  function scheduleSecurityScanPoll() {
    if (securityScanTimer || typeof window === "undefined") return;
    securityScanTimer = window.setTimeout(async () => {
      securityScanTimer = null;
      try {
        await refreshSecurityScan();
      } catch (error) {
        handleError(error);
      }
    }, 1500);
  }

  async function startSecurityScan(path, autoQuarantine = false, autoTerminateProcesses = false) {
    const root = String(path || "").trim();
    if (!root) throw new Error("请输入扫描路径");
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan`, {
      method: "POST",
      timeoutMs: 12000,
      body: JSON.stringify({
        path: root,
        auto_quarantine: Boolean(autoQuarantine),
        auto_terminate_processes: Boolean(autoTerminateProcesses),
      }),
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    state.securitySummary.scan = response;
    scheduleSecurityScanPoll();
    return response;
  }

  async function quarantineSecurityFinding(findingID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/${encodeURIComponent(findingID)}/quarantine`, {
      method: "POST",
      timeoutMs: 12000,
      body: JSON.stringify({ confirm: "QUARANTINE" }),
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.scan) state.securitySummary.scan = response.scan;
    setNotice("文件已隔离", "success");
    await refreshSecurityQuarantine();
    return response;
  }

  async function terminateSecurityProcess(findingID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/${encodeURIComponent(findingID)}/terminate`, {
      method: "POST",
      timeoutMs: 12000,
      body: JSON.stringify({ confirm: "TERMINATE_PROCESS" }),
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.scan) state.securitySummary.scan = response.scan;
    setNotice("进程查杀请求已发送", "success");
    return response;
  }

  async function refreshSecurityQuarantine() {
    if (!state.nodeId) return state.securityQuarantine;
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine`);
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return state.securityQuarantine;
    state.securityQuarantine = {
      root: response?.root || "",
      entries: Array.isArray(response?.entries) ? response.entries : [],
      node_id: nodeID,
    };
    return state.securityQuarantine;
  }

  async function deleteSecurityQuarantine(entryID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine/${encodeURIComponent(entryID)}`, {
      method: "DELETE",
      body: JSON.stringify({ confirm: "DELETE_QUARANTINE" }),
    });
    if (nodeID !== state.nodeId) return response;
    await refreshSecurityQuarantine();
    setNotice(t("securityQuarantineDeleted"), "success");
    return response;
  }

  async function restoreSecurityQuarantine(entryID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine/${encodeURIComponent(entryID)}/restore`, {
      method: "POST",
      timeoutMs: 12000,
      body: JSON.stringify({ confirm: "RESTORE_QUARANTINE" }),
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    await refreshSecurityQuarantine();
    setNotice(t("securityQuarantineRestored"), "success");
    return response;
  }

  async function downloadSecurityScanReport(format = "html", reportID = "") {
    const node = encodeURIComponent(state.nodeId || "");
    const selectedFormat = format === "json" ? "json" : "html";
    const endpoint = reportID ? `reports/${encodeURIComponent(reportID)}` : "report";
    const result = await downloadFile(`/nodes/${node}/security/scan/${endpoint}?format=${selectedFormat}`);
    const href = URL.createObjectURL(result.blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = result.filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.setTimeout(() => URL.revokeObjectURL(href), 1000);
    setNotice(t("securityReportDownloaded"), "success");
    return result;
  }

  async function refreshAll() {
    const nodes = await refreshNodes();
    await Promise.all([refreshInventory(), refreshPersistedLogs(), refreshManagementSettings()]);
    const [inventory, loggingSettings, persistedLogs, authSettings, usersResp] = await Promise.all([
      Promise.resolve(state.inventory),
      Promise.resolve(state.loggingSettings),
      Promise.resolve({ logs: state.persistedLogs }),
      Promise.resolve(state.authSettings),
      Promise.resolve({ users: state.users }),
    ]);
    state.inventory = inventory;
    state.interfaces = inventory.interfaces || [];
    state.recommendedInterface = inventory.recommended || state.recommendedInterface;
    state.loggingSettings = { ...state.loggingSettings, ...loggingSettings };
    state.persistedLogs = persistedLogs.logs || [];
    state.authSettings = { ...state.authSettings, ...authSettings };
    state.users = Array.isArray(usersResp?.users) ? usersResp.users : [];
    state.selection.clear();
    await refreshClusterAggregate({ force: true });
    if (state.section === "overview") await refreshOverviewSecurityData();

    const preferred = pickPreferredInterface();
    const selectedExists = (state.interfaces || []).some((item) => item.name === state.selectedInterface);
    if ((!state.selectedInterface || !selectedExists) && preferred) {
      state.selectedInterface = preferred;
    }
    await queueRefreshCurrent();
    state.error = "";
    return nodes;
  }

  async function refreshSectionData(section = state.section, options = {}) {
    const target = section || "overview";
    const fromStream = !!options.fromStream;
    if (target === "cluster") {
      await refreshNodes();
      return;
    }
    if (target === "monitoring") {
      await refreshNodes();
      return;
    }
    if (target === "management") {
      await Promise.all([refreshNodes(), refreshManagementSettings()]);
      return;
    }
    if (target === "ssh") {
      await Promise.all([refreshNodes(), refreshManagementSettings()]);
      return;
    }
    if (target === "ssh-console") {
      await Promise.all([refreshNodes(), refreshManagementSettings()]);
      return;
    }
    if (target === "security" || target === "malware") {
      await Promise.all([
        refreshNodes(),
        refreshInventory(),
        refreshSecurityData(),
        target === "security" ? refreshSSHProtectionData() : Promise.resolve(),
        queueRefreshCurrentLight(),
        refreshPersistedLogs(),
      ]);
      return;
    }
    if (target === "events") {
      await Promise.all([refreshNodes(), refreshInventory(), refreshPersistedLogs(), refreshManagementSettings(), refreshSecurityData()]);
      return;
    }
    if (target === "logs") {
      await Promise.all([refreshNodes(), refreshInventory(), refreshPersistedLogs(), queueRefreshCurrentLight(), refreshLogPanels()]);
      return;
    }
    if (target === "policy") {
      await Promise.all([refreshNodes(), refreshInventory(), queueRefreshCurrentLight()]);
      return;
    }
    // overview
    await refreshNodes();
    await Promise.all([
      refreshInventory(),
      queueRefreshCurrent(),
      refreshClusterAggregate(),
      refreshOverviewSecurityData(),
      fromStream ? Promise.resolve() : refreshPersistedLogs(),
    ]);
  }

  async function queueSectionRefresh(section = state.section, options = {}) {
    sectionRefreshQueued = { section, options };
    if (sectionRefreshInFlight) return sectionRefreshInFlight;
    sectionRefreshInFlight = (async () => {
      while (sectionRefreshQueued) {
        const current = sectionRefreshQueued;
        sectionRefreshQueued = null;
        await refreshSectionData(current.section, current.options);
      }
    })();
    try {
      return await sectionRefreshInFlight;
    } finally {
      sectionRefreshInFlight = null;
    }
  }

  async function refreshAfterWrite(scope = "current") {
    if (scope === "cluster") {
      await refreshNodes();
      return;
    }
    if (scope === "policy") {
      // Keep policy interactions snappy: only refresh the currently focused
      // interface summary instead of reloading nodes/inventory each click.
      await queueRefreshCurrentLight();
      return;
    }
    if (scope === "logs") {
      await Promise.all([refreshNodes(), refreshInventory(), refreshPersistedLogs(), queueRefreshCurrentLight(), refreshLogPanels()]);
      return;
    }
    if (scope === "management") {
      await Promise.all([refreshNodes(), refreshManagementSettings()]);
      return;
    }
    await refreshSectionData(state.section);
  }

  async function refreshClusterAggregate(options = {}) {
    const force = !!options.force;
    const now = Date.now();
    if (!force && clusterAggregateInFlight) return clusterAggregateInFlight;
    if (!force && now - clusterAggregateLastAt < CLUSTER_AGGREGATE_TTL_MS) return state.clusterAggregate;
    clusterAggregateInFlight = (async () => {
      const direction = state.direction === "egress" ? "egress" : "ingress";
      const payload = await request(withDirection("/cluster/aggregate", direction)).catch(() => ({}));
      state.clusterAggregate = {
        passed: Number(payload?.passed || 0),
        dropped: Number(payload?.dropped || 0),
        recent_passed: Number(payload?.recent_passed || 0),
        recent_dropped: Number(payload?.recent_dropped || 0),
        passed_pps: Number(payload?.passed_pps || 0),
        dropped_pps: Number(payload?.dropped_pps || 0),
        drop_rate: Number(payload?.drop_rate || 0),
        window_seconds: Number(payload?.window_seconds || 300),
        trusted: Number(payload?.trusted || 0),
        pendingRelease: Number(payload?.pendingRelease || 0),
        nodes: Array.isArray(payload?.nodes) ? payload.nodes : [],
        top_attackers: Array.isArray(payload?.top_attackers) ? payload.top_attackers : [],
        top_countries: Array.isArray(payload?.top_countries) ? payload.top_countries : [],
        top_ports: Array.isArray(payload?.top_ports) ? payload.top_ports : [],
        top_passed: Array.isArray(payload?.top_passed) ? payload.top_passed : [],
        trend: Array.isArray(payload?.trend) ? payload.trend : [],
        system: payload?.system && typeof payload.system === "object" ? payload.system : {
          node_count: 0,
          sampled_nodes: 0,
          average_cpu_percent: 0,
          average_memory_percent: 0,
          rx_bytes_per_second: 0,
          tx_bytes_per_second: 0,
        },
      };
      clusterAggregateLastAt = Date.now();
    })();
    try {
      return await clusterAggregateInFlight;
    } finally {
      clusterAggregateInFlight = null;
    }
  }

  async function refreshLogPanels() {
    if (!state.nodeId || !currentInterface.value) return;
    const iface = requireInterfaceEncoded();
    const [interfaceLogs, temporaryBlocks, rateLimits] = await Promise.all([
      request(withDirection(`/nodes/${state.nodeId}/interfaces/${iface}/drop-logs`, state.direction)).catch(() => ({ logs: [] })),
      request(withDirection(`/nodes/${state.nodeId}/interfaces/${iface}/temporary-blocks`, state.direction)).catch(() => ({ temporary_blocks: [] })),
      request(withDirection(`/nodes/${state.nodeId}/interfaces/${iface}/rate-limits`, state.direction)).catch(() => ({ rate_limits: [] })),
    ]);
    state.interfaceLogs = Array.isArray(interfaceLogs?.logs) ? interfaceLogs.logs : [];
    state.temporaryBlocks = Array.isArray(temporaryBlocks?.temporary_blocks) ? temporaryBlocks.temporary_blocks : [];
    state.rateLimits = Array.isArray(rateLimits?.rate_limits) ? rateLimits.rate_limits : [];
  }

  async function refreshData() {
    await withBusy("refresh", async () => {
      await queueSectionRefresh(state.section);
      setNotice(t("noticeRefreshDone"), "info");
    });
  }

  function pickPreferredInterface() {
    const list = (state.interfaces || []).filter((item) => item?.is_physical) || [];
    const base = list.length ? list : (state.interfaces || []);
    const scored = [...base].sort((a, b) => {
      const scoreA = Number(a.last_passed || 0) + Number(a.last_dropped || 0);
      const scoreB = Number(b.last_passed || 0) + Number(b.last_dropped || 0);
      return scoreB - scoreA;
    });
    return scored.find((item) => (item.last_passed || item.last_dropped))?.name || state.recommendedInterface || state.defaultInterface || base[0]?.name || "";
  }

  function applyInterfaceSummary(summary, autoSwitchDirection = true) {
    const nextPolicy = summary?.policy || {};
    const selectedDirectionPolicy = nextPolicy?.[state.direction] || {};
    const policyAllowlist = Array.isArray(selectedDirectionPolicy?.rules)
      ? selectedDirectionPolicy.rules.map((item) => item?.cidr).filter(Boolean)
      : [];

    const nextBypass = cloneArray(summary?.bypass);
    const nextBlocked = cloneArray(summary?.blocked);
    const nextICMPAllow = cloneArray(summary?.icmp_allow);
    const nextICMPBlocked = cloneArray(summary?.icmp_blocked);
    const nextAllowlist = cloneArray(summary?.allowlist);
    const nextPublicPorts = cloneArray(summary?.public_ports);
    const nextDeniedPorts = cloneArray(summary?.denied_ports);
    const nextAllowedPorts = cloneArray(summary?.ports);
    const nextPublicRules = normalizePortRules(summary, "public_port_rules", "public_ports");
    const nextDeniedRules = normalizePortRules(summary, "denied_port_rules", "denied_ports");
    const nextAllowedRules = normalizePortRules(summary, "allowed_port_rules", "ports");

    const selectedTotal =
      policyAllowlist.length +
      Number((selectedDirectionPolicy?.bypass_cidrs || []).length) +
      Number((selectedDirectionPolicy?.blocked_cidrs || []).length) +
      Number((selectedDirectionPolicy?.icmp_allow_cidrs || []).length) +
      Number((selectedDirectionPolicy?.icmp_blocked_cidrs || []).length) +
      Number((selectedDirectionPolicy?.public_port_rules || []).length) +
      Number((selectedDirectionPolicy?.denied_port_rules || []).length) +
      Number((selectedDirectionPolicy?.allowed_port_rules || []).length);
    const altDirection = state.direction === "ingress" ? "egress" : "ingress";
    const altDirectionPolicy = nextPolicy?.[altDirection] || {};
    const altTotal =
      Number((altDirectionPolicy?.rules || []).length) +
      Number((altDirectionPolicy?.bypass_cidrs || []).length) +
      Number((altDirectionPolicy?.blocked_cidrs || []).length) +
      Number((altDirectionPolicy?.icmp_allow_cidrs || []).length) +
      Number((altDirectionPolicy?.icmp_blocked_cidrs || []).length) +
      Number((altDirectionPolicy?.public_port_rules || []).length) +
      Number((altDirectionPolicy?.denied_port_rules || []).length) +
      Number((altDirectionPolicy?.allowed_port_rules || []).length);
    if (autoSwitchDirection && selectedTotal === 0 && altTotal > 0) {
      state.direction = altDirection;
      return false;
    }

    state.policy = nextPolicy;
    state.protectionTrial = summary?.protection_trial || null;
    state.health = summary?.health || { interfaces: [] };
    state.stats = summary?.stats || { passed: 0, dropped: 0 };
    state.recentStats = summary?.recent_stats || {
      window_seconds: 300,
      recent_passed: 0,
      recent_dropped: 0,
      passed_pps: 0,
      dropped_pps: 0,
      drop_rate: 0,
    };
    state.insights = summary?.insights || state.insights;
    state.bypassCIDRs = cloneArray(selectedDirectionPolicy?.bypass_cidrs);
    state.blockedCIDRs = cloneArray(selectedDirectionPolicy?.blocked_cidrs);
    state.icmpAllowCIDRs = cloneArray(selectedDirectionPolicy?.icmp_allow_cidrs);
    state.icmpBlockedCIDRs = cloneArray(selectedDirectionPolicy?.icmp_blocked_cidrs);
    state.allowlist = policyAllowlist;
    state.publicPorts = cloneArray(selectedDirectionPolicy?.public_ports);
    state.deniedPorts = cloneArray(selectedDirectionPolicy?.denied_ports);
    state.allowedPorts = cloneArray(selectedDirectionPolicy?.allowed_ports);
    state.publicPortRules = normalizePortRules(selectedDirectionPolicy, "public_port_rules", "public_ports");
    state.deniedPortRules = normalizePortRules(selectedDirectionPolicy, "denied_port_rules", "denied_ports");
    state.allowedPortRules = normalizePortRules(selectedDirectionPolicy, "allowed_port_rules", "allowed_ports");
    state.interfaceLogs = Array.isArray(summary?.interface_logs) ? summary.interface_logs : [];
    state.temporaryBlocks = Array.isArray(summary?.temporary_blocks) ? summary.temporary_blocks : [];
    state.rateLimits = Array.isArray(summary?.rate_limits) ? summary.rate_limits : [];
    state.forms.nonIPv4 = nextPolicy?.[state.direction]?.non_ipv4_action || nextPolicy?.non_ipv4_action || "drop";
    state.error = "";
    return true;
  }

  async function refreshCurrent(autoSwitchDirection = true) {
    if (!state.nodeId) return;
    if (!currentInterface.value) return;
    const token = ++refreshCurrentToken;
    const iface = requireInterfaceEncoded();
    const currentNodeId = state.nodeId;
    const currentDirection = state.direction;
    const summary = await request(withDirection(`/nodes/${state.nodeId}/interfaces/${iface}/summary`, currentDirection), {
      key: `summary:${currentNodeId}|iface:${iface}|dir:${currentDirection}`,
    }).catch(() => null);
    if (token !== refreshCurrentToken || !summary) return;
    const applied = applyInterfaceSummary(summary, autoSwitchDirection);
    if (!applied && autoSwitchDirection) {
      await refreshCurrent(false);
    }
  }

  async function queueRefreshCurrent(autoSwitchDirection = true) {
    if (refreshCurrentInFlight) {
      refreshCurrentQueued = true;
      refreshCurrentQueuedAutoSwitch = refreshCurrentQueuedAutoSwitch === null
        ? autoSwitchDirection
        : refreshCurrentQueuedAutoSwitch && autoSwitchDirection;
      return refreshCurrentInFlight;
    }
    refreshCurrentInFlight = (async () => {
      do {
        const queuedAutoSwitch = refreshCurrentQueuedAutoSwitch;
        refreshCurrentQueued = false;
        refreshCurrentQueuedAutoSwitch = null;
        await refreshCurrent(queuedAutoSwitch === null ? autoSwitchDirection : queuedAutoSwitch);
      } while (refreshCurrentQueued);
    })();
    try {
      return await refreshCurrentInFlight;
    } finally {
      refreshCurrentInFlight = null;
    }
  }

  async function refreshCurrentLight(autoSwitchDirection = true) {
    await refreshCurrent(autoSwitchDirection);
  }

  async function queueRefreshCurrentLight(autoSwitchDirection = true) {
    if (refreshCurrentInFlight) {
      refreshCurrentQueued = true;
      refreshCurrentQueuedAutoSwitch = refreshCurrentQueuedAutoSwitch === null
        ? autoSwitchDirection
        : refreshCurrentQueuedAutoSwitch && autoSwitchDirection;
      return refreshCurrentInFlight;
    }
    refreshCurrentInFlight = (async () => {
      do {
        const queuedAutoSwitch = refreshCurrentQueuedAutoSwitch;
        refreshCurrentQueued = false;
        refreshCurrentQueuedAutoSwitch = null;
        await refreshCurrentLight(queuedAutoSwitch === null ? autoSwitchDirection : queuedAutoSwitch);
      } while (refreshCurrentQueued);
    })();
    try {
      return await refreshCurrentInFlight;
    } finally {
      refreshCurrentInFlight = null;
    }
  }

  async function mutate(path, method, body) {
    await requestWithSSHConfirmation(path, {
      method,
      body: JSON.stringify(body || {}),
    });
    await refreshAfterWrite("current");
  }

  async function requestWithSSHConfirmation(path, options = {}) {
    try {
      return await request(path, options);
    } catch (error) {
      if (error?.code !== "SSH_CONFIRM_REQUIRED") throw error;
      return new Promise((resolve, reject) => {
        openModal({
          title: "确认 SSH 管理端口变更",
          copy: `检测到该操作会影响 sshd 端口 ${error.payload?.port || error.payload?.ports?.join(", ") || "22"}。请输入当前控制台密码，确认后才会立即生效。`,
          fields: [{ key: "confirm_password", label: "当前密码", type: "password" }],
          onConfirm: async (values) => {
            try {
              const nextOptions = { ...options };
              nextOptions.headers = { ...(options.headers || {}), "X-Nodewall-Confirm-Password": values.confirm_password || "" };
              if (String(options.method || "GET").toUpperCase() === "DELETE") {
                nextOptions.body = undefined;
                nextOptions.method = "DELETE";
                resolve(await request(path, nextOptions));
                return;
              }
              let body = {};
              try { body = options.body ? JSON.parse(options.body) : {}; } catch { body = {}; }
              body.confirm_password = values.confirm_password || "";
              nextOptions.body = JSON.stringify(body);
              resolve(await request(path, nextOptions));
            } catch (retryError) {
              reject(retryError);
              throw retryError;
            }
          },
        });
      });
    }
  }

  async function addCIDR(kind, value, options = {}) {
    const trimmed = String(value || "").trim();
    if (!trimmed) return;
    const iface = requireInterfaceEncoded();
    const pathMap = {
      allowlist: `/nodes/${state.nodeId}/interfaces/${iface}/allowlist`,
      bypass: `/nodes/${state.nodeId}/interfaces/${iface}/bypass`,
      blocked: `/nodes/${state.nodeId}/interfaces/${iface}/block`,
      icmpAllow: `/nodes/${state.nodeId}/interfaces/${iface}/icmp-allowlist`,
      icmpBlocked: `/nodes/${state.nodeId}/interfaces/${iface}/icmp-blocklist`,
    };
    const body = { cidr: trimmed };
    if (kind === "allowlist") {
      const comment = String(options?.comment || "").trim();
      if (comment) body.comment = comment;
    }
    await mutate(withDirection(pathMap[kind], state.direction), "POST", body);
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function addPort(kind, value, protocol = "") {
    const port = Number(value || 0);
    if (!port && String(protocol || "").toLowerCase() !== "icmp") return;
    const iface = requireInterfaceEncoded();
    const pathMap = {
      public: `/nodes/${state.nodeId}/interfaces/${iface}/public-ports`,
      denied: `/nodes/${state.nodeId}/interfaces/${iface}/denied-ports`,
      allowed: `/nodes/${state.nodeId}/interfaces/${iface}/ports`,
    };
    const normalizedProtocol = protocol === "both" ? "" : protocol;
    const payload = {
      port: String(protocol || "").toLowerCase() === "icmp" ? 0 : port,
      protocol: normalizedProtocol || undefined,
    };
    await mutate(withDirection(pathMap[kind], state.direction), "POST", payload);
    // Do not auto-create opposite-direction policy entries in UI flow.
    // Reply allowance should be handled by dataplane/runtime logic.
  }

  async function saveRuleDescription({ kind, value, protocol = "", description = "" } = {}) {
    const iface = requireInterfaceEncoded();
    const endpoint = `/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/rule-description`;
    const protocols = String(protocol).toLowerCase() === "both" ? ["tcp", "udp"] : [String(protocol).toLowerCase()];
    for (const nextProtocol of protocols) {
      const response = await request(withDirection(endpoint, state.direction), {
        method: "PUT",
        body: JSON.stringify({ kind, value: String(value ?? ""), protocol: nextProtocol, description }),
      });
      if (response) state.policy = response;
    }
    await refreshAfterWrite("policy");
  }

  async function saveIPv6Action(action) {
    const nextAction = action === "pass" ? "pass" : "drop";
    const current = state.policy || {};
    const draft = {
      node_id: state.nodeId,
      interface: currentInterface.value,
      ingress: normalizeDirectionPolicyDraft(current.ingress || current, current.non_ipv4_action),
      egress: normalizeDirectionPolicyDraft(current.egress, current.non_ipv4_action),
    };
    const selected = draft[state.direction] || draft.ingress;
    selected.non_ipv4_action = nextAction;
    const iface = requireInterfaceEncoded();
    try {
      const updated = await requestWithSSHConfirmation(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/policy`, {
        method: "PUT",
        body: JSON.stringify({ policy: draft }),
      });
      if (updated) state.policy = updated;
      await refreshAfterWrite("policy");
      setNotice(t("noticeRefreshDone"), "success");
    } catch (error) {
      state.forms.nonIPv4 = current?.[state.direction]?.non_ipv4_action || current?.non_ipv4_action || "drop";
      throw error;
    }
  }

  async function removeCIDR(kind, value) {
    const iface = requireInterfaceEncoded();
    const pathMap = {
      allowlist: `/nodes/${state.nodeId}/interfaces/${iface}/allowlist`,
      bypass: `/nodes/${state.nodeId}/interfaces/${iface}/bypass`,
      blocked: `/nodes/${state.nodeId}/interfaces/${iface}/block`,
      icmpAllow: `/nodes/${state.nodeId}/interfaces/${iface}/icmp-allowlist`,
      icmpBlocked: `/nodes/${state.nodeId}/interfaces/${iface}/icmp-blocklist`,
    };
    const separator = pathMap[kind].includes("?") ? "&" : "?";
    const path = `${pathMap[kind]}${separator}cidr=${encodeURIComponent(value || "")}`;
    await requestWithSSHConfirmation(withDirection(path, state.direction), { method: "DELETE" });
    await refreshAfterWrite("policy");
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function removePort(kind, value, protocol = "") {
    const iface = requireInterfaceEncoded();
    const pathMap = {
      public: `/nodes/${state.nodeId}/interfaces/${iface}/public-ports/${value}`,
      denied: `/nodes/${state.nodeId}/interfaces/${iface}/denied-ports/${value}`,
      allowed: `/nodes/${state.nodeId}/interfaces/${iface}/ports/${value}`,
    };
    const path = protocol ? `${pathMap[kind]}?protocol=${encodeURIComponent(protocol)}` : pathMap[kind];
    await requestWithSSHConfirmation(withDirection(path, state.direction), { method: "DELETE" });
    await refreshAfterWrite("policy");
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function changeRuleStrategy(row, nextStrategy) {
    const target = nextStrategy === "deny" ? "deny" : "allow";
    const currentKind = String(row?.kind || "");
    if (!currentKind || currentKind === "bypass") return;

    const iface = requireInterfaceEncoded();
    const current = state.policy || {};
    const draft = {
      node_id: state.nodeId,
      interface: currentInterface.value,
      ingress: normalizeDirectionPolicyDraft(current.ingress || current, current.non_ipv4_action),
      egress: normalizeDirectionPolicyDraft(current.egress, current.non_ipv4_action),
    };
    const selected = draft[state.direction] || draft.ingress;
    const cidr = String(row?.value || "");

    if (currentKind === "allowlist" || currentKind === "blocked") {
      selected.rules = (selected.rules || []).filter((item) => String(item?.cidr || "") !== cidr);
      selected.blocked_cidrs = (selected.blocked_cidrs || []).filter((item) => String(item) !== cidr);
      if (target === "allow") {
        selected.rules.push({ cidr, action: "allow" });
      } else {
        selected.blocked_cidrs.push(cidr);
      }
    } else if (currentKind === "icmpAllow" || currentKind === "icmpBlocked") {
      selected.icmp_allow_cidrs = (selected.icmp_allow_cidrs || []).filter((item) => String(item) !== cidr);
      selected.icmp_blocked_cidrs = (selected.icmp_blocked_cidrs || []).filter((item) => String(item) !== cidr);
      if (target === "allow") {
        selected.icmp_allow_cidrs.push(cidr);
      } else {
        selected.icmp_blocked_cidrs.push(cidr);
      }
    } else if (currentKind === "public" || currentKind === "allowed" || currentKind === "denied") {
      const port = Number(row?.value || 0);
      const protocol = String(row?.portProtocol || "tcp").toLowerCase();
      const ruleSets = [
        ["public_port_rules", "public_ports"],
        ["allowed_port_rules", "allowed_ports"],
        ["denied_port_rules", "denied_ports"],
      ];
      for (const [rulesKey, portsKey] of ruleSets) {
        const rules = normalizedPortRuleDraft(selected[rulesKey], selected[portsKey]);
        selected[rulesKey] = rules.filter((item) => item.port !== port || item.protocol !== protocol);
      }
      const targetRulesKey = target === "deny" ? "denied_port_rules" : "public_port_rules";
      selected[targetRulesKey].push({ protocol, port });
      for (const [rulesKey, portsKey] of ruleSets) {
        selected[portsKey] = collapsePortRuleDraft(selected[rulesKey]);
      }
    } else {
      return;
    }

    const updated = await requestWithSSHConfirmation(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/policy`, {
      method: "PUT",
      body: JSON.stringify({ policy: draft }),
    });
    if (updated) state.policy = updated;
    await refreshAfterWrite("policy");
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function attachCurrent() {
    await withBusy("attach", async () => {
      const iface = requireInterfaceEncoded();
      const ifaceName = currentInterface.value || "-";
      let mode = "native";
      try {
        await request(`/nodes/${state.nodeId}/interfaces/${iface}/attach`, {
          method: "POST",
          body: JSON.stringify({ mode }),
        });
      } catch {
        mode = "generic";
        await request(`/nodes/${state.nodeId}/interfaces/${iface}/attach`, {
          method: "POST",
          body: JSON.stringify({ mode }),
        });
      }
      try {
        await refreshAfterWrite("policy");
        const attachedMode = String(currentInterfaceRecord.value?.attach_mode || mode).toUpperCase();
        setNotice(t("noticeAttachSuccess", { iface: ifaceName, mode: attachedMode }), "success");
      } catch (error) {
        setNotice(`${t("noticeAttachFailed", { iface: ifaceName })}: ${error?.message || error}`, "info");
        throw error;
      }
    });
  }

  async function detachCurrent() {
    await withBusy("detach", async () => {
      const iface = requireInterfaceEncoded();
      const ifaceName = currentInterface.value || "-";
      try {
        await request(`/nodes/${state.nodeId}/interfaces/${iface}/detach`, {
          method: "POST",
          body: JSON.stringify({}),
        });
        await refreshAfterWrite("policy");
        setNotice(t("noticeDetachSuccess", { iface: ifaceName }), "success");
      } catch (error) {
        setNotice(`${t("noticeDetachFailed", { iface: ifaceName })}: ${error?.message || error}`, "info");
        throw error;
      }
    });
  }

  async function enableProtectionBaseline() {
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      if (response?.policy) state.policy = response.policy;
      state.protectionTrial = null;
      await Promise.all([
        refreshAfterWrite("policy"),
        refreshClusterAggregate({ force: true }),
      ]);
      setNotice(t("protectionBaselineEnabled"), "success");
      return response;
    });
  }

  async function trialProtectionBaseline(seconds = 30) {
    const trialSeconds = Math.max(1, Math.min(120, Number(seconds) || 30));
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline`, {
        method: "POST",
        body: JSON.stringify({ trial_seconds: trialSeconds }),
      });
      if (response?.policy) state.policy = response.policy;
      state.protectionTrial = response?.trial || null;
      await Promise.all([
        refreshAfterWrite("policy"),
        refreshClusterAggregate({ force: true }),
      ]);
      setNotice(t("protectionTrialStarted"), "success");
      if (typeof window !== "undefined") {
        window.setTimeout(() => refreshAfterWrite("policy").catch(() => {}), (trialSeconds + 1) * 1000);
      }
      return response;
    });
  }

  async function confirmProtectionTrial() {
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline/confirm`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      if (response?.policy) state.policy = response.policy;
      state.protectionTrial = null;
      await Promise.all([
        refreshAfterWrite("policy"),
        refreshClusterAggregate({ force: true }),
      ]);
      setNotice(t("protectionTrialConfirmed"), "success");
      return response;
    });
  }

  async function rollbackProtectionTrial() {
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline/rollback`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      state.protectionTrial = null;
      await Promise.all([
        refreshAfterWrite("policy"),
        refreshClusterAggregate({ force: true }),
      ]);
      setNotice(t("protectionTrialRolledBack"), "success");
    });
  }

  async function runLogAction(type, item, payload = {}) {
    const sourceIP = normalizeIPv4(item.source_ip);
    if (!sourceIP) {
      throw new Error(t("requestErrorInvalidSourceIP"));
    }
    await requestWithSSHConfirmation(`/logs/actions/${type}`, {
      method: "POST",
      body: JSON.stringify({
        node_id: state.nodeId,
        interface: item.interface,
        direction: item.direction || "ingress",
        source_ip: sourceIP,
        port: item.port || 0,
        ...payload,
      }),
    });
    await refreshAfterWrite("logs");
  }

  function toggleLogSelection(item) {
    const key = logKey(item);
    if (state.selection.has(key)) {
      state.selection.delete(key);
      return;
    }
    state.selection.add(key);
  }

  function clearSelection() {
    state.selection.clear();
  }

  async function saveLoggingSettings() {
    await mutate("/settings/logging", "PUT", state.loggingSettings);
  }

  async function saveAuthSettings() {
    await mutate("/settings/auth", "PUT", state.authSettings);
  }

  async function saveSSHProtectionSettings() {
    const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection`, {
      method: "PUT",
      body: JSON.stringify(state.sshProtection.settings),
    });
    state.sshProtection = {
      ...state.sshProtection,
      ...response,
      settings: { ...state.sshProtection.settings, ...(response?.settings || {}) },
    };
    await refreshAfterWrite("management");
    setNotice(t("sshProtectionSaved"), "success");
  }

  async function saveSSHTransferPolicy(currentPassword) {
    const transfer = { ...state.sshProtection.settings.transfer };
    const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection/transfer`, {
      method: "PUT",
      body: JSON.stringify({ ...transfer, current_password: currentPassword }),
    });
    state.sshProtection = {
      ...state.sshProtection,
      ...response,
      settings: { ...state.sshProtection.settings, ...(response?.settings || {}) },
    };
    await refreshAfterWrite("management");
    setNotice(t("sshTransferPolicySaved"), "success");
  }

  async function refreshSSHActivity() {
    if (!state.nodeId) return [];
    const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection/activity?limit=100`);
    state.sshProtection.activity = Array.isArray(response?.records) ? response.records : [];
    return state.sshProtection.activity;
  }

  async function createSSHIntegrityBaseline(currentPassword) {
    const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection/integrity/baseline`, {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword }),
    });
    if (response?.integrity) {
      state.sshProtection.integrity = { ...state.sshProtection.integrity, ...response.integrity };
    }
    setNotice(t("sshIntegrityBaselineSaved"), "success");
  }

  async function verifySSHIntegrity() {
    const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection/integrity/verify`, {
      method: "POST",
    });
    if (response?.integrity) {
      state.sshProtection.integrity = { ...state.sshProtection.integrity, ...response.integrity };
    }
    setNotice(t("sshIntegrityChecked"), "success");
    return response;
  }

  async function releaseSSHProtectionBlock(id) {
    await request(`/nodes/${encodeURIComponent(state.nodeId)}/ssh-protection/blocks/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    await refreshAfterWrite("management");
    setNotice(t("sshProtectionReleased"), "info");
  }

  async function changePassword() {
    await request("/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: state.forms.currentPassword,
        new_password: state.forms.newPassword,
      }),
    });
    state.forms.currentPassword = "";
    state.forms.newPassword = "";
  }

  async function createUser() {
    await request("/auth/users", {
      method: "POST",
      body: JSON.stringify({
        username: state.forms.createUsername,
        password: state.forms.createPassword,
        role: state.forms.createRole || "viewer",
      }),
    });
    state.forms.createUsername = "";
    state.forms.createPassword = "";
    state.forms.createRole = "viewer";
    await refreshAfterWrite("management");
    setNotice(t("noticeUserCreated"), "success");
  }

  async function updateUserRole(username, role) {
    await request(`/auth/users/${encodeURIComponent(username)}`, {
      method: "PUT",
      body: JSON.stringify({ role }),
    });
    await refreshAfterWrite("management");
    setNotice(t("noticeUserUpdated"), "success");
  }

  async function updateUserEnabled(username, enabled) {
    await request(`/auth/users/${encodeURIComponent(username)}`, {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    });
    await refreshAfterWrite("management");
    setNotice(t("noticeUserUpdated"), "success");
  }

  async function resetUserPassword(username) {
    if (!state.forms.resetPassword) return;
    await request(`/auth/users/${encodeURIComponent(username)}/password`, {
      method: "PUT",
      body: JSON.stringify({ new_password: state.forms.resetPassword }),
    });
    state.forms.resetPassword = "";
    setNotice(t("noticeUserPasswordReset"), "success");
  }

  async function deleteUser(username) {
    await request(`/auth/users/${encodeURIComponent(username)}`, {
      method: "DELETE",
    });
    await refreshAfterWrite("management");
    setNotice(t("noticeUserDeleted"), "info");
  }

  async function clearPersistedLogs() {
    await request("/logs/drop", {
      method: "DELETE",
      body: JSON.stringify({}),
    });
    await refreshAfterWrite("logs");
  }

  function confirmClearPersistedLogs() {
    openModal({
      title: t("clearLogsTitle"),
      copy: t("clearLogsCopy"),
      onConfirm: async () => {
        await clearPersistedLogs();
        setNotice(t("logsCleared"), "success");
      },
    });
  }

  async function upsertNode(nodeInput) {
    const payload = {
      id: String(nodeInput?.id || "").trim(),
      name: String(nodeInput?.name || "").trim(),
      agent_url: String(nodeInput?.agent_url || "").trim(),
    };
    if (!payload.id || !payload.agent_url) {
      throw new Error(t("clusterFormRequired"));
    }
    await request("/nodes", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    await refreshAfterWrite("cluster");
    state.nodeId = payload.id;
    setNotice(t("clusterSaved"), "success");
  }

  async function renameNode(nodeID, name) {
    const id = String(nodeID || "").trim();
    const nextName = String(name || "").trim();
    const current = (state.nodes || []).find((item) => item.id === id);
    if (!id || !nextName) throw new Error(t("clusterRenameRequired"));
    if (!current?.agent_url) throw new Error(t("clusterFormRequired"));
    await request(`/nodes/${encodeURIComponent(id)}/name`, {
      method: "PUT",
      body: JSON.stringify({ name: nextName }),
    });
    state.nodes = state.nodes.map((item) => item.id === id ? { ...item, name: nextName } : item);
    setNotice(t("clusterRenamed"), "success");
  }

  async function saveSSHConnection(nodeID, profile) {
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-connection`, {
      method: "PUT",
      body: JSON.stringify({
        host: String(profile?.host || "").trim(),
        port: Number(profile?.port || 22),
        user: String(profile?.user || "root").trim(),
      }),
    });
    state.nodes = state.nodes.map((node) => node.id === nodeID ? { ...node, ssh: response } : node);
    setNotice(t("sshConnectionSaved"), "success");
    return response;
  }

  async function testSSHConnection(nodeID, profile) {
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-connection/test`, {
      method: "POST",
      timeoutMs: 6000,
      body: JSON.stringify({
        host: String(profile?.host || "").trim(),
        port: Number(profile?.port || 22),
        user: String(profile?.user || "root").trim(),
      }),
    });
    setNotice(t("sshConnectionReachable"), "success");
    return response;
  }

  return reactive({
    state,
    currentInterface,
    currentInterfaceRecord,
    currentNode,
    metrics,
    filteredLogs,
    visibleInterfaces,
    formatNumber,
    formatLogReason,
    setSection,
    setSecurityFeature,
    setEventsView,
    setDirection,
    setInterface,
    setNode,
    setOverviewScope,
    deleteNode,
    bootstrap,
    refreshAll,
    refreshData,
    addCIDR,
    addPort,
    saveRuleDescription,
    saveIPv6Action,
    removeCIDR,
    removePort,
    changeRuleStrategy,
    attachCurrent,
    detachCurrent,
    enableProtectionBaseline,
    trialProtectionBaseline,
    confirmProtectionTrial,
    rollbackProtectionTrial,
    runLogAction,
    toggleLogSelection,
    clearSelection,
    saveLoggingSettings,
    saveAuthSettings,
    saveSSHProtectionSettings,
    saveSSHTransferPolicy,
    refreshSSHActivity,
    createSSHIntegrityBaseline,
    verifySSHIntegrity,
    releaseSSHProtectionBlock,
    refreshSecurityData,
    refreshSecurityScan,
    refreshSecurityQuarantine,
    startSecurityScan,
    quarantineSecurityFinding,
    terminateSecurityProcess,
    deleteSecurityQuarantine,
    restoreSecurityQuarantine,
    downloadSecurityScanReport,
    changePassword,
    createUser,
    updateUserRole,
    updateUserEnabled,
    resetUserPassword,
    deleteUser,
    clearPersistedLogs,
    confirmClearPersistedLogs,
    upsertNode,
    renameNode,
    saveSSHConnection,
    testSSHConnection,
    openSSHConsole,
    closeSSHConsole,
    createSSHConsoleSession,
    closeSSHConsoleSession,
    openModal,
    closeModal,
    confirmModal,
    closeErrorDialog,
    dismissToast,
    handleError,
  });
}
