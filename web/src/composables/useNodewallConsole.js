import { computed, reactive, ref } from "vue";
import { downloadFile, request, withDirection } from "@/lib/api";
import { eventDispositionKey } from "@/lib/eventIds";
import { buildEventRecords } from "@/lib/eventRecords";
import { canActOnFirewallSource } from "@/lib/firewallLogs";

const LEGACY_EVENT_STATUS_KEY = "nodewall-event-status";

function loadLegacyEventStatuses() {
  try {
    const saved = typeof window === "undefined" ? "" : window.localStorage?.getItem(LEGACY_EVENT_STATUS_KEY);
    const entries = JSON.parse(saved || "[]");
    return new Map(Array.isArray(entries) ? entries : []);
  } catch {
    return new Map();
  }
}

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
  return [item.interface || "-", item.direction || "ingress", item.source_ip || item.source_cidr || "-", item.port || 0, item.timestamp || "-"].join("|");
}

function riskFromInsights(insights, stats) {
  if ((insights.top_attackers || []).some((item) => item.risk === "high")) return "high";
  if ((insights.top_attackers || []).some((item) => item.risk === "medium")) return "medium";
  if ((stats.dropped || 0) > 0) return "medium";
  return "low";
}

function base64URLBytes(value) {
  const normalized = String(value || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = window.atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function base64URLFromBytes(value) {
  const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value || []);
  let binary = "";
  bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
  return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function webAuthnPublicKeyOptions(payload) {
  const options = JSON.parse(JSON.stringify(payload?.publicKey || payload || {}));
  if (options.challenge) options.challenge = base64URLBytes(options.challenge);
  if (options.user?.id) options.user.id = base64URLBytes(options.user.id);
  for (const item of (options.excludeCredentials || [])) {
    if (item.id) item.id = base64URLBytes(item.id);
  }
  for (const item of (options.allowCredentials || [])) {
    if (item.id) item.id = base64URLBytes(item.id);
  }
  return options;
}

function serializeWebAuthnCredential(credential) {
  const response = credential.response || {};
  const result = {
    id: credential.id,
    rawId: base64URLFromBytes(response.rawId),
    type: credential.type,
    response: {},
  };
  if (response.clientDataJSON) result.response.clientDataJSON = base64URLFromBytes(response.clientDataJSON);
  if (response.attestationObject) result.response.attestationObject = base64URLFromBytes(response.attestationObject);
  if (response.authenticatorData) result.response.authenticatorData = base64URLFromBytes(response.authenticatorData);
  if (response.signature) result.response.signature = base64URLFromBytes(response.signature);
  if (response.userHandle) result.response.userHandle = base64URLFromBytes(response.userHandle);
  return result;
}

export function useNodewallConsole(i18n) {
  const t = i18n?.t || ((key) => key);
  let disposed = false;
  let locationChangeHandler = null;
  let clusterEventSource = null;
  let clusterReconnectTimer = null;
  let clusterAuthCheckInFlight = null;
  let securityScanTimer = null;
  let securityQuarantineRefreshTimer = null;
  let securityQuarantineRefreshInFlight = null;
  let securityScanEventSource = null;
  let securityScanEventNodeID = "";
  let securityScanEventReady = false;
  let securityScanEventFailed = false;
  let securityScanRevision = 0;
  let clusterEventStreamKey = "";
  let refreshCurrentToken = 0;
  let eventsRefreshInFlight = null;
  let eventsDataGeneration = 0;
  let overviewDataGeneration = 0;
  let monitoringDataGeneration = 0;
  const sectionRefreshInFlight = new Map();
  let clusterAggregateInFlight = null;
  let clusterAggregateLastAt = 0;
  let clusterAggregateToken = 0;
  let securityOverviewToken = 0;
  const nodeProtectionInFlight = new Map();
  let eventDispositionRefreshToken = 0;
  let eventDispositionMutationGeneration = 0;
  let legacyDispositionEndpoint = false;
  const localEventStatuses = ref(loadLegacyEventStatuses());
  let persistedLogsRefreshToken = 0;
  let nodesRefreshToken = 0;
  let managementSettingsRefreshToken = 0;
  const managementSettingsMutationToken = {
    logging: 0,
    auth: 0,
    passkey: 0,
    smtp: 0,
  };
  const eventDispositionPending = new Map();
  const eventDispositionMutationSequence = new Map();
  let toastCounter = 0;
  let modalOnCancel = null;
  const deleteEventSeen = new Set();
  let clusterEventStreamReady = false;
  const toastTimers = new Map();
  const CLUSTER_AGGREGATE_TTL_MS = 5000;
  const NODE_STORAGE_KEY = "nodewall-selected-node";
  const SECTION_STORAGE_KEY = "nodewall-selected-section";
  // The security overview is the operator landing page. It owns the compact
  // cross-node summary and embeds resource health, while the protection page
  // remains a focused workspace for firewall/SSH/malware controls.
  const DEFAULT_SECTION = "overview";
  const SECURITY_FEATURE_SET = new Set(["overview", "firewall", "malware", "ssh"]);
  const SECTION_SET = new Set(["overview", "cluster", "policy", "logs", "monitoring", "events", "management", "users", "account", "security", "ssh-console"]);

  function nodeIdFromLocation() {
    if (typeof window === "undefined") return "";
    const query = new URLSearchParams(window.location.search || "");
    const storedNode = typeof window.localStorage?.getItem === "function"
      ? window.localStorage.getItem(NODE_STORAGE_KEY)
      : "";
    return String(query.get("node") || storedNode || "").trim();
  }

  function writeNodeToLocation(nodeID) {
    const next = String(nodeID || "").trim();
    if (typeof window === "undefined") return;
    if (next && typeof window.localStorage?.setItem === "function") {
      window.localStorage.setItem(NODE_STORAGE_KEY, next);
    } else if (!next && typeof window.localStorage?.removeItem === "function") {
      window.localStorage.removeItem(NODE_STORAGE_KEY);
    }
    // Lightweight console tests provide only the browser primitives they need;
    // persisting to localStorage is still useful there even when URL/history
    // are absent. In the real browser both APIs are available.
    if (typeof URL !== "function" || !window.location?.href || typeof window.history?.replaceState !== "function") return;
    const url = new URL(window.location.href);
    if (next) url.searchParams.set("node", next);
    else url.searchParams.delete("node");
    window.history.replaceState({}, "", url);
  }

  function normalizeSecurityFeature(value) {
    const next = String(value || "").trim().toLowerCase();
    return SECURITY_FEATURE_SET.has(next) ? next : "firewall";
  }

  function normalizeSection(value) {
    const next = String(value || "").trim().toLowerCase();
    if (next === "malware" || next === "ssh" || next === "firewall") return "security";
    if (next === "logs") return "events";
    return SECTION_SET.has(next) ? next : "overview";
  }

  function sectionFromLocation() {
    if (typeof window === "undefined") return { section: DEFAULT_SECTION, feature: "overview" };
    const hash = String(window.location.hash || "").replace(/^#/, "").trim().toLowerCase();
    const query = new URLSearchParams(window.location.search || "");
    const explicitHash = SECTION_SET.has(hash) || SECURITY_FEATURE_SET.has(hash);
    const querySection = String(query.get("section") || "").trim().toLowerCase();
    let remembered = "";
    try { remembered = window.sessionStorage?.getItem(SECTION_STORAGE_KEY) || ""; } catch (_) {}
    const requested = explicitHash ? hash : (querySection || remembered || DEFAULT_SECTION);
    const section = normalizeSection(requested);
    let feature = "overview";
    if (section === "security") {
      if (SECURITY_FEATURE_SET.has(requested)) feature = requested;
      else if (!explicitHash && querySection && query.get("feature")) feature = normalizeSecurityFeature(query.get("feature"));
    }
    return { section, feature };
  }

  function rememberSection(section, feature) {
    const route = section === "security" && feature !== "overview" ? feature : section;
    if (typeof window !== "undefined") {
      // A sign-in redirect can lose the fragment. Remember it per tab so a
      // different Web tab cannot move this tab out of the event center.
      try { window.sessionStorage?.setItem(SECTION_STORAGE_KEY, route); } catch (_) {}
    }
    return route;
  }

  function writeSectionToLocation(section) {
    if (typeof window === "undefined") return;
    const route = rememberSection(normalizeSection(section), state.securityFeature);
    if (window.location.hash !== `#${route}`) window.location.hash = route;
  }

  function applySectionFromLocation(shouldRefresh = true) {
    const { section: next, feature } = sectionFromLocation();
    const nextFeature = next === "security" ? feature : state.securityFeature;
    rememberSection(next, nextFeature);
    const featureChanged = nextFeature !== state.securityFeature;
    state.securityFeature = nextFeature;
    if (next === state.section) {
      if (shouldRefresh && featureChanged && next === "security") {
        syncSectionEventStream();
        queueSectionRefresh(next).catch(handleError);
      }
      return;
    }
    state.section = next;
    state.error = "";
    if (state.loading) return;
    syncSectionEventStream();
    if (shouldRefresh) {
      queueSectionRefresh(next).catch(handleError);
    }
  }

  const state = reactive({
    locale: computed(() => i18n?.state?.locale || "zh-CN"),
    section: DEFAULT_SECTION,
    securityFeature: "overview",
    eventsView: "logs",
    overviewScope: "all",
    direction: "ingress",
    nodeId: nodeIdFromLocation() || "node-01",
    nodes: [],
    nodesLoaded: false,
    version: {
      app_version: "",
      package_version: "",
    },
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
    accountSecurity: {
      loading: false,
      auth_enabled: false,
      username: "",
      email: "",
      email_verified: false,
      otp_enabled: false,
      recovery_codes_remaining: 0,
      passkeys: 0,
      passkey_list: [],
      passkey_enabled: false,
      passkey_rp_id: "",
      passkey_origins: [],
      passkey_tls_mode: "local",
      mfa_required: false,
      require_mfa_for_admin: false,
      allowed_methods: [],
      setup: null,
      recovery_codes: [],
    },
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
      mfa_required: false,
      require_mfa_for_admin: false,
      allowed_mfa_methods: ["otp", "passkey"],
      passkey_enabled: false,
      passkey_rp_id: "",
      passkey_origins: [],
      passkey_tls_mode: "local",
    },
    passkeySettings: {
      enabled: false,
      rp_id: "",
      origins: [],
      tls_mode: "local",
      tls_enabled: false,
      requirements_met: false,
      certificate_present: false,
      certificate_valid: false,
      certificate_error: "",
      certificate_dns_names: [],
      certificate_ip_addresses: [],
      certificate_ip_compatible: false,
      certificate_not_after: "",
      restart_required: false,
      certificate_pem: "",
      private_key_pem: "",
    },
    smtpSettings: {
      enabled: false,
      host: "",
      port: 587,
      security: "starttls",
      username: "",
      from_email: "",
      from_name: "",
      subject_prefix: "[NodeWall]",
      reset_subject: "Password reset code",
      reset_template: "",
      verify_subject: "Email verification code",
      verify_template: "",
      has_password: false,
      password: "",
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
        allow_password_login: true,
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
      keys: [],
    },
    sshConsole: {
      nodeId: "",
      sessionId: "",
    },
    securitySummary: {
      engine: "nodewall",
      checks: [],
      scan: { status: "idle", findings: [] },
      quarantine: { enabled: true, automatic: true },
    },
    securityScanReports: [],
    securityScanArchiveError: "",
    securityQuarantine: {
      root: "",
      entries: [],
    },
    // Overview uses this lightweight per-node snapshot to show the health of
    // every protection capability without duplicating the detailed pages.
    securityOverviewNodes: [],
    nodeProtection: {},
    // Direct Agent reachability is kept separately from the manager heartbeat.
    // A standby Web server can still reach a peer while the active manager is
    // offline, so last_seen_at alone must not force that peer into "断开".
    nodeReachability: {},
    settingsLoaded: { logging: false, auth: false, passkey: false, smtp: false },
    settingsETags: {},
    consoleRevision: 0,
    loggingNodeID: "",
    managementScope: "global",
    sshSettingsETag: "",
    users: [],
    inventory: { interfaces: [], recommended: "" },
    interfaceDataStatus: "loading",
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
        average_filesystem_used_percent: 0,
        uptime_seconds: 0,
        rx_bytes_per_second: 0,
        tx_bytes_per_second: 0,
      },
    },
    // Monitoring samples arrive from the page-scoped SSE stream. Keeping the
    // last frame in the shared store lets the page render immediately after a
    // route switch without starting a second polling loop.
    monitoringHistory: null,
    monitoringHistoryError: "",
    monitoringStreamQuery: { scope: "cluster", node: "", range: 900, from: "", to: "" },
    overviewProtectionStatus: "",
    persistedLogs: [],
    // A cluster-wide event feed is independent of node-scoped security forms.
    // Keep it when switching nodes/pages; only its own snapshot replaces it.
    eventCenter: { scope: "cluster", nodes: [], logs: [], ready: false, error: "" },
    eventsRevision: 0,
    // Event triage decisions are shared by all browsers through the server.
    eventDispositions: {},
    eventDispositionsLoaded: false,
    eventDispositionRevision: 0,
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
      error: "",
      busy: false,
      open: false,
      title: "",
      copy: "",
      fields: [],
      onConfirm: null,
      keepOpenOnError: false,
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
      otpCurrentPassword: "",
      otpCode: "",
      otpDisablePassword: "",
      otpDisableCode: "",
      email: "",
      emailPassword: "",
      emailRequestID: "",
      emailCode: "",
      passkeyName: "",
      passkeyPassword: "",
    },
  });

  const currentInterface = computed(() => {
    if (state.section !== "overview" && state.selectedInterface) return state.selectedInterface;
    if (state.defaultInterface) return state.defaultInterface;
    if (state.recommendedInterface) return state.recommendedInterface;
    const physical = (state.interfaces || []).find((item) => item?.is_physical);
    return physical?.name || state.interfaces[0]?.name || "";
  });
  const currentInterfaceRecord = computed(() => (state.interfaces || []).find((item) => item.name === currentInterface.value) || null);
  const currentPolicy = computed(() => state.policy?.node_id === state.nodeId
    && state.policy?.interface === currentInterface.value ? state.policy : null);
  const currentNode = computed(() => (state.nodes || []).find((item) => item.id === state.nodeId) || null);

  function isNodeOnline(node) {
    const status = state.nodeProtection[node?.id];
    if (status?.node_status === "online") return true;
    if (status?.node_status === "offline") {
      // A newer heartbeat may arrive before the next protection snapshot.
      const checked = new Date(status.checked_at || 0).getTime();
      return checked > 0 && new Date(node?.last_seen_at || 0).getTime() > checked;
    }
    const seen = new Date(node?.last_seen_at || 0).getTime();
    if (seen > 0 && Date.now() - seen <= 60000) return true;
    return state.nodeReachability[node?.id] === true;
  }

  function resetNodeScopedSecurityData(nodeID = "") {
    // Clear data from the previous host immediately. Requests are guarded by
    // node ID below, but clearing here also prevents a brief cross-host view
    // while the newly selected Agent is still loading.
    state.securitySummary = {
      engine: "nodewall",
      node_id: nodeID,
      checks: [],
      scan: { status: "idle", findings: [], node_id: nodeID },
      quarantine: { enabled: true, automatic: true },
    };
    state.securityQuarantine = { root: "", entries: [], node_id: nodeID };
    state.securityScanReports = [];
    state.securityScanArchiveError = "";
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
        allow_password_login: true,
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
      keys: [],
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
        item.source_cidr,
        item.source_domain,
        item.interface,
        item.reason,
        item.port,
        item.disposition?.status,
      ].join(" ").toLowerCase().includes(query);
    });
  });

  const eventRows = computed(() => buildEventRecords(state.eventCenter, {
    t,
    formatLogReason,
    statusFor: (id, node, fallback) => state.eventDispositionsLoaded
      ? state.eventDispositions[eventDispositionKey(node, id)]?.status || fallback
      : localEventStatuses.value.get(id) || fallback,
  }));
  const pendingEventCount = computed(() => eventRows.value.filter((row) => row.status === "pending").length);

  function formatLogReason(reason) {
    switch (String(reason || "").replace(/^nodewall:/, "")) {
      case "reply_flow_allowed":
        return t("reasonReplyFlowAllowed");
      case "blocked_source":
        return t("reasonBlockedSource");
      case "denied_port":
        return t("reasonDeniedPort");
      case "restricted_policy":
        return t("reasonRestrictedPolicy");
      case "source_not_allowed":
      case "default_deny":
        return t("reasonSourceNotAllowed");
      case "dhcp_broadcast":
        return t("reasonDHCPBroadcast");
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
    if (requested === "overview") {
      state.section = "overview";
      state.error = "";
      writeSectionToLocation("overview");
      syncSectionEventStream();
      queueSectionRefresh("overview").catch(handleError);
      return;
    }
    if (requested === "security") state.securityFeature = "overview";
    if (SECURITY_FEATURE_SET.has(requested)) state.securityFeature = requested;
    state.section = normalizeSection(requested);
    state.error = "";
    writeSectionToLocation(state.section);
    syncSectionEventStream();
    queueSectionRefresh(state.section).catch(handleError);
  }

  // Logout is deliberately a browser navigation. The server-side GET endpoint
  // clears the session and CSRF cookies in one response, so the console cannot
  // remain visible with stale in-memory data after the session is revoked.
  function logout() {
    if (typeof window !== "undefined") window.location.assign("/logout");
  }

  function setSecurityFeature(feature) {
    state.securityFeature = normalizeSecurityFeature(feature);
    syncSectionEventStream();
    // Keep the selected tool in the URL so a refresh returns to the same
    // security function instead of silently falling back to the firewall.
    if (state.section === "security") writeSectionToLocation("security");
    if (state.section === "security") {
      // Feature tabs share the selected node, but each feature owns a
      // different subset of node data. Refresh that subset when switching
      // tabs so a fast node switch does not leave the newly opened tab empty.
      queueSectionRefresh("security").catch(handleError);
    }
  }

  function setEventsView(view) {
    state.eventsView = ["logs", "ssh"].includes(view) ? view : "logs";
  }

  function setMonitoringStreamQuery(query = {}) {
    const previous = monitoringHistoryParams().toString();
    state.monitoringStreamQuery = {
      scope: query.node ? "node" : "cluster",
      node: query.node || "",
      range: query.range || 900,
      from: query.from || "",
      to: query.to || "",
    };
    if (monitoringHistoryParams().toString() !== previous) {
      monitoringDataGeneration++;
      state.monitoringHistory = null;
      state.monitoringHistoryError = "";
    }
    if (state.section === "monitoring") {
      syncSectionEventStream();
      if (!state.monitoringHistory) queueSectionRefresh("monitoring").catch(handleError);
    }
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
    const nextDirection = direction === "egress" ? "egress" : "ingress";
    if (state.direction === nextDirection) return;
    state.direction = nextDirection;
    resetInterfaceData();
    closeModal();
    state.error = "";
    if (["overview", "security"].includes(state.section)) {
      syncSectionEventStream();
      if (clusterEventSource && !(state.section === "security" && state.selectedInterface)) return;
    }
    const refreshCurrentFn = state.section === "overview" ? queueRefreshCurrent : queueRefreshCurrentLight;
    // A manually selected direction must remain selected even when it has no
    // rules yet. Automatic direction discovery is only appropriate during the
    // initial data load, otherwise an empty egress policy immediately jumps
    // back to ingress and makes the toggle appear broken.
    Promise.all([refreshCurrentFn(false), state.section === "overview" ? refreshClusterAggregate({ force: true }) : Promise.resolve()]).catch(handleError);
  }

  function setInterface(iface) {
    const nextInterface = String(iface || "").trim();
    if (!nextInterface || nextInterface === currentInterface.value) return;
    state.selectedInterface = nextInterface;
    resetInterfaceData();
    closeModal();
    state.error = "";
    syncSectionEventStream();
    // HTTP and SSE share the same per-interface collector. HTTP also keeps
    // the chosen NIC usable when an older Web resolves SSE to an active NIC.
    queueRefreshCurrentLight(false).catch(handleError);
  }

  function resetInterfaceData() {
    refreshCurrentToken++;
    state.interfaceDataStatus = "loading";
    applyPolicyRules({});
    state.stats = { passed: 0, dropped: 0 };
    state.recentStats = { window_seconds: 300, recent_passed: 0, recent_dropped: 0, passed_pps: 0, dropped_pps: 0, drop_rate: 0 };
    state.insights = { top_attackers: [], top_countries: [], top_ports: [], top_passed: [], trend: [], suggested_blocks: [] };
    state.protectionTrial = null;
    state.interfaceLogs = [];
    state.temporaryBlocks = [];
    state.rateLimits = [];
  }

  async function setNode(nodeId) {
    const nextNodeID = String(nodeId || "").trim();
    if (nextNodeID === state.nodeId) return;
    if (state.section === "ssh-console" && state.sshConsole.sessionId) {
      await closeSSHConsoleSession();
    }
    resetInterfaceData();
    // Cluster-scoped event/monitoring subscriptions do not depend on the
    // security workspace's node and must survive changes to that selection.
    if (["overview", "security", "policy", "ssh-console"].includes(state.section)) stopClusterEventStream();
    closeModal();
    state.nodeId = nextNodeID;
    writeNodeToLocation(nextNodeID);
    if (state.section === "ssh-console") state.sshConsole.nodeId = nextNodeID;
    state.selectedInterface = "";
    state.defaultInterface = "";
    state.recommendedInterface = "";
    state.interfaces = [];
    state.inventory = { interfaces: [], recommended: "" };
    state.overviewProtectionStatus = "";
    state.health = { interfaces: [] };
    if (securityScanTimer && typeof window !== "undefined") {
      window.clearTimeout(securityScanTimer);
      securityScanTimer = null;
    }
    stopSecurityScanEventStream();
    securityScanRevision++;
    resetNodeScopedSecurityData(nextNodeID);
    state.sshSettingsETag = "";
    syncSectionEventStream();
    state.error = "";
    try {
      // The section refresh already loads the selected node's inventory and
      // data. Doing a preliminary refresh here caused duplicate Agent calls
      // and, on every node switch, a full cluster aggregation that probes all
      // nodes. Keep the existing event stream and load only this section once.
      await queueSectionRefresh(state.section, { nodeSwitch: true });
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
    await refreshAll();
  }

  async function updateNode(nodeId) {
    if (!nodeId) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeId)}/update`, {
      method: "POST",
      timeoutMs: 15000,
      body: JSON.stringify({}),
    });
    await refreshNodes();
    setNotice(t("clusterUpdateAccepted"), "success");
    return response;
  }

  function handleError(error, options = {}) {
    if (error?.code === "SUPERSEDED" || error?.code === "ABORTED") return;
    const errorCandidates = [
      error?.message,
      error?.payload?.error,
      error?.payload?.message,
      error?.error,
      typeof error === "string" ? error : "",
    ].map((value) => String(value || "").trim()).filter(Boolean);
    const rawMessage = errorCandidates[0] || String(error);
    const normalizedMessage = errorCandidates.join(" ").toLowerCase();
    if (normalizedMessage.includes("superseded")) return;
    let message = rawMessage;
    if (error?.code === "CONFIG_CHANGED") {
      if (options.inline) return t("settingsConflict");
      state.error = t("settingsConflict");
      setNotice(state.error, "error");
      return;
    }
    const localizedPasskeyError = [
      "passkeyBrowserUnsupported",
      "passkeyPasswordRequired",
      "passkeyRegistrationCancelled",
      "passkeyOriginRequired",
      "passkeyRegistrationFailed",
      "passkeyDNSRequired",
      "passkeyLoginUnavailable",
      "passkeyOperationFailed",
      "passkeyAlreadyRegistered",
      "passkeyDisabled",
      "passkeyRPIDRequired",
      "passkeyHTTPSOriginRequired",
      "passkeyTLSDisabled",
      "passkeyCertificateInvalid",
      "passkeyCertificateHostnameMismatch",
      "passkeyProxyCertificateImport",
      "passkeyOriginOutsideRP",
      "passkeyPrivateKeyHTTPSRequired",
    ].some((key) => rawMessage === t(key));
    if (localizedPasskeyError) {
      message = rawMessage;
    } else if (
      normalizedMessage.includes("previous policy update is still recovering")
      || normalizedMessage.includes("policy update recovery")
      || normalizedMessage.includes("retry after node connectivity is restored")
      || normalizedMessage.includes("node connectivity is restored")
    ) {
      message = t("requestErrorPolicyRecovery");
    } else if (normalizedMessage.includes("restore target already exists")) {
      message = t("securityQuarantineRestoreTargetExists");
    } else if (normalizedMessage.includes("quarantine entry not found")) {
      message = t("securityQuarantineEntryNotFound");
    } else if (normalizedMessage.includes("quarantine entry is no longer a regular file")) {
      message = t("securityQuarantineEntryInvalid");
    } else if (normalizedMessage.includes("original path is unavailable")) {
      message = t("securityQuarantineRestoreUnavailable");
    } else if (normalizedMessage.includes("finding changed since the scan")) {
      message = t("securityFindingChanged");
    } else if (normalizedMessage.includes("finding not found in the latest scan")) {
      message = t("securityFindingNotFound");
    } else if (normalizedMessage.includes("only regular file findings can be manually isolated")) {
      message = t("securityManualFileOnly");
    } else if (normalizedMessage.includes("process is evidence-only")) {
      message = t("securityProcessIsolationUnavailable");
    } else if (normalizedMessage.includes("finding is no longer a regular file")) {
      message = t("securityFindingNoLongerFile");
    } else if (normalizedMessage.includes("无法定位内核模块文件") || normalizedMessage.includes("no disk module file") || normalizedMessage.includes("sysfs virtual directory")) {
      message = t("securityKernelModuleNeedsRebootReview");
    } else if (normalizedMessage.includes("otp verification failed") || normalizedMessage.includes("setup expired")) {
      message = t("otpVerificationFailed");
    } else if (normalizedMessage.includes("valid otp or recovery code is required")) {
      message = t("otpDisableCodeInvalid");
    } else if (normalizedMessage.includes("otp is already enabled")) {
      message = t("otpAlreadyEnabled");
    } else if (normalizedMessage.includes("must enable otp before mfa is required")) {
      message = t("mfaPolicyEnrollmentRequired");
    } else if (normalizedMessage.includes("otp must remain an allowed method")) {
      message = t("mfaPolicyOTPRequired");
    } else if (normalizedMessage.includes("at least one additional verification method")) {
      message = t("mfaPolicyMethodRequired");
    } else if (normalizedMessage.includes("passkey must be enabled and ready")) {
      message = t("mfaPolicyPasskeyDisabled");
    } else if (normalizedMessage.includes("must enroll an allowed mfa method")) {
      message = t("mfaPolicyEnrollmentRequired");
    } else if (normalizedMessage.includes("current password is invalid")) {
      message = t("currentPasswordInvalid");
    } else if (normalizedMessage.includes("authentication required")) {
      message = t("authenticationRequired");
    } else if (normalizedMessage.includes("cannot validate mfa policy")) {
      message = t("mfaPolicyValidationFailed");
    } else if (normalizedMessage.includes("mfa policy prevents disabling")) {
      message = t("mfaPolicyPreventsDisable");
    } else if (normalizedMessage.includes("email verification code is invalid")) {
      message = t("emailCodeInvalid");
    } else if (normalizedMessage.includes("passkey registration session") || normalizedMessage.includes("passkey login session")) {
      message = t("passkeySessionExpired");
    } else if (normalizedMessage.includes("passkey requires a dns host") || normalizedMessage.includes("passkey requires an https origin")) {
      message = t("passkeyDNSRequired");
    } else if (normalizedMessage.includes("relying party id") || normalizedMessage.includes("valid domain string") || normalizedMessage.includes("rp id")) {
      message = t("passkeyOriginRequired");
    } else if (normalizedMessage.includes("passkey login is unavailable for this account")) {
      message = t("passkeyLoginUnavailable");
    } else if (normalizedMessage.includes("passkey is disabled in system settings")) {
      message = t("passkeyDisabled");
    } else if (normalizedMessage.includes("passkey rp id is required") || normalizedMessage.includes("passkey rp id must be a dns")) {
      message = t("passkeyRPIDRequired");
    } else if (normalizedMessage.includes("at least one https passkey origin") || normalizedMessage.includes("passkey origin must be a valid https url") || normalizedMessage.includes("passkey origin must use a dns")) {
      message = t("passkeyHTTPSOriginRequired");
    } else if (normalizedMessage.includes("passkey origin host") && normalizedMessage.includes("outside rp id")) {
      message = t("passkeyOriginOutsideRP");
    } else if (normalizedMessage.includes("nodewall https must be enabled")) {
      message = t("passkeyTLSDisabled");
    } else if (normalizedMessage.includes("certificate import is not used")) {
      message = t("passkeyProxyCertificateImport");
    } else if (normalizedMessage.includes("private key import requires an https")) {
      message = t("passkeyPrivateKeyHTTPSRequired");
    } else if (normalizedMessage.includes("local tls certificate does not contain rp id")) {
      message = t("passkeyCertificateHostnameMismatch");
    } else if (normalizedMessage.includes("tls certificate") || normalizedMessage.includes("parse tls certificate")) {
      message = t("passkeyCertificateInvalid");
    } else if (normalizedMessage.includes("passkey credential is already registered")) {
      message = t("passkeyAlreadyRegistered");
    } else if (normalizedMessage.includes("passkey") || normalizedMessage.includes("webauthn")) {
      message = t("passkeyOperationFailed");
    } else if (normalizedMessage.includes("totp") || normalizedMessage.includes("otp secret") || normalizedMessage.includes("otp verification")) {
      message = t("otpVerificationFailed");
    } else if (normalizedMessage.includes("authentication is disabled")) {
      message = t("authDisabled");
    } else if (normalizedMessage.includes("email address is invalid")) {
      message = t("emailAddressInvalid");
    } else if (normalizedMessage.includes("smtp must be enabled before binding")) {
      message = t("emailSMTPRequired");
    } else if (normalizedMessage.includes("new password must be at least")) {
      message = t("passwordTooShort");
    } else if (normalizedMessage.includes("password reset request is no longer valid") || normalizedMessage.includes("password reset code is invalid")) {
      message = t("passwordResetInvalid");
    } else if (normalizedMessage.includes("smtp is not enabled") || normalizedMessage.includes("smtp mail sender is not configured")) {
      message = t("smtpDisabled");
    } else if (normalizedMessage.includes("smtp host is required") || normalizedMessage.includes("smtp port is invalid") || normalizedMessage.includes("smtp security must be") || normalizedMessage.includes("smtp sender address is required") || normalizedMessage.includes("smtp sender address is invalid") || normalizedMessage.includes("plain smtp is only allowed") || normalizedMessage.includes("unsupported smtp security") || normalizedMessage.includes("email subject contains invalid")) {
      message = t("smtpConfigurationInvalid");
    } else if (normalizedMessage.includes("recipient email address is invalid")) {
      message = t("smtpRecipientInvalid");
    } else if (normalizedMessage.includes("temporarily allow dns") || normalizedMessage.includes("temporarily allow smtp egress") || normalizedMessage.includes("temporary egress")) {
      message = t("smtpEgressDenied");
    } else if (normalizedMessage.includes("resolve smtp host") || normalizedMessage.includes("smtp host has no ipv4") || normalizedMessage.includes("dns")) {
      message = t("smtpDNSFailed");
    } else if (normalizedMessage.includes("connect to smtp server")) {
      message = t("smtpConnectionFailed");
    } else if (normalizedMessage.includes("smtp tls") || normalizedMessage.includes("smtp starttls") || normalizedMessage.includes("does not support starttls")) {
      message = t("smtpTLSFailed");
    } else if (normalizedMessage.includes("smtp authentication")) {
      message = t("smtpAuthFailed");
    } else if (normalizedMessage.includes("smtp") && (normalizedMessage.includes("failed") || normalizedMessage.includes("error"))) {
      message = t("smtpDeliveryFailed");
    } else if (normalizedMessage.includes("native xdp dataplane cannot enforce egress policy")) {
      message = t("nativeXDPNoEgress");
    }
    if (message === "Request superseded" || message === "Request aborted") return;
    if (error?.code === "AUTH_REQUIRED") return;
    if (options.inline) return message === "Failed to fetch" ? t("requestErrorOffline") : message;
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
    if (state.modal.open) closeModal();
    state.modal.error = "";
    state.modal.busy = false;
    state.modal.open = true;
    state.modal.title = config.title;
    state.modal.copy = config.copy;
    state.modal.fields = config.fields || [];
    state.modal.onConfirm = config.onConfirm || null;
    state.modal.keepOpenOnError = Boolean(config.keepOpenOnError);
    modalOnCancel = config.onCancel || null;
  }

  function closeModal() {
    const cancel = modalOnCancel;
    modalOnCancel = null;
    state.modal.error = "";
    state.modal.busy = false;
    state.modal.open = false;
    state.modal.title = "";
    state.modal.copy = "";
    state.modal.fields = [];
    state.modal.onConfirm = null;
    state.modal.keepOpenOnError = false;
    cancel?.();
  }

  async function confirmModal(payload) {
    const confirm = state.modal.onConfirm;
    if (!confirm || state.modal.busy) return;
    state.modal.busy = true;
    state.modal.error = "";
    try {
      await confirm(payload || {});
      if (state.modal.onConfirm === confirm) closeModal();
    } catch (error) {
      if (state.modal.onConfirm !== confirm) return;
      if (state.modal.keepOpenOnError) state.modal.error = handleError(error, { inline: true }) || "";
      else { closeModal(); handleError(error); }
    } finally {
      if (state.modal.onConfirm === confirm) state.modal.busy = false;
    }
  }

  async function bootstrap() {
    disposed = false;
    state.loading = true;
    try {
      applySectionFromLocation(false);
      // Version metadata is decorative and must not keep the application
      // shell waiting if that endpoint is slow or temporarily unavailable.
      request("/version").then((versionInfo) => {
        state.version = {
          app_version: versionInfo.app_version || versionInfo.version || "",
          package_version: versionInfo.package_version || versionInfo.version || "",
        };
      }).catch(() => {});
      const [session, bootstrapData] = await Promise.all([
        request("/auth/session").catch(() => ({ auth_enabled: false, authenticated: false })),
        request("/bootstrap"),
      ]);
      state.authEnabled = !!session.auth_enabled;
      state.authAuthenticated = !!session.authenticated;
      state.authUsername = session.username || "";
      state.authRole = session.role || "";
      const requestedNodeID = nodeIdFromLocation();
      state.nodeId = requestedNodeID || bootstrapData.node_id || state.nodeId;
      writeNodeToLocation(state.nodeId);
      // Bootstrap describes the manager Agent. A remote-node URL must wait
      // for that node's own inventory before selecting or subscribing a NIC.
      state.defaultInterface = state.nodeId === bootstrapData.node_id ? bootstrapData.default_interface || "" : "";
      state.recommendedInterface = state.defaultInterface;
      state.currentSourceIP = bootstrapData.client_ip || "";
      resetNodeScopedSecurityData(state.nodeId);
      if (typeof window !== "undefined") {
        locationChangeHandler = () => applySectionFromLocation(true);
        window.addEventListener("hashchange", locationChangeHandler);
      }
      // The shell only depends on session/bootstrap data. Each page loads its
      // own data after it is visible, so unrelated nodes or logs cannot hold
      // the whole console behind the startup spinner.
      state.loading = false;
      const eventFeed = refreshEventsData();
      const eventDispositions = state.section === "events" ? Promise.resolve() : refreshEventDispositions();
      await refreshNodes();
      syncSectionEventStream();
      await Promise.all([eventFeed, eventDispositions, queueSectionRefresh(state.section)]);
      state.error = "";
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
    clusterEventStreamKey = "";
  }

  function dispose() {
    disposed = true;
    stopClusterEventStream();
    stopSecurityScanEventStream();
    for (const timer of toastTimers.values()) window.clearTimeout(timer);
    toastTimers.clear();
    if (locationChangeHandler && typeof window !== "undefined") window.removeEventListener?.("hashchange", locationChangeHandler);
    locationChangeHandler = null;
  }

  const clusterEventPhaseKeys = Object.freeze({
    update: "clusterEventPhaseUpdate",
    cleanup: "clusterEventPhaseCleanup",
    agent_delete: "clusterEventPhaseAgentDelete",
    finalize: "clusterEventPhaseFinalize",
  });

  const clusterEventStatusKeys = Object.freeze({
    running: "clusterEventStatusRunning",
    success: "clusterEventStatusSuccess",
    failed: "clusterEventStatusFailed",
  });

  const clusterEventMessageKeys = Object.freeze({
    "node delete requested": "clusterEventNodeDeleteRequested",
    "triggering remote cleanup": "clusterEventTriggerCleanup",
    "remote cleanup done": "clusterEventCleanupDone",
    "remote cleanup failed": "clusterEventCleanupFailed",
    "remote cleanup unreachable": "clusterEventCleanupUnreachable",
    "remote cleanup request build failed": "clusterEventCleanupBuildFailed",
    "triggering remote full delete": "clusterEventTriggerFullDelete",
    "remote full delete triggered": "clusterEventFullDeleteTriggered",
    "remote full delete failed": "clusterEventFullDeleteFailed",
    "remote full delete unreachable": "clusterEventFullDeleteUnreachable",
    "remote full delete request build failed": "clusterEventFullDeleteBuildFailed",
    "node not found while deleting": "clusterEventNodeNotFound",
    "node removed from manager list": "clusterEventNodeRemoved",
    "remote update request build failed": "clusterEventUpdateBuildFailed",
    "remote update unreachable": "clusterEventUpdateUnreachable",
    "remote agent update rejected": "clusterEventUpdateRejected",
    "triggering remote agent update": "clusterEventUpdateRunning",
    "remote agent update accepted": "clusterEventUpdateAccepted",
  });

  function localizeClusterEventPhase(phase) {
    const key = clusterEventPhaseKeys[String(phase || "").trim()];
    return key ? t(key) : String(phase || "");
  }

  function localizeClusterEventStatus(status) {
    const key = clusterEventStatusKeys[String(status || "").trim()];
    return key ? t(key) : String(status || "");
  }

  function localizeClusterEventMessage(item) {
    const raw = String(item?.message || "").trim();
    const key = clusterEventMessageKeys[raw];
    return key ? t(key) : raw;
  }

  function streamSectionKey() {
    const section = String(state.section || "").trim() || "overview";
    const params = new URLSearchParams({
      section,
      event_feed: "1",
      overview: section === "overview" ? "1" : "0",
    });
    if (["overview", "security"].includes(section) && state.nodeId) params.set("node", state.nodeId);
    if (section === "management") params.set("settings_scope", state.managementScope);
    if (section === "security") {
      params.set("feature", state.securityFeature || "overview");
      if (state.selectedInterface) params.set("iface", state.selectedInterface);
      params.set("direction", state.direction === "egress" ? "egress" : "ingress");
    }
    if (section === "overview") {
      params.set("direction", state.direction === "egress" ? "egress" : "ingress");
    }
    if (section === "monitoring") {
      for (const [key, value] of monitoringHistoryParams()) params.set(key, value);
    }
    return params.toString();
  }

  function syncSectionEventStream() {
    if (disposed) return;
    if (state.section !== "security" || !["overview", "malware"].includes(state.securityFeature)) {
      stopSecurityScanEventStream();
    }
    const nextKey = streamSectionKey();
    if (!nextKey) {
      stopClusterEventStream();
      stopSecurityScanEventStream();
      return;
    }
    if (clusterEventSource && clusterEventStreamKey === nextKey) return;
    startClusterEventStream(nextKey);
  }

  function setManagementScope(scope) {
    state.managementScope = scope === "node" ? "node" : "global";
    if (state.section === "management") syncSectionEventStream();
  }

  function sectionStreamActive() {
    if (!clusterEventSource || clusterEventStreamKey !== streamSectionKey()) return false;
    // An EventSource object exists while it is still connecting or when a
    // malformed/partial frame left the firewall view without its current
    // interface summary. Keep the HTTP path as a recovery path until the
    // selected view has a usable summary.
    if (state.section === "overview") return state.interfaceDataStatus === "ready";
    if (state.section === "security" && ["overview", "firewall"].includes(state.securityFeature)) {
      return state.interfaceDataStatus === "ready" && Boolean(currentPolicy.value);
    }
    if (state.section === "events") return state.eventCenter.ready;
    return true;
  }

  function startClusterEventStream(streamKey = streamSectionKey()) {
    if (disposed) return;
    stopClusterEventStream();
    state.consoleRevision = 0;
    if (typeof window === "undefined" || typeof window.EventSource === "undefined") return;
    // The first SSE frame contains the server's recent event history. Treat it
    // as the baseline so a page refresh does not replay every old operation as
    // a new toast. Only events arriving after this baseline are notifications.
    clusterEventStreamReady = false;
    clusterEventStreamKey = streamKey;
    const source = new window.EventSource(`/events/cluster?${streamKey}`);
    clusterEventSource = source;
    source.addEventListener("nodes", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const next = JSON.parse(event.data || "[]");
        if (!Array.isArray(next)) return;
        const previousNodeID = state.nodeId;
        const previousNodeIDs = new Set((state.nodes || []).map((item) => item?.id).filter(Boolean));
        const nextNodeIDs = new Set(next.map((item) => item?.id).filter(Boolean));
        const membershipChanged = previousNodeIDs.size !== nextNodeIDs.size
          || [...previousNodeIDs].some((id) => !nextNodeIDs.has(id));
        nodesRefreshToken++;
        state.nodes = next;
        state.nodesLoaded = true;
        pruneEventCenterNodes();
        const selectedStillExists = state.nodes.some((item) => item.id === previousNodeID);
        const nextNodeID = selectedStillExists ? previousNodeID : (state.nodes[0]?.id || "");
        if (nextNodeID !== previousNodeID) {
          // A different browser can remove the selected Agent. Reuse the
          // normal node-switch reset so the event center cannot retain that
          // Agent's SSH or scan records after the cluster snapshot changes.
          setNode(nextNodeID).catch(handleError);
          return;
        }
        if (membershipChanged) {
          refreshEventsData().catch(handleError);
          if (state.section === "security") refreshPersistedLogs().catch(handleError);
        }
        // Node protection status arrives on the explicit cluster page stream.
      } catch (_) {
        // ignore parse errors from partial stream frames
      }
    });
    source.addEventListener("overview", (event) => {
      if (clusterEventSource !== source) return;
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
    source.addEventListener("overview_data", (event) => {
      if (clusterEventSource !== source) return;
      try { applyOverviewSnapshot(JSON.parse(event.data || "{}")); } catch (_) {}
    });
    source.addEventListener("cluster", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const payload = JSON.parse(event.data || "{}");
        if (!payload || typeof payload !== "object" || state.section !== "cluster") return;
        state.nodeProtection = payload;
        for (const [id, item] of Object.entries(payload)) {
          state.nodeReachability[id] = item?.reachable !== false && item?.protection_status !== "unavailable";
        }
      } catch (_) {
        // Keep the last complete cluster protection snapshot on malformed data.
      }
    });
    source.addEventListener("monitoring", (event) => {
      if (clusterEventSource !== source) return;
      try {
        applyMonitoringSnapshot(JSON.parse(event.data || "{}"));
      } catch (_) {
        // Ignore malformed frames and keep the last completed sample visible.
      }
    });
    source.addEventListener("security", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const payload = JSON.parse(event.data || "{}");
        if (!payload || typeof payload !== "object" || state.section !== "security" || !acceptConsoleSnapshot(payload)) return;
        if (state.securityFeature === "overview" && payload.events) applyEventCenterSnapshot(payload.events);
        const items = Array.isArray(payload.nodes) ? payload.nodes : [];
        const selected = items.find((item) => String(item?.node_id || "") === String(state.nodeId || ""));
        if (items.length) {
          state.securityOverviewNodes = items.map((item) => ({
            id: item.node_id || item.id || "",
            name: item.name || item.node_id || item.id || "",
            summary: item.summary || {},
            scan: item.scan || { status: "idle", findings: [] },
            ssh: item.ssh || {},
            activity: Array.isArray(item.sshActivity?.records) ? item.sshActivity.records : (Array.isArray(item.activity) ? item.activity : []),
          }));
        }
        if (!selected) return;
        if (selected.status === "offline") {
          state.nodeReachability[state.nodeId] = false;
          state.interfaceDataStatus = "unavailable";
          state.health = { node_id: state.nodeId, status: "unavailable", interfaces: [] };
          state.sshProtection = { ...state.sshProtection, loading: false, settings: { ...state.sshProtection.settings, enabled: null } };
          return;
        }
        state.nodeReachability[state.nodeId] = true;
        if (selected.summary) state.securitySummary = { ...state.securitySummary, ...selected.summary, scan: selected.scan || state.securitySummary.scan };
        if (selected.scan) {
          applySecurityScan(selected.scan);
          if (selected.scan.status === "running" && state.section === "security") startSecurityScanEventStream(state.nodeId);
          else if (state.section === "security") stopSecurityScanEventStream();
        }
        const previousInterface = currentInterface.value;
        const resolvedInterface = selected.interface || selected.current?.policy?.interface;
        if (Array.isArray(selected.inventory?.interfaces)) {
          state.inventory = selected.inventory;
          state.interfaces = selected.inventory.interfaces;
          state.recommendedInterface = selected.inventory.recommended || "";
          if (!state.interfaces.some((item) => item.name === state.defaultInterface)) {
            state.defaultInterface = state.recommendedInterface || state.interfaces[0]?.name || "";
          }
        }
        if (!state.selectedInterface && resolvedInterface) state.defaultInterface = resolvedInterface;
        if (previousInterface !== currentInterface.value) resetInterfaceData();

        // A stream can return another NIC when collecting a default or when
        // an older Web falls back to the attached NIC. Keep the user's
        // explicit selection and apply only data belonging to that NIC.
        if (!state.selectedInterface || resolvedInterface === state.selectedInterface) {
          if (resolvedInterface && !state.interfaces.some(item => item.name === resolvedInterface)) {
            state.interfaces = [...state.interfaces, { name: resolvedInterface }];
          }
          if (selected.current && applyInterfaceSummary(selected.current, false)) {
            refreshCurrentToken++;
          } else if (selected.interface_status && selected.interface_status !== "ready"
            && state.interfaceDataStatus !== "ready") {
            state.interfaceDataStatus = selected.interface_status;
          }
        }
        // Apply independent health after the summary, whose optional health
        // field may be missing while inventory or rule collection is delayed.
        if (selected.health && typeof selected.health === "object") state.health = selected.health;
        if (selected.reports) {
          if (Array.isArray(selected.reports.reports)) state.securityScanReports = selected.reports.reports;
          state.securityScanArchiveError = selected.reports.archive_error || "";
        }
        if (selected.quarantine) state.securityQuarantine = {
          root: selected.quarantine.root || "",
          entries: Array.isArray(selected.quarantine.entries) ? selected.quarantine.entries : [],
          node_id: state.nodeId,
        };
        if (selected.ssh) applySSHProtectionSnapshot(selected.ssh);
        if (selected.ssh_settings_etag) state.sshSettingsETag = selected.ssh_settings_etag;
        if (Array.isArray(selected.sshKeys?.keys)) state.sshProtection.keys = selected.sshKeys.keys;
        if (Array.isArray(selected.sshActivity?.records)) state.sshProtection.activity = selected.sshActivity.records;
        syncSectionEventStream();
      } catch (_) {
        // Keep the last complete security snapshot when a frame is malformed.
      }
    });
    source.addEventListener("events", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const payload = JSON.parse(event.data || "{}");
        applyEventCenterSnapshot(payload);
      } catch (_) {
        // Keep the last complete event snapshot when a frame is malformed.
      }
    });
    source.addEventListener("settings", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const payload = JSON.parse(event.data || "{}");
        if (!payload || typeof payload !== "object" || state.section !== "management") return;
        if (!acceptConsoleSnapshot(payload)) return;
        for (const key of ["auth", "passkey", "smtp", "logging"]) {
          if (!payload[key]) continue;
          state[`${key}Settings`] = { ...state[`${key}Settings`], ...payload[key] };
          if (payload.settings_etags?.[key]) state.settingsETags[key] = payload.settings_etags[key];
          state.settingsLoaded[key] = true;
        }
        if (payload.logging_node_id) state.loggingNodeID = payload.logging_node_id;
        if (payload.node_protection && typeof payload.node_protection === "object") {
          state.nodeProtection = payload.node_protection;
          for (const [id, item] of Object.entries(payload.node_protection)) {
            state.nodeReachability[id] = item?.reachable !== false && item?.protection_status !== "unavailable";
          }
        }
      } catch (_) {
        // Keep the last complete settings snapshot when a frame is malformed.
      }
    });
    source.addEventListener("node_delete", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const next = JSON.parse(event.data || "[]");
        if (!Array.isArray(next)) return;
        state.nodeDeleteEvents = next;
        if (!clusterEventStreamReady) {
          for (const item of next) {
            const id = String(item?.id || "");
            if (id) deleteEventSeen.add(id);
          }
          clusterEventStreamReady = true;
          return;
        }
        const recent = next.slice(-10);
        for (const item of recent) {
          const id = String(item?.id || "");
          if (!id || deleteEventSeen.has(id)) continue;
          deleteEventSeen.add(id);
          const nodeId = String(item?.node_id || "");
          const phase = String(item?.phase || "");
          const status = String(item?.status || "");
          const message = localizeClusterEventMessage(item);
          if (!nodeId) continue;
          const phaseLabel = localizeClusterEventPhase(phase);
          const statusLabel = localizeClusterEventStatus(status);
          setNotice(`[${nodeId}] ${phaseLabel}/${statusLabel} ${message}`.trim(), status === "failed" ? "error" : "info");
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
    source.addEventListener("event_dispositions", (event) => {
      if (clusterEventSource !== source) return;
      try {
        const payload = JSON.parse(event.data || "[]");
        const revision = Number(payload?.revision || 0);
        if (revision > 0 && state.eventDispositionRevision > 0 && revision < state.eventDispositionRevision) return;
        const next = Array.isArray(payload) ? payload : payload?.dispositions;
        if (!Array.isArray(next)) return;
        const mapped = {};
        for (const item of next) {
          const eventID = String(item?.event_id || "").trim();
          const nodeID = String(item?.node_id || "").trim();
          if (!eventID || !nodeID) continue;
          mapped[eventDispositionKey(nodeID, eventID)] = item;
        }
        state.eventDispositions = mapped;
        state.eventDispositionsLoaded = true;
        if (revision > 0) state.eventDispositionRevision = revision;
      } catch (_) {
        // ignore parse errors from partial stream frames
      }
    });
    source.onerror = () => {
      if (clusterEventSource !== source) return;
      stopClusterEventStream();
      // A proxy may expose the console but reject long-lived SSE. One
      // bounded page refresh keeps the last usable state while reconnecting;
      // normal browsers stay entirely on the stream path.
      if (["overview", "monitoring", "events", "security", "management"].includes(state.section)) {
        queueSectionRefresh(state.section, { fromStream: true }).catch(handleError);
      }
      refreshEventsData().catch(handleError);
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

  function applyOverviewSnapshot(payload) {
    if (!payload || typeof payload !== "object" || state.section !== "overview") return false;
    if (payload.events) applyEventCenterSnapshot(payload.events); // Older managers nest the feed.
    if ((payload.node_id && payload.node_id !== state.nodeId)
      || (payload.direction && payload.direction !== state.direction)
      || !acceptConsoleSnapshot(payload)) return false;
    overviewDataGeneration++;
    refreshCurrentToken++;
    if (payload.inventory && Array.isArray(payload.inventory.interfaces)) {
      state.inventory = payload.inventory;
      state.interfaces = payload.inventory.interfaces;
      state.recommendedInterface = payload.inventory.recommended || "";
    }
    const resolvedInterface = payload.interface || payload.current?.policy?.interface;
    const sameInterface = !resolvedInterface || resolvedInterface === currentInterface.value;
    if (resolvedInterface) {
      state.defaultInterface = resolvedInterface;
      if (!state.interfaces.some(item => item.name === resolvedInterface)) state.interfaces = [...state.interfaces, { name: resolvedInterface }];
    }
    if (payload.current && typeof payload.current === "object") applyInterfaceSummary(payload.current, false);
    // Agent health is independent of the time spent reading rules and other
    // cards. Use it even when those optional probes were incomplete.
    if (payload.health && typeof payload.health === "object") state.health = payload.health;
    if (typeof payload.protection_status === "string") state.overviewProtectionStatus = payload.protection_status;
    else if (payload.health || !sameInterface) state.overviewProtectionStatus = "";
    if (payload.interface_status && !(sameInterface && state.interfaceDataStatus === "ready"
      && payload.interface_status === "unavailable" && payload.reachable !== false)) {
      state.interfaceDataStatus = payload.interface_status;
    }
    if (typeof payload.reachable === "boolean") state.nodeReachability[state.nodeId] = payload.reachable;
    if (Array.isArray(payload.logs)) state.persistedLogs = payload.logs;
    const selected = payload.security;
    if (selected?.node_id === state.nodeId) {
      if (selected.summary) state.securitySummary = { ...state.securitySummary, ...selected.summary, scan: selected.scan || state.securitySummary.scan };
      if (selected.scan) applySecurityScan(selected.scan);
      if (selected.ssh) applySSHProtectionSnapshot(selected.ssh);
      if (Array.isArray(selected.sshActivity?.records)) state.sshProtection.activity = selected.sshActivity.records;
    }
    return true;
  }

  async function refreshOverviewData(nodeSwitch) {
    const node = state.nodeId;
    if (!node) return;
    const direction = state.direction;
    const generation = overviewDataGeneration;
    const current = () => !disposed && state.section === "overview" && node === state.nodeId
      && direction === state.direction && generation === overviewDataGeneration;
    const query = new URLSearchParams({ node, direction });
    const snapshot = await request(`/overview/snapshot?${query}`, { cache: "no-store", key: "overview:snapshot" }).catch(() => null);
    if (!current()) return;
    if (snapshot?.node_id === node && applyOverviewSnapshot(snapshot)) return;
    // Older managers have the individual interface/security endpoints only.
    await Promise.all([
      (async () => {
        await refreshInventory();
        if (current()) await queueRefreshCurrent();
      })(),
      refreshOverviewSecurityData({ nodeID: nodeSwitch ? node : "" }),
    ]);
  }

  function monitoringHistoryParams() {
    const { node, range, from, to } = state.monitoringStreamQuery;
    const params = new URLSearchParams({ range: String(range) });
    if (node) params.set("node", node);
    if (from && to) {
      params.set("from", from);
      params.set("to", to);
    }
    return params;
  }

  function applyMonitoringSnapshot(payload) {
    const query = state.monitoringStreamQuery;
    if (state.section !== "monitoring" || payload?.scope !== query.scope || (payload.node_id || "") !== query.node) return false;
    if (!Array.isArray(payload.points) || !Array.isArray(payload.nodes)) return false;
    monitoringDataGeneration++;
    state.monitoringHistory = payload;
    state.monitoringHistoryError = "";
    return true;
  }

  async function refreshMonitoringHistory() {
    if (disposed || state.section !== "monitoring") return;
    const query = monitoringHistoryParams().toString();
    const generation = monitoringDataGeneration;
    const payload = await request(`/monitoring/history?${query}`, { cache: "no-store", key: "monitoring:history" }).catch(() => null);
    if (disposed || state.section !== "monitoring" || generation !== monitoringDataGeneration || query !== monitoringHistoryParams().toString()) return;
    if (!applyMonitoringSnapshot(payload)) state.monitoringHistoryError = t("monitoringHistoryUnavailable");
  }

  async function refreshNodes() {
    const refreshToken = ++nodesRefreshToken;
    const previousNodeID = state.nodeId;
    const response = await request("/nodes", { cache: "no-store" }).catch(() => null);
    if (refreshToken !== nodesRefreshToken) return state.nodes;
    // A transient node-list failure must not clear the selected host or make
    // the event center appear empty. A successful empty list still clears it.
    if (!response) return state.nodes;
    const nodes = Array.isArray(response) ? response : response.nodes;
    if (!Array.isArray(nodes)) return state.nodes;
    state.nodes = nodes;
    state.nodesLoaded = true;
    pruneEventCenterNodes();
    if (!state.nodes.some((item) => item.id === state.nodeId)) {
      state.nodeId = state.nodes[0]?.id || "";
    }
    if (state.nodeId !== previousNodeID) {
      resetInterfaceData();
      state.selectedInterface = "";
      state.defaultInterface = "";
      state.recommendedInterface = "";
      state.interfaces = [];
      state.inventory = { interfaces: [], recommended: "" };
      state.overviewProtectionStatus = "";
      state.health = { interfaces: [] };
      resetNodeScopedSecurityData(state.nodeId);
    }
    writeNodeToLocation(state.nodeId);
    return nodes;
  }

  async function refreshNodeProtections() {
    const nodes = [...state.nodes];
    const currentIDs = new Set(nodes.map((item) => item.id));
    for (const id of Object.keys(state.nodeProtection)) {
      if (!currentIDs.has(id)) delete state.nodeProtection[id];
    }
    for (const id of Object.keys(state.nodeReachability)) {
      if (!currentIDs.has(id)) delete state.nodeReachability[id];
    }
    await Promise.all(nodes.map(async (item) => {
      const id = String(item.id || "");
      if (!id) return;
      if (nodeProtectionInFlight.has(id)) return nodeProtectionInFlight.get(id);
      if (!state.nodeProtection[id]) state.nodeProtection[id] = { protection_status: "loading" };
      const pending = request(`/nodes/${encodeURIComponent(id)}/protection-status`, { timeoutMs: 4000 })
        .then((result) => {
          const current = state.nodes.find((node) => node.id === id);
          if (!current) return;
          const reachable = result?.connection_status
            ? result.connection_status === "reachable"
            : result?.protection_status !== "unavailable";
          state.nodeReachability[id] = reachable;
          state.nodeProtection[id] = result;
        })
        .catch((error) => {
          state.nodeReachability[id] = false;
          if (state.nodes.some((node) => node.id === id)) state.nodeProtection[id] = { protection_status: "unavailable", reason: error?.message || "" };
        })
        .finally(() => nodeProtectionInFlight.delete(id));
      nodeProtectionInFlight.set(id, pending);
      return pending;
    }));
  }

  async function refreshInventory() {
    const nodeID = state.nodeId;
    let inventory = await (nodeID
      ? request(`/nodes/${nodeID}/interfaces`).catch(() => ({ interfaces: [], recommended: "" }))
      : Promise.resolve({ interfaces: [], recommended: "" }));
    // Inventory is an auxiliary endpoint and can be slow while the Agent is
    // enumerating devices. The protection-status endpoint already probes the
    // authoritative health snapshot, so use its attached interface to keep
    // the firewall editor usable instead of rendering an empty selector.
    if (nodeID && (!Array.isArray(inventory?.interfaces) || inventory.interfaces.length === 0)) {
      const fallback = await request(`/nodes/${encodeURIComponent(nodeID)}/protection-status`).catch(() => null);
      const iface = String(fallback?.interface || "").trim();
      if (iface) {
        inventory = {
          interfaces: [{ name: iface, is_physical: true, is_recommended: true, attached: true }],
          recommended: iface,
        };
      }
    }
    // A quick second switch can finish the first Agent request later. Do not
    // let that stale response overwrite the newly selected node's inventory.
    if (nodeID !== state.nodeId) return inventory;
    state.inventory = inventory;
    state.interfaces = inventory.interfaces || [];
    state.recommendedInterface = inventory.recommended || state.recommendedInterface;
    return inventory;
  }

  async function refreshPersistedLogs() {
    const refreshToken = ++persistedLogsRefreshToken;
    const persistedLogs = await request("/logs/drop?limit=500").catch(() => ({ logs: [] }));
    if (refreshToken !== persistedLogsRefreshToken) return persistedLogs;
    state.persistedLogs = persistedLogs.logs || [];
    state.selection.clear();
    return persistedLogs;
  }

  function pruneEventCenterNodes() {
    if (!state.nodesLoaded) return;
    const enrolled = new Set(state.nodes.map((node) => node.id));
    state.eventCenter = { ...state.eventCenter,
      nodes: state.eventCenter.nodes.filter((node) => enrolled.has(node.node_id)),
      logs: state.eventCenter.logs.filter((log) => enrolled.has(log.node_id)),
    };
  }

  function applyEventCenterSnapshot(payload) {
    if (payload?.scope !== "cluster" || !Array.isArray(payload.nodes) || !Array.isArray(payload.logs)) return false;
    const revision = Number(payload.revision || 0);
    const generatedAt = Date.parse(payload.generated_at || "") || 0;
    const previousAt = Date.parse(state.eventCenter.generated_at || "") || 0;
    if (generatedAt && previousAt) {
      if (generatedAt < previousAt) return false;
      // Revision counters restart with the manager Web process. The same
      // timestamp still needs revision ordering across HTTP and SSE.
      if (generatedAt === previousAt && revision < state.eventsRevision) return false;
    } else if (revision < state.eventsRevision) return false;
    if (generatedAt && generatedAt === previousAt && revision === state.eventsRevision && !state.eventCenter.error) return true;
    state.eventsRevision = revision;
    eventsDataGeneration++;
    state.eventCenter = { ...payload, ready: true, error: "" };
    pruneEventCenterNodes();
    return true;
  }

  async function refreshEventsData() {
    if (disposed) return;
    if (eventsRefreshInFlight) return eventsRefreshInFlight;
    const generation = eventsDataGeneration;
    eventsRefreshInFlight = request("/events/snapshot", { cache: "no-store", timeoutMs: 12000 })
      .catch(() => null)
      .then((payload) => {
        // The feed belongs to the cluster. Route and node changes must not
        // cancel it, but a newer event frame already applied takes priority.
        if (disposed || generation !== eventsDataGeneration) return;
        if (!applyEventCenterSnapshot(payload) && !state.eventCenter.ready) {
          state.eventCenter.error = t("eventsFeedUnavailable");
        }
      }).finally(() => { eventsRefreshInFlight = null; });
    return eventsRefreshInFlight;
  }

  async function refreshEventDispositions() {
    const refreshToken = ++eventDispositionRefreshToken;
    const mutationGeneration = eventDispositionMutationGeneration;
    const payload = await request("/events/dispositions").catch((error) => {
      if (refreshToken === eventDispositionRefreshToken && !state.eventDispositionsLoaded) {
        legacyDispositionEndpoint = [404, 405].includes(error.status);
      }
      return null;
    });
    if (!payload || !Array.isArray(payload.dispositions)) return false;
    // A refresh may have started before a local mutation completed. Applying
    // that older snapshot would make the table briefly revert after a batch
    // action. The next SSE frame or explicit refresh will reconcile it.
    if (refreshToken !== eventDispositionRefreshToken || eventDispositionPending.size > 0 || mutationGeneration !== eventDispositionMutationGeneration) return false;
    const revision = Number(payload.revision || 0);
    if (revision > 0 && revision < state.eventDispositionRevision) return false;
    const mapped = {};
    for (const item of payload.dispositions) {
      const eventID = String(item?.event_id || "").trim();
      const nodeID = String(item?.node_id || "").trim();
      if (!eventID || !nodeID) continue;
      mapped[eventDispositionKey(nodeID, eventID)] = item;
    }
    state.eventDispositions = mapped;
    state.eventDispositionsLoaded = true;
    if (revision > 0) state.eventDispositionRevision = revision;
    return true;
  }

  async function updateEventDisposition(eventID, nodeID, source, status) {
    const id = String(eventID || "").trim();
    const node = String(nodeID || "").trim();
    const nextStatus = String(status || "open").trim();
    if (!id || !node) throw new Error("event disposition requires event and node");
    const payload = { node_id: node, source: String(source || "firewall").trim(), status: nextStatus };
    const key = eventDispositionKey(node, id);
    eventDispositionMutationGeneration += 1;
    const mutationID = (eventDispositionMutationSequence.get(key) || 0) + 1;
    eventDispositionMutationSequence.set(key, mutationID);
    eventDispositionPending.set(key, mutationID);
    try {
      const response = await request(`/events/dispositions/${encodeURIComponent(id)}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      if (eventDispositionMutationSequence.get(key) === mutationID) {
        if (nextStatus === "open") {
          const next = { ...state.eventDispositions };
          delete next[key];
          state.eventDispositions = next;
        } else if (response?.disposition) {
          state.eventDispositions = { ...state.eventDispositions, [key]: response.disposition };
        }
        const revision = Number(response?.revision || 0);
        if (revision > state.eventDispositionRevision) state.eventDispositionRevision = revision;
      }
      state.eventDispositionsLoaded = true;
      return response;
    } catch (error) {
      // On a manager that supports dispositions, a 404 can mean that the
      // node was removed. Only fall back after the list endpoint is missing.
      if (!legacyDispositionEndpoint || state.eventDispositionsLoaded || ![404, 405].includes(error.status)) throw error;
      if (eventDispositionMutationSequence.get(key) === mutationID) {
        const next = new Map(localEventStatuses.value);
        if (nextStatus === "open") next.delete(id);
        else next.set(id, nextStatus);
        window.localStorage?.setItem?.(LEGACY_EVENT_STATUS_KEY, JSON.stringify([...next].slice(-500)));
        localEventStatuses.value = next;
      }
    } finally {
      if (eventDispositionPending.get(key) === mutationID) eventDispositionPending.delete(key);
    }
  }

  async function refreshManagementSettings(options = {}) {
    if (options.nodeOnly) return;
    const refreshToken = ++managementSettingsRefreshToken;
    const mutationSnapshot = { ...managementSettingsMutationToken };
    const settings = [
      ["logging", "loggingSettings"],
      ["auth", "authSettings"],
      ["passkey", "passkeySettings"],
      ["smtp", "smtpSettings"],
    ];
    await Promise.all(settings.map(async ([endpoint, key]) => {
      let stale = false;
      try {
        const value = await request(`/settings/${endpoint}`, { cache: "no-store", onResponse: (response) => {
          const revision = response?.headers?.get("X-NodeWall-Revision");
          stale = revision !== null && revision !== undefined && Number(revision) < state.consoleRevision;
          if (!stale && refreshToken === managementSettingsRefreshToken && mutationSnapshot[endpoint] === managementSettingsMutationToken[endpoint]) captureConfigurationResponse(response, endpoint);
        } });
        if (stale || refreshToken !== managementSettingsRefreshToken || mutationSnapshot[endpoint] !== managementSettingsMutationToken[endpoint]) return;
        state[key] = { ...state[key], ...value };
        state.settingsLoaded[endpoint] = true;
      } catch (_) {
        // A failed endpoint must not clear the other usable settings forms.
      }
    }));
  }

  async function refreshUsers() {
    const response = await request("/auth/users").catch(() => null);
    if (response && Array.isArray(response.users)) state.users = response.users;
  }

  async function refreshAccountSecurity() {
    state.accountSecurity.loading = true;
    try {
      const security = await request("/account/security");
      state.accountSecurity = {
        ...state.accountSecurity,
        ...security,
        loading: false,
        setup: null,
      };
      const passkeys = await request("/account/passkeys").catch(() => ({ passkeys: [] }));
      state.accountSecurity.passkey_list = Array.isArray(passkeys?.passkeys) ? passkeys.passkeys : [];
      state.accountSecurity.passkeys = state.accountSecurity.passkey_list.length;
      return security;
    } catch (error) {
      state.accountSecurity.loading = false;
      throw error;
    }
  }

  async function saveManagementSettings(endpoint, draft, options = {}) {
    const mutationToken = ++managementSettingsMutationToken[endpoint];
    const payload = { ...(draft || state[`${endpoint}Settings`]) };
    if (endpoint === "smtp" && !String(payload.password || "").trim()) delete payload.password;
    if (endpoint === "passkey") {
      if (payload.tls_mode === "proxy" || !String(payload.certificate_pem || "").trim()) delete payload.certificate_pem;
      if (payload.tls_mode === "proxy" || !String(payload.private_key_pem || "").trim()) delete payload.private_key_pem;
    }
    const etag = options.etag ?? state.settingsETags[endpoint];
    const result = await request(`/settings/${endpoint}`, {
      method: "PUT",
      headers: etag ? { "If-Match": etag } : {},
      body: JSON.stringify(payload),
      onResponse: (response) => captureConfigurationResponse(response, endpoint),
    });
    if (mutationToken !== managementSettingsMutationToken[endpoint]) return result;
    const cleared = endpoint === "smtp" ? { password: "" } : endpoint === "passkey" ? { certificate_pem: "", private_key_pem: "" } : {};
    state[`${endpoint}Settings`] = { ...state[`${endpoint}Settings`], ...result, ...cleared };
    state.settingsLoaded[endpoint] = true;
    return state[`${endpoint}Settings`];
  }

  function acceptConsoleSnapshot(payload) {
    if (!Number.isFinite(payload?.revision)) return true;
    if (payload.revision < state.consoleRevision) return false;
    state.consoleRevision = payload.revision;
    return true;
  }

  function captureConfigurationResponse(response, endpoint) {
    const revision = Number(response?.headers?.get("X-NodeWall-Revision") || 0);
    state.consoleRevision = Math.max(state.consoleRevision, revision);
    const etag = response?.headers?.get("ETag");
    if (etag && endpoint) state.settingsETags[endpoint] = etag;
    if (etag && !endpoint) state.sshSettingsETag = etag;
  }

  async function saveSMTPSettings(draft, options) {
    const result = await saveManagementSettings("smtp", draft, options);
    setNotice(t("smtpSaved"), "success");
    return result;
  }

  async function testSMTP(to = "") {
    await request("/settings/smtp/test", { method: "POST", body: JSON.stringify({ to }) });
    setNotice(t("smtpTestSent"), "success");
  }

  async function setupOTP(currentPassword) {
    const password = String(currentPassword !== undefined ? currentPassword : state.forms.otpCurrentPassword || "").trim();
    if (!password) throw new Error(t("otpCurrentPasswordRequired"));
    const setup = await request("/account/otp/setup", {
      method: "POST",
      body: JSON.stringify({ current_password: password }),
    });
    state.accountSecurity.setup = setup;
    state.forms.otpCurrentPassword = "";
    setNotice(t("otpSetupReady"), "success");
    return setup;
  }

  async function verifyOTP() {
    const code = String(state.forms.otpCode || "").trim();
    if (!code) throw new Error(t("otpCodeRequired"));
    const result = await request("/account/otp/verify", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
    state.accountSecurity.recovery_codes = result.recovery_codes || [];
    state.accountSecurity.setup = null;
    state.forms.otpCode = "";
    await refreshAccountSecurity();
    setNotice(t("otpEnabled"), "success");
    return result;
  }

  async function disableOTP(currentPassword, otpCode) {
    const password = String(currentPassword !== undefined ? currentPassword : state.forms.otpDisablePassword || "").trim();
    const code = String(otpCode !== undefined ? otpCode : state.forms.otpDisableCode || "").trim();
    if (!password || !code) throw new Error(t("otpDisableRequired"));
    await request("/account/otp/disable", {
      method: "POST",
      body: JSON.stringify({ current_password: password, code }),
    });
    state.forms.otpDisablePassword = "";
    state.forms.otpDisableCode = "";
    state.accountSecurity.recovery_codes = [];
    await refreshAccountSecurity();
    setNotice(t("otpDisabled"), "info");
  }

  async function requestEmailVerification() {
    const email = String(state.forms.email || "").trim();
    const password = String(state.forms.emailPassword || "").trim();
    if (!email || !password) throw new Error(t("emailVerificationRequired"));
    const result = await request("/account/email/request", {
      method: "POST",
      body: JSON.stringify({ email, current_password: password }),
    });
    state.forms.emailRequestID = result.request_id || "";
    state.forms.emailPassword = "";
    setNotice(t("emailVerificationSent"), "success");
    return result;
  }

  async function confirmEmailVerification() {
    const requestID = String(state.forms.emailRequestID || "").trim();
    const code = String(state.forms.emailCode || "").trim();
    if (!requestID || !code) throw new Error(t("emailCodeRequired"));
    const result = await request("/account/email/confirm", {
      method: "POST",
      body: JSON.stringify({ request_id: requestID, code }),
    });
    state.forms.emailCode = "";
    await refreshAccountSecurity();
    setNotice(t("emailVerified"), "success");
    return result;
  }

  async function registerPasskey(currentPassword) {
    if (!window?.PublicKeyCredential || !navigator?.credentials) throw new Error(t("passkeyBrowserUnsupported"));
    if (!state.accountSecurity.passkey_enabled) throw new Error(t("passkeyDisabled"));
    const hostname = String(window.location.hostname || "").trim();
    const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    if (!window.isSecureContext || isIPv4) throw new Error(t("passkeyOriginRequired"));
    const password = String(currentPassword !== undefined ? currentPassword : state.forms.passkeyPassword || "").trim();
    if (!password) throw new Error(t("passkeyPasswordRequired"));
    const optionsPayload = await request("/account/passkeys/register/options", {
      method: "POST",
      body: JSON.stringify({ current_password: password, name: state.forms.passkeyName || "" }),
    });
    let credential;
    try {
      credential = await navigator.credentials.create({ publicKey: webAuthnPublicKeyOptions(optionsPayload) });
    } catch (error) {
      const name = String(error?.name || "");
      if (name === "SecurityError" || name === "NotSupportedError") throw new Error(t("passkeyOriginRequired"));
      if (name === "NotAllowedError") throw new Error(t("passkeyRegistrationFailed"));
      throw error;
    }
    if (!credential) throw new Error(t("passkeyRegistrationCancelled"));
    await request("/account/passkeys/register/verify", {
      method: "POST",
      body: JSON.stringify(serializeWebAuthnCredential(credential)),
    });
    state.forms.passkeyName = "";
    state.forms.passkeyPassword = "";
    await refreshAccountSecurity();
    setNotice(t("passkeyRegistered"), "success");
  }

  async function deletePasskey(id, currentPassword) {
    const password = String(currentPassword !== undefined ? currentPassword : state.forms.passkeyPassword || "").trim();
    if (!password) throw new Error(t("passkeyPasswordRequired"));
    await request(`/account/passkeys/${encodeURIComponent(id)}/delete`, {
      method: "POST",
      body: JSON.stringify({ current_password: password }),
    });
    state.forms.passkeyPassword = "";
    await refreshAccountSecurity();
    setNotice(t("passkeyDeleted"), "info");
  }

  function applySSHProtectionSnapshot(snapshot, nodeID = state.nodeId) {
    const previous = state.sshProtection;
    const blocks = snapshot?.active_blocks;
    let activeBlocks = previous.active_blocks;
    // Go serializes a nil slice as null when the last block has expired.
    // A partial status update may omit the field and should keep the count.
    if (blocks === null) activeBlocks = [];
    else if (Array.isArray(blocks)) activeBlocks = blocks;
    state.sshProtection = {
      ...previous,
      ...snapshot,
      loading: false,
      node_id: nodeID,
      settings: { ...previous.settings, ...snapshot?.settings },
      active_blocks: activeBlocks,
      ports: Array.isArray(snapshot?.ports) ? snapshot.ports : previous.ports,
      upload_security: { ...previous.upload_security, ...snapshot?.upload_security },
    };
  }

  // SSH protection belongs to the selected Agent. Security-page refreshes
  // must load it explicitly because they do not load the broader management
  // settings endpoint.
  async function refreshSSHProtectionData(nodeID = state.nodeId) {
    if (!nodeID) return;
    const encodedNode = encodeURIComponent(nodeID);
    await Promise.all([
      request(`/nodes/${encodedNode}/ssh-protection`, { onResponse: (response) => { if (nodeID === state.nodeId) captureConfigurationResponse(response); } }).then((sshProtection) => {
        if (nodeID !== state.nodeId) return;
        applySSHProtectionSnapshot(sshProtection, nodeID);
      }).catch(() => {
        if (nodeID === state.nodeId) state.sshProtection.loading = false;
      }),
      request(`/nodes/${encodedNode}/ssh-protection/activity?limit=100`).then((activity) => {
        if (nodeID === state.nodeId && Array.isArray(activity?.records)) state.sshProtection.activity = activity.records;
      }).catch(() => {}),
      request(`/nodes/${encodedNode}/ssh-protection/keys`).then((keys) => {
        if (nodeID === state.nodeId && Array.isArray(keys?.keys)) state.sshProtection.keys = keys.keys;
      }).catch(() => {}),
    ]);
  }

  async function refreshSecurityData() {
    if (!state.nodeId) return;
    const nodeID = state.nodeId;
    const node = encodeURIComponent(nodeID);
    const previousReports = state.securityScanReports;
    const onMalwarePage = () => state.section === "security" && state.securityFeature === "malware" && state.nodeId === nodeID;
    let scanReceived = false;
    const scanRevision = securityScanRevision;
    await Promise.all([
      request(`/nodes/${node}/security/summary`).then((summary) => {
        if (nodeID !== state.nodeId || (summary?.node_id && summary.node_id !== nodeID)) return;
        state.securitySummary = {
          ...state.securitySummary,
          ...summary,
          checks: Array.isArray(summary?.checks) ? summary.checks : state.securitySummary.checks,
          scan: scanReceived || scanRevision !== securityScanRevision ? state.securitySummary.scan : (summary?.scan || state.securitySummary.scan),
        };
        if (state.securitySummary.scan?.status === "running") scheduleSecurityScanPoll();
      }).catch(() => {}),
      request(`/nodes/${node}/security/scan`).then((scan) => {
        if (nodeID !== state.nodeId || (scan?.node_id && scan.node_id !== nodeID) || !scan?.status) return;
        scanReceived = true;
        if (scanRevision !== securityScanRevision) return;
        applySecurityScan(scan);
        if (scan.status === "running") scheduleSecurityScanPoll();
      }).catch(() => {}),
      refreshSecurityQuarantine().catch(() => {}),
      onMalwarePage() ? request(`/nodes/${node}/security/scan/reports`).then((result) => {
        // Keep the live archive list if an SSE frame arrived during this read.
        if (!onMalwarePage() || state.securityScanReports !== previousReports) return;
        state.securityScanReports = Array.isArray(result?.reports) ? result.reports : [];
        state.securityScanArchiveError = result?.archive_error || "";
      }).catch((error) => {
        if (onMalwarePage() && state.securityScanReports === previousReports) state.securityScanArchiveError = error.message;
      }) : Promise.resolve(),
    ]);
    return state.securitySummary;
  }

  async function refreshOverviewSecurityData(options = {}) {
    const requestedNodeID = String(options.nodeID || "").trim();
    const nodes = (state.nodes || [])
      .filter((item) => item?.id && (!requestedNodeID || item.id === requestedNodeID));
    const token = ++securityOverviewToken;
    const scanRevision = securityScanRevision;
    if (!nodes.length) {
      if (!requestedNodeID) state.securityOverviewNodes = [];
      return [];
    }

    const previous = new Map(state.securityOverviewNodes.map((item) => [item.id, item]));
    const initial = nodes.map((item) => ({
      id: item.id,
      name: item.name || item.id,
      summary: previous.get(item.id)?.summary || {},
      scan: previous.get(item.id)?.scan || { status: "idle", findings: [] },
      ssh: previous.get(item.id)?.ssh || {},
      activity: previous.get(item.id)?.activity || [],
    }));
    state.securityOverviewNodes = requestedNodeID
      ? [...state.securityOverviewNodes.filter((item) => item.id !== requestedNodeID), ...initial]
      : initial;

    const update = (id, patch, provisionalScan = false) => {
      if (token !== securityOverviewToken) return;
      state.securityOverviewNodes = state.securityOverviewNodes.map((item) => item.id === id ? { ...item, ...patch } : item);
      if (id !== state.nodeId) return;
      if (patch.summary) {
        const scan = state.securitySummary.scan;
        state.securitySummary = {
          ...state.securitySummary,
          ...patch.summary,
          checks: Array.isArray(patch.summary.checks) ? patch.summary.checks : state.securitySummary.checks,
          scan,
        };
      }
      if (patch.scan && scanRevision === securityScanRevision) {
        if (provisionalScan) state.securitySummary.scan = patch.scan;
        else applySecurityScan(patch.scan);
        if (patch.scan.status === "running") scheduleSecurityScanPoll();
      }
      if (patch.ssh) applySSHProtectionSnapshot(patch.ssh, id);
      if (patch.activity) state.sshProtection.activity = patch.activity;
    };

    await Promise.all(nodes.map(async (item) => {
      const node = encodeURIComponent(item.id);
      let scanReceived = false;
      await Promise.all([
        request(`/nodes/${node}/security/summary`).then((summary) => {
          if (summary?.node_id && summary.node_id !== item.id) return;
          update(item.id, { summary, ...(!scanReceived && summary?.scan ? { scan: summary.scan } : {}) }, true);
        }).catch(() => {}),
        request(`/nodes/${node}/security/scan`).then((scan) => {
          if ((scan?.node_id && scan.node_id !== item.id) || !scan?.status) return;
          scanReceived = true;
          update(item.id, { scan });
        }).catch(() => {}),
        request(`/nodes/${node}/ssh-protection`).then((ssh) => update(item.id, { ssh })).catch(() => {}),
        request(`/nodes/${node}/ssh-protection/activity?limit=100`).then((activity) => {
          if (Array.isArray(activity?.records)) update(item.id, { activity: activity.records });
        }).catch(() => {}),
      ]);
    }));
    return state.securityOverviewNodes;
  }

  function applySecurityScan(scan) {
    const previous = state.securitySummary.scan;
    const previousFindingState = securityScanFindingState(previous);
    const nextFindingState = securityScanFindingState(scan);
    state.securitySummary.scan = scan;
    securityScanRevision++;
    const scanNodeID = String(scan?.node_id || state.nodeId || "");
    if (scan?.status === "running" && scanPageActive() && scanNodeID === String(state.nodeId || "")
      && (previous?.status !== "running" || previousFindingState !== nextFindingState)) {
      scheduleSecurityQuarantineRefresh(state.nodeId);
    }
  }

  // Quarantine entries change when a finding is contained. Progress counters
  // change much more often, so use the action state as the refresh signal and
  // avoid walking a large quarantine directory on every SSE frame.
  function securityScanFindingState(scan) {
    return (Array.isArray(scan?.findings) ? scan.findings : []).map((finding) => [
      finding?.id,
      finding?.quarantined,
      finding?.quarantine_path,
      finding?.terminated,
      finding?.termination_error,
      finding?.containment_blocked_reason,
      finding?.evidence_archived,
      finding?.startup_blocked,
      finding?.module_unloaded,
      finding?.ignored,
    ].map((value) => String(value ?? "")).join("\u0001")).join("\u0002");
  }

  async function refreshSecurityScan() {
    if (!state.nodeId) return;
    const nodeID = state.nodeId;
    const revision = securityScanRevision;
    const payload = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan`, { timeoutMs: 12000 });
    if (nodeID !== state.nodeId || (payload?.node_id && payload.node_id !== nodeID)) return;
    if (revision !== securityScanRevision) {
      if (state.securitySummary.scan?.status === "running") scheduleSecurityScanPoll();
      return payload;
    }
    applySecurityScan(payload);
    if (payload?.status === "running") {
      startSecurityScanEventStream(nodeID);
      scheduleSecurityScanPoll();
    } else {
      stopSecurityScanEventStream();
      await refreshSecurityQuarantine().catch(() => {});
    }
    return payload;
  }

  function stopSecurityScanEventStream() {
    if (securityScanTimer && typeof window !== "undefined") {
      window.clearTimeout(securityScanTimer);
      securityScanTimer = null;
    }
    if (securityScanEventSource) {
      securityScanEventSource.close();
      securityScanEventSource = null;
    }
    if (securityQuarantineRefreshTimer && typeof window !== "undefined") {
      window.clearTimeout(securityQuarantineRefreshTimer);
      securityQuarantineRefreshTimer = null;
    }
    securityScanEventNodeID = "";
    securityScanEventReady = false;
    securityScanEventFailed = false;
  }

  function scheduleSecurityQuarantineRefresh(nodeID = state.nodeId) {
    if (disposed || typeof window === "undefined" || !scanPageActive() || !nodeID || securityQuarantineRefreshTimer) return;
    securityQuarantineRefreshTimer = window.setTimeout(async () => {
      securityQuarantineRefreshTimer = null;
      if (nodeID !== state.nodeId || !scanPageActive() || state.securitySummary.scan?.status !== "running") return;
      await refreshSecurityQuarantine().catch(() => {});
    }, 700);
  }

  function scanPageActive() {
    return state.section === "security" && ["overview", "malware"].includes(state.securityFeature);
  }

  function startSecurityScanEventStream(nodeID = state.nodeId) {
    if (disposed || typeof window === "undefined" || typeof window.EventSource === "undefined" || !nodeID || !scanPageActive()) return;
    const encodedNode = encodeURIComponent(nodeID);
    if (securityScanEventSource && securityScanEventNodeID === String(nodeID)) return;
    stopSecurityScanEventStream();
    const source = new window.EventSource(`/nodes/${encodedNode}/security/scan/events`);
    securityScanEventSource = source;
    securityScanEventNodeID = String(nodeID);
    securityScanEventFailed = false;
    source.onopen = () => {
      if (nodeID !== state.nodeId || source !== securityScanEventSource) return;
      securityScanEventReady = true;
      securityScanEventFailed = false;
      // Once the stream is open, cancel the fallback request. This prevents
      // the old fixed 1.5s polling loop from competing with SSE updates.
      if (securityScanTimer && typeof window !== "undefined") {
        window.clearTimeout(securityScanTimer);
        securityScanTimer = null;
      }
    };
    source.addEventListener("scan", (event) => {
      try {
        const payload = JSON.parse(event.data || "{}");
        if (nodeID !== state.nodeId || source !== securityScanEventSource || (payload?.node_id && payload.node_id !== nodeID)) return;
        applySecurityScan(payload);
        if (payload?.status !== "running") {
          stopSecurityScanEventStream();
          refreshSecurityQuarantine().catch(() => {});
        }
      } catch (_) {
        // The polling fallback remains active if a partial SSE frame is seen.
      }
    });
    source.onerror = () => {
      // EventSource reconnects by itself. Until it opens again, use a
      // backstop status request so a proxy interruption cannot hide progress.
      if (nodeID === state.nodeId && source === securityScanEventSource) {
        securityScanEventReady = false;
        securityScanEventFailed = true;
      }
      if (nodeID === state.nodeId && source === securityScanEventSource && state.securitySummary.scan?.status === "running") {
        scheduleSecurityScanPoll();
      }
    };
    if (state.securitySummary.scan?.status === "running") scheduleSecurityQuarantineRefresh(nodeID);
  }

  function scheduleSecurityScanPoll() {
    // SSE is the normal transport. Open it before deciding whether a
    // fallback timer is needed; this matters when the summary request wins
    // the race against the scan request during page initialization.
    if (disposed || typeof window === "undefined" || !scanPageActive()) return;
    if (!securityScanEventSource) startSecurityScanEventStream();
    // Keep a polling timer only while the browser has reported a stream error
    // or EventSource is unavailable. This avoids the old fixed polling loop
    // racing a healthy event stream.
    if (securityScanEventReady || securityScanTimer || (securityScanEventSource && !securityScanEventFailed)) return;
    const nodeID = state.nodeId;
    securityScanTimer = window.setTimeout(async () => {
      securityScanTimer = null;
      if (nodeID !== state.nodeId || !scanPageActive()) return;
      try {
        await refreshSecurityScan();
      } catch (error) {
        if (nodeID !== state.nodeId) return;
        handleError(error);
        if (state.securitySummary.scan?.status === "running") scheduleSecurityScanPoll();
      }
    }, 1500);
  }

  async function startSecurityScan(path, autoQuarantine = false, autoTerminateProcesses = false, mode = "full") {
    const root = String(path || "").trim();
    if (!root) throw new Error(t("securityScanRootRequired"));
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan`, {
      method: "POST",
      timeoutMs: 12000,
      body: JSON.stringify({
        path: root,
        mode: String(mode || "full"),
        auto_quarantine: Boolean(autoQuarantine),
        auto_terminate_processes: Boolean(autoTerminateProcesses),
      }),
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    applySecurityScan(response);
    startSecurityScanEventStream(nodeID);
    scheduleSecurityScanPoll();
    return response;
  }

  async function stopSecurityScan() {
    const nodeID = state.nodeId;
    const revision = securityScanRevision;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/stop`, {
      method: "POST",
      timeoutMs: 12000,
    });
    if (nodeID !== state.nodeId) return response;
    if (revision === securityScanRevision) applySecurityScan(response);
    if (state.securitySummary.scan?.status === "running") scheduleSecurityScanPoll();
    else {
      stopSecurityScanEventStream();
      await refreshSecurityQuarantine().catch(() => {});
    }
    setNotice(t("securityScanStopped"), "info");
    return response;
  }

  async function quarantineSecurityFinding(findingID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/${encodeURIComponent(findingID)}/quarantine`, {
      method: "POST",
      timeoutMs: 12000,
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.scan && nodeID === state.nodeId) applySecurityScan(response.scan);
    if (Array.isArray(response?.chain_warnings) && response.chain_warnings.length) {
      setNotice(`${t("securityQuarantineChainWarning")}：${response.chain_warnings.join("；")}`, "info");
    } else {
      setNotice(t("securityQuarantined"), "success");
    }
    await refreshSecurityQuarantine();
    return response;
  }

  async function ignoreSecurityFinding(findingID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/${encodeURIComponent(findingID)}/ignore`, {
      method: "POST",
      timeoutMs: 12000,
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.scan && nodeID === state.nodeId) applySecurityScan(response.scan);
    setNotice(t("securityFindingIgnored"), "info");
    return response;
  }

  async function terminateSecurityProcess(findingID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/scan/${encodeURIComponent(findingID)}/terminate`, {
      method: "POST",
      timeoutMs: 12000,
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.scan && nodeID === state.nodeId) applySecurityScan(response.scan);
    setNotice(t("securityProcessContained"), "success");
    return response;
  }

  async function refreshSecurityQuarantine() {
    if (!state.nodeId) return state.securityQuarantine;
    const nodeID = state.nodeId;
    // Progress frames can arrive faster than a slow filesystem listing. Share
    // one request per node so a busy scan never creates a request pile-up.
    if (securityQuarantineRefreshInFlight?.nodeID === nodeID) {
      return securityQuarantineRefreshInFlight.promise;
    }
    const promise = (async () => {
      const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine`, { timeoutMs: 4000 });
      if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return state.securityQuarantine;
      state.securityQuarantine = {
        root: response?.root || "",
        entries: Array.isArray(response?.entries) ? response.entries : [],
        node_id: nodeID,
      };
      return state.securityQuarantine;
    })();
    const current = { nodeID, promise };
    securityQuarantineRefreshInFlight = current;
    try {
      return await promise;
    } finally {
      if (securityQuarantineRefreshInFlight === current) securityQuarantineRefreshInFlight = null;
    }
  }

  async function deleteSecurityQuarantine(entryID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine/${encodeURIComponent(entryID)}`, {
      method: "DELETE",
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
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    await refreshSecurityQuarantine();
    setNotice(t("securityQuarantineRestored"), "success");
    return response;
  }

  async function loadSecurityQuarantineModule(entryID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine/${encodeURIComponent(entryID)}/load`, {
      method: "POST",
      timeoutMs: 20000,
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    await refreshSecurityQuarantine();
    setNotice(t("securityQuarantineModuleLoadedNotice"), "success");
    return response;
  }

  async function unloadSecurityQuarantineModule(entryID) {
    const nodeID = state.nodeId;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/security/quarantine/${encodeURIComponent(entryID)}/unload`, {
      method: "POST",
      timeoutMs: 20000,
    });
    if (nodeID !== state.nodeId || (response?.node_id && response.node_id !== nodeID)) return response;
    await refreshSecurityQuarantine();
    setNotice(t("securityQuarantineModuleUnloadedNotice"), "success");
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
    await refreshSectionData(state.section);
    state.error = "";
    return nodes;
  }

  async function refreshSectionData(section = state.section, options = {}) {
    const target = section || "overview";
    const fromStream = !!options.fromStream;
    const nodeSwitch = !!options.nodeSwitch;
    const force = !!options.force;
    if (target === "cluster") {
      await refreshNodes();
      if (sectionStreamActive() && !nodeSwitch) return;
      await refreshNodeProtections();
      return;
    }
    if (target === "monitoring") {
      if (!state.nodesLoaded) await refreshNodes();
      if (!state.monitoringHistory || fromStream || force) await refreshMonitoringHistory();
      return;
    }
    if (target === "management") {
      await refreshNodes();
      if (sectionStreamActive()) return;
      await Promise.all([
        refreshManagementSettings({ nodeOnly: nodeSwitch }),
        refreshNodeProtections(),
      ]);
      return;
    }
    if (target === "users") {
      await Promise.all([refreshNodes(), nodeSwitch ? Promise.resolve() : refreshUsers()]);
      return;
    }
    if (target === "account") {
      await refreshAccountSecurity();
      return;
    }
    if (target === "ssh") {
      await Promise.all([refreshNodes(), refreshManagementSettings({ nodeOnly: nodeSwitch })]);
      return;
    }
    if (target === "ssh-console") {
      await refreshNodes();
      return;
    }
    if (target === "security" || target === "malware") {
      await refreshNodes();
      if (sectionStreamActive()) return;
      const feature = target === "malware" ? "malware" : state.securityFeature;
      const needsSecurityData = feature === "overview" || feature === "malware";
      const needsSSHData = feature === "overview" || feature === "ssh";
      const needsCurrentData = feature === "overview" || feature === "firewall";
      const needsResourceAggregate = feature === "overview";
      const currentData = needsCurrentData ? (async () => {
        const nodeID = state.nodeId;
        await refreshInventory();
        if (nodeID === state.nodeId) await queueRefreshCurrentLight();
      })() : Promise.resolve();
      await Promise.all([
        needsSecurityData ? refreshSecurityData() : Promise.resolve(),
        needsSSHData ? refreshSSHProtectionData() : Promise.resolve(),
        needsResourceAggregate ? refreshClusterAggregate({ force }) : Promise.resolve(),
        currentData,
        feature === "overview" ? refreshEventsData() : refreshPersistedLogs(),
      ]);
      return;
    }
    if (target === "events") {
      if (sectionStreamActive() && state.eventDispositionsLoaded) return;
      await refreshNodes();
      await Promise.all([refreshEventDispositions(), refreshEventsData()]);
      return;
    }
    if (target === "logs") {
      await refreshNodes();
      await Promise.all([
        (async () => {
          const nodeID = state.nodeId;
          await refreshInventory();
          if (nodeID === state.nodeId) await Promise.all([queueRefreshCurrentLight(), refreshLogPanels()]);
        })(),
        nodeSwitch ? Promise.resolve() : refreshPersistedLogs(),
      ]);
      return;
    }
    if (target === "policy") {
      await refreshNodes();
      await refreshInventory();
      await queueRefreshCurrentLight();
      return;
    }
    await refreshNodes();
    if (sectionStreamActive()) return;
    await Promise.all([
      refreshOverviewData(nodeSwitch),
      nodeSwitch ? Promise.resolve() : refreshClusterAggregate({ force }),
      nodeSwitch || fromStream ? Promise.resolve() : refreshPersistedLogs(),
    ]);
  }

  async function queueSectionRefresh(section = state.section, options = {}) {
    const key = [section, state.nodeId, state.securityFeature, !!options.nodeSwitch, !!options.fromStream, !!options.force,
      section === "monitoring" ? monitoringHistoryParams().toString() : ""].join("|");
    if (sectionRefreshInFlight.has(key)) return sectionRefreshInFlight.get(key);
    const pending = refreshSectionData(section, options).finally(() => sectionRefreshInFlight.delete(key));
    sectionRefreshInFlight.set(key, pending);
    return pending;
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
      await refreshNodes();
      if (state.section === "users") await refreshUsers();
      else if (state.section === "security") await refreshSSHProtectionData();
      else if (state.section === "events") await refreshEventsData();
      else await refreshManagementSettings();
      return;
    }
    await refreshSectionData(state.section);
  }

  async function refreshClusterAggregate(options = {}) {
    const force = !!options.force;
    const now = Date.now();
    if (!force && clusterAggregateInFlight) return clusterAggregateInFlight;
    if (!force && now - clusterAggregateLastAt < CLUSTER_AGGREGATE_TTL_MS) return state.clusterAggregate;
    const token = ++clusterAggregateToken;
    const pending = (async () => {
      const direction = state.direction === "egress" ? "egress" : "ingress";
      const payload = await request(withDirection("/cluster/aggregate", direction)).catch(() => null);
      if (!payload || token !== clusterAggregateToken || direction !== state.direction) return;
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
          average_filesystem_used_percent: 0,
          uptime_seconds: 0,
          rx_bytes_per_second: 0,
          tx_bytes_per_second: 0,
        },
      };
      clusterAggregateLastAt = Date.now();
    })();
    clusterAggregateInFlight = pending;
    try {
      return await pending;
    } finally {
      if (clusterAggregateInFlight === pending) clusterAggregateInFlight = null;
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

  async function refreshData(options = {}) {
    await withBusy("refresh", async () => {
      await queueSectionRefresh(state.section, { force: !!options.force });
      setNotice(t("noticeRefreshDone"), "info");
    });
  }

  function applyInterfaceSummary(summary, autoSwitchDirection = true) {
    // A summary collected before a write can finish after its response. Keep
    // the newer confirmed policy while still accepting fresh health/counters.
    const incoming = summary?.policy || {};
    if ((incoming.node_id && incoming.node_id !== state.nodeId)
      || (incoming.interface && incoming.interface !== currentInterface.value)) return false;
    const currentTime = Date.parse(state.policy?.updated_at || "") || 0;
    const nextTime = Date.parse(incoming.updated_at || "") || 0;
    const nextPolicy = currentTime > nextTime && state.policy?.node_id === incoming.node_id
      && state.policy?.interface === incoming.interface ? state.policy : incoming;
    const selectedDirectionPolicy = nextPolicy?.[state.direction] || {};
    const policyAllowlist = Array.isArray(selectedDirectionPolicy?.rules)
      ? selectedDirectionPolicy.rules.map((item) => item?.cidr).filter(Boolean)
      : [];

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

    applyPolicyRules(nextPolicy);
    const summaryTrial = summary?.protection_trial;
    state.protectionTrial = summaryTrial &&
      (!summaryTrial.direction || summaryTrial.direction === state.direction)
      ? summaryTrial
      : null;
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
    state.interfaceLogs = Array.isArray(summary?.interface_logs) ? summary.interface_logs : [];
    state.temporaryBlocks = Array.isArray(summary?.temporary_blocks) ? summary.temporary_blocks : [];
    state.rateLimits = Array.isArray(summary?.rate_limits) ? summary.rate_limits : [];
    state.interfaceDataStatus = "ready";
    state.error = "";
    return true;
  }

  function applyPolicyRules(policy) {
    state.policy = policy;
    const selected = policy?.[state.direction] || policy || {};
    state.allowlist = (selected.rules || []).map((item) => item?.cidr).filter(Boolean);
    state.bypassCIDRs = cloneArray(selected.bypass_cidrs);
    state.blockedCIDRs = cloneArray(selected.blocked_cidrs);
    state.icmpAllowCIDRs = cloneArray(selected.icmp_allow_cidrs);
    state.icmpBlockedCIDRs = cloneArray(selected.icmp_blocked_cidrs);
    state.publicPorts = cloneArray(selected.public_ports);
    state.deniedPorts = cloneArray(selected.denied_ports);
    state.allowedPorts = cloneArray(selected.allowed_ports);
    state.publicPortRules = normalizePortRules(selected, "public_port_rules", "public_ports");
    state.deniedPortRules = normalizePortRules(selected, "denied_port_rules", "denied_ports");
    state.allowedPortRules = normalizePortRules(selected, "allowed_port_rules", "allowed_ports");
    state.forms.nonIPv4 = selected.non_ipv4_action || policy?.non_ipv4_action || "drop";
  }

  function policyTarget(options = {}) {
    return {
      nodeID: options.nodeID || state.nodeId,
      interface: options.interface || currentInterface.value,
      direction: options.direction || state.direction,
      section: state.section,
      feature: state.securityFeature,
    };
  }

  function isCurrentPolicyTarget(target) {
    return !disposed && target.nodeID === state.nodeId && target.interface === currentInterface.value
      && target.direction === state.direction && target.section === state.section && target.feature === state.securityFeature;
  }

  async function writePolicy(path, method, body, target = policyTarget()) {
    let revision = 0;
    const updated = await requestWithSSHConfirmation(path, {
      method,
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      onResponse: (response) => { revision = Number(response?.headers?.get("X-NodeWall-Revision") || 0); },
    });
    if (!isCurrentPolicyTarget(target)) return updated;
    // Use the server's confirmed result immediately, then let SSE maintain it.
    // Raising the revision floor prevents an older in-flight frame undoing it.
    if (revision && revision < state.consoleRevision) return updated;
    state.consoleRevision = Math.max(state.consoleRevision, revision);
    if (updated?.ingress || updated?.egress) {
      if (updated.node_id && updated.node_id !== target.nodeID) return updated;
      if (updated.interface && updated.interface !== target.interface) return updated;
      refreshCurrentToken++;
      const currentTime = Date.parse(state.policy?.updated_at || "") || 0;
      const nextTime = Date.parse(updated.updated_at || "") || 0;
      if (!currentTime || !nextTime || nextTime >= currentTime) applyPolicyRules(updated);
      state.interfaceDataStatus = "ready";
    } else {
      await refreshAfterWrite("policy");
    }
    return updated;
  }

  async function refreshCurrent(autoSwitchDirection = true) {
    if (!state.nodeId || !currentInterface.value) {
      state.interfaceDataStatus = "unavailable";
      return;
    }
    const token = ++refreshCurrentToken;
    state.interfaceDataStatus = "loading";
    const interfaceName = currentInterface.value;
    const iface = requireInterfaceEncoded();
    const currentNodeId = state.nodeId;
    const currentDirection = state.direction;
    const summary = await request(withDirection(`/nodes/${state.nodeId}/interfaces/${iface}/summary`, currentDirection), {
      key: `summary:${currentNodeId}|iface:${iface}|dir:${currentDirection}`,
    }).catch(() => null);
    if (token !== refreshCurrentToken || currentNodeId !== state.nodeId || interfaceName !== currentInterface.value || currentDirection !== state.direction) return;
    if (!summary) {
      state.interfaceDataStatus = "unavailable";
      return;
    }
    if (applyInterfaceSummary(summary, autoSwitchDirection && !state.selectedInterface)) return;
    if (currentDirection !== state.direction) {
      await refreshCurrent(false);
    } else {
      state.interfaceDataStatus = "unavailable";
    }
  }

  async function queueRefreshCurrent(autoSwitchDirection = true) {
    // refreshCurrent has a request token and aborts duplicate requests, so a
    // slow previous node does not need to finish before the new node loads.
    return refreshCurrent(autoSwitchDirection);
  }

  async function refreshCurrentLight(autoSwitchDirection = true) {
    await refreshCurrent(autoSwitchDirection);
  }

  async function queueRefreshCurrentLight(autoSwitchDirection = true) {
    return refreshCurrentLight(autoSwitchDirection);
  }

  async function requestWithSSHConfirmation(path, options = {}) {
    try {
      return await request(path, options);
    } catch (error) {
      if (error?.code !== "SSH_CONFIRM_REQUIRED") throw error;
      return new Promise((resolve, reject) => {
        openModal({
          title: t("sshConfirmTitle"),
          copy: t("sshConfirmCopy", { ports: error.payload?.port || error.payload?.ports?.join(", ") || "22" }),
          fields: [{ key: "confirm_password", label: t("currentConsolePassword"), type: "password" }],
          onCancel: () => reject(Object.assign(new Error("Request aborted"), { code: "ABORTED" })),
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
    if (!trimmed) throw new Error(t("policyRuleSourceRequired"));
    const target = policyTarget(options);
    const iface = encodeURIComponent(target.interface);
    const node = encodeURIComponent(target.nodeID);
    const pathMap = {
      allowlist: `/nodes/${node}/interfaces/${iface}/allowlist`,
      bypass: `/nodes/${node}/interfaces/${iface}/bypass`,
      blocked: `/nodes/${node}/interfaces/${iface}/block`,
      icmpAllow: `/nodes/${node}/interfaces/${iface}/icmp-allowlist`,
      icmpBlocked: `/nodes/${node}/interfaces/${iface}/icmp-blocklist`,
    };
    const body = { cidr: trimmed };
    if (kind === "allowlist") {
      const comment = String(options?.comment || "").trim();
      if (comment) body.comment = comment;
    }
    if (!target.nodeID || !target.interface || !pathMap[kind]) throw new Error(t("settingsTargetChanged"));
    return writePolicy(withDirection(pathMap[kind], target.direction), "POST", body, target);
  }

  async function addPort(kind, value, protocol = "", options = {}) {
    const port = Number(value || 0);
    if (String(protocol || "").toLowerCase() !== "icmp" && (!Number.isInteger(port) || port < 1 || port > 65535)) throw new Error(t("policyRulePortInvalid"));
    const target = policyTarget(options);
    const iface = encodeURIComponent(target.interface);
    const node = encodeURIComponent(target.nodeID);
    const pathMap = {
      public: `/nodes/${node}/interfaces/${iface}/public-ports`,
      denied: `/nodes/${node}/interfaces/${iface}/denied-ports`,
      allowed: `/nodes/${node}/interfaces/${iface}/ports`,
    };
    const normalizedProtocol = protocol === "both" ? "" : protocol;
    const payload = {
      port: String(protocol || "").toLowerCase() === "icmp" ? 0 : port,
      protocol: normalizedProtocol || undefined,
    };
    if (!target.nodeID || !target.interface || !pathMap[kind]) throw new Error(t("settingsTargetChanged"));
    // Do not auto-create opposite-direction policy entries in UI flow.
    // Reply allowance should be handled by dataplane/runtime logic.
    return writePolicy(withDirection(pathMap[kind], target.direction), "POST", payload, target);
  }

  async function saveRuleDescription({ kind, value, protocol = "", description = "" } = {}, options = {}) {
    const target = policyTarget(options);
    const iface = encodeURIComponent(target.interface);
    const endpoint = `/nodes/${encodeURIComponent(target.nodeID)}/interfaces/${iface}/rule-description`;
    const protocols = String(protocol).toLowerCase() === "both" ? ["tcp", "udp"] : [String(protocol).toLowerCase()];
    for (const nextProtocol of protocols) {
      await writePolicy(withDirection(endpoint, target.direction), "PUT",
        { kind, value: String(value ?? ""), protocol: nextProtocol, description }, target);
    }
  }

  async function saveIPv6Action(action) {
    const scope = policyTarget();
    const nextAction = action === "pass" ? "pass" : "drop";
    const current = state.policy || {};
    const draft = {
      node_id: state.nodeId,
      interface: currentInterface.value,
      updated_at: current.updated_at,
      ingress: normalizeDirectionPolicyDraft(current.ingress || current, current.non_ipv4_action),
      egress: normalizeDirectionPolicyDraft(current.egress, current.non_ipv4_action),
    };
    const selected = draft[state.direction] || draft.ingress;
    selected.non_ipv4_action = nextAction;
    const iface = requireInterfaceEncoded();
    try {
      await writePolicy(`/nodes/${encodeURIComponent(scope.nodeID)}/interfaces/${iface}/policy`, "PUT", { policy: draft }, scope);
      setNotice(t("noticeRefreshDone"), "success");
    } catch (error) {
      if (isCurrentPolicyTarget(scope)) state.forms.nonIPv4 = current?.[scope.direction]?.non_ipv4_action || current?.non_ipv4_action || "drop";
      throw error;
    }
  }

  async function removeCIDR(kind, value) {
    const target = policyTarget();
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
    await writePolicy(withDirection(path, target.direction), "DELETE", undefined, target);
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function removePort(kind, value, protocol = "") {
    const target = policyTarget();
    const iface = requireInterfaceEncoded();
    const pathMap = {
      public: `/nodes/${state.nodeId}/interfaces/${iface}/public-ports/${value}`,
      denied: `/nodes/${state.nodeId}/interfaces/${iface}/denied-ports/${value}`,
      allowed: `/nodes/${state.nodeId}/interfaces/${iface}/ports/${value}`,
    };
    const path = protocol ? `${pathMap[kind]}?protocol=${encodeURIComponent(protocol)}` : pathMap[kind];
    await writePolicy(withDirection(path, target.direction), "DELETE", undefined, target);
    setNotice(t("noticeRefreshDone"), "success");
  }

  async function changeRuleStrategy(row, nextStrategy) {
    const scope = policyTarget();
    const target = nextStrategy === "deny" ? "deny" : "allow";
    const currentKind = String(row?.kind || "");
    if (!currentKind || currentKind === "bypass") return;

    const iface = requireInterfaceEncoded();
    const current = state.policy || {};
    const draft = {
      node_id: state.nodeId,
      interface: currentInterface.value,
      updated_at: current.updated_at,
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
      const targetRulesKey = target === "deny"
        ? "denied_port_rules"
        : (state.direction === "egress" ? "allowed_port_rules" : "public_port_rules");
      selected[targetRulesKey].push({ protocol, port });
      for (const [rulesKey, portsKey] of ruleSets) {
        selected[portsKey] = collapsePortRuleDraft(selected[rulesKey]);
      }
    } else {
      return;
    }

    await writePolicy(`/nodes/${encodeURIComponent(scope.nodeID)}/interfaces/${iface}/policy`, "PUT", { policy: draft }, scope);
    setNotice(t("noticeRefreshDone"), "success");
  }

  // Edit a rule through one complete policy update. Keeping the replacement
  // atomic avoids the unsafe delete-then-add window that would briefly remove
  // an SSH or management rule while an operator is editing it.
  async function updateRule(row, next = {}) {
    const scope = policyTarget();
    const currentKind = String(row?.kind || "");
    if (!currentKind || currentKind === "bypass") return;

    const iface = requireInterfaceEncoded();
    const current = state.policy || {};
    const draft = {
      node_id: state.nodeId,
      interface: currentInterface.value,
      updated_at: current.updated_at,
      ingress: normalizeDirectionPolicyDraft(current.ingress || current, current.non_ipv4_action),
      egress: normalizeDirectionPolicyDraft(current.egress, current.non_ipv4_action),
    };
    const selected = draft[state.direction] || draft.ingress;
    const oldValue = String(row?.value || "");

    if (["allowlist", "blocked", "icmpAllow", "icmpBlocked"].includes(currentKind)) {
      selected.rules = (selected.rules || []).filter((item) => String(item?.cidr || "") !== oldValue);
      selected.blocked_cidrs = (selected.blocked_cidrs || []).filter((item) => String(item) !== oldValue);
      selected.icmp_allow_cidrs = (selected.icmp_allow_cidrs || []).filter((item) => String(item) !== oldValue);
      selected.icmp_blocked_cidrs = (selected.icmp_blocked_cidrs || []).filter((item) => String(item) !== oldValue);
    } else if (["public", "allowed", "denied"].includes(currentKind)) {
      const oldPort = Number(row?.value || 0);
      const oldProtocol = String(row?.portProtocol || "tcp").toLowerCase();
      const ruleSets = [
        ["public_port_rules", "public_ports"],
        ["allowed_port_rules", "allowed_ports"],
        ["denied_port_rules", "denied_ports"],
      ];
      for (const [rulesKey, portsKey] of ruleSets) {
        const rules = normalizedPortRuleDraft(selected[rulesKey], selected[portsKey]);
        selected[rulesKey] = rules.filter((item) => item.port !== oldPort || item.protocol !== oldProtocol);
        selected[portsKey] = collapsePortRuleDraft(selected[rulesKey]);
      }
    }

    const nextKind = String(next.kind || "");
    const nextSource = String(next.sourceValue || "").trim();
    const nextProtocol = String(next.protocol || "tcp").toLowerCase();
    if (["allowlist", "blocked"].includes(nextKind) && nextSource) {
      if (nextKind === "allowlist") selected.rules.push({ cidr: nextSource, action: "allow" });
      else selected.blocked_cidrs.push(nextSource);
    } else if (["icmpAllow", "icmpBlocked"].includes(nextKind) && nextSource) {
      const target = nextKind === "icmpAllow" ? selected.icmp_allow_cidrs : selected.icmp_blocked_cidrs;
      target.push(nextSource);
    } else if (["public", "allowed", "denied"].includes(nextKind)) {
      const nextPort = nextProtocol === "icmp" ? 0 : Number(next.targetValue || 0);
      if (!nextPort && nextProtocol !== "icmp") return;
      const protocols = nextProtocol === "both" ? ["tcp", "udp"] : [nextProtocol];
      const targetRulesKey = nextKind === "denied"
        ? "denied_port_rules"
        : (state.direction === "egress" ? "allowed_port_rules" : "public_port_rules");
      for (const protocol of protocols) selected[targetRulesKey].push({ protocol, port: nextPort });
      const ruleSets = [
        ["public_port_rules", "public_ports"],
        ["allowed_port_rules", "allowed_ports"],
        ["denied_port_rules", "denied_ports"],
      ];
      for (const [rulesKey, portsKey] of ruleSets) {
        selected[rulesKey] = normalizedPortRuleDraft(selected[rulesKey], selected[portsKey]);
        selected[portsKey] = collapsePortRuleDraft(selected[rulesKey]);
      }
    } else {
      return;
    }

    const updated = await writePolicy(`/nodes/${encodeURIComponent(scope.nodeID)}/interfaces/${iface}/policy`, "PUT", { policy: draft }, scope);
    setNotice(t("noticeRefreshDone"), "success");
    return updated;
  }

  async function addRuleToNodes(rule, targets = [], options = {}) {
    const results = [];
    let cancelled = false;
    // Each target has its own NIC and receives only this rule. Copying the
    // source's full policy here used to change unrelated rules on other hosts.
    // Sequential writes bound Agent load and keep SSH confirmations usable.
    for (const item of targets) {
      const target = policyTarget(item);
      let ruleSaved = false;
      try {
        if (cancelled) throw new Error(t("policyRuleNotSubmitted"));
        if (!item.nodeID || !item.interface) throw new Error(t("settingsTargetChanged"));
        if (options.editingRow && target.nodeID === options.sourceNodeID) {
          if (!isCurrentPolicyTarget(target)) throw new Error(t("settingsTargetChanged"));
          await updateRule(options.editingRow, rule);
        } else if (["allowlist", "bypass", "blocked", "icmpAllow", "icmpBlocked"].includes(rule.kind)) {
          await addCIDR(rule.kind, rule.sourceValue, { ...target, comment: rule.description });
        } else {
          await addPort(rule.kind, rule.targetValue, rule.protocol, target);
        }
        ruleSaved = true;
        if (rule.description || options.editingRow) {
          try {
            await saveRuleDescription({
              kind: rule.kind,
              value: rule.sourceValue || rule.targetValue,
              protocol: ["public", "allowed", "denied"].includes(rule.kind) ? rule.protocol : "",
              description: rule.description || "",
            }, target);
          } catch (error) {
            throw new Error(t("policyRuleNoteFailed", { error: error.message }));
          }
        }
        results.push({ ...item, status: "success", ruleSaved });
      } catch (error) {
        results.push({ ...item, status: "failed", ruleSaved, error: error.message });
        if (error.code === "ABORTED" || error.code === "AUTH_REQUIRED") cancelled = true;
      }
    }
    return results;
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
        body: JSON.stringify({ direction: state.direction }),
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

  async function disableProtectionBaseline() {
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline/disable`, {
        method: "POST",
        body: JSON.stringify({ direction: state.direction }),
      });
      if (response?.policy) state.policy = response.policy;
      state.protectionTrial = null;
      await Promise.all([
        refreshAfterWrite("policy"),
        refreshClusterAggregate({ force: true }),
      ]);
      setNotice(t("protectionDisabled"), "success");
      return response;
    });
  }

  async function copyPolicyToNodes(targetNodeIDs = [], options = {}) {
    const sourceNodeID = String(options.sourceNodeID || state.nodeId || "").trim();
    const iface = String(options.interface || currentInterface.value || "").trim();
    const direction = options.direction === "egress" ? "egress" : (options.direction || state.direction);
    const targets = [...new Set((targetNodeIDs || []).map((item) => String(item || "").trim()).filter((item) => item && item !== sourceNodeID))];
    if (!sourceNodeID || !iface || !targets.length) return null;
    const response = await requestWithSSHConfirmation("/policy/copy", {
      method: "POST",
      body: JSON.stringify({
        source_node_id: sourceNodeID,
        interface: iface,
        direction,
        target_node_ids: targets,
        target_interfaces: options.targetInterfaces || {},
      }),
    });
    await refreshClusterAggregate({ force: true });
    const failed = (response?.results || []).filter((item) => item.status === "failed");
    setNotice(failed.length ? t("policyCopyPartial", { count: failed.length }) : t("policyCopyDone", { count: targets.length }), failed.length ? "info" : "success");
    return response;
  }

  async function trialProtectionBaseline(seconds = 30) {
    const trialSeconds = Math.max(1, Math.min(120, Number(seconds) || 30));
    await withBusy("protection-baseline", async () => {
      const iface = requireInterfaceEncoded();
      const response = await request(`/nodes/${encodeURIComponent(state.nodeId)}/interfaces/${iface}/protection-baseline`, {
        method: "POST",
        body: JSON.stringify({ direction: state.direction, trial_seconds: trialSeconds }),
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
    if (!canActOnFirewallSource(item)) {
      throw new Error(t("firewallSourceActionUnavailable"));
    }
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
    if (!canActOnFirewallSource(item)) return;
    state.selection.add(key);
  }

  function clearSelection() {
    state.selection.clear();
  }

  async function saveLoggingSettings(draft, options) {
    const result = await saveManagementSettings("logging", draft, options);
    setNotice(t("saveLogging"), "success");
    return result;
  }

  async function saveAuthSettings(draft, options) {
    const result = await saveManagementSettings("auth", draft, options);
    setNotice(t("saveAuth"), "success");
    return result;
  }

  async function savePasskeySettings(draft, options) {
    const result = await saveManagementSettings("passkey", draft, options);
    // Related read-only policy fields follow the authoritative Passkey result.
    state.authSettings = { ...state.authSettings, passkey_enabled: Boolean(result.enabled), passkey_rp_id: result.rp_id || "", passkey_origins: result.origins || [], passkey_tls_mode: result.tls_mode || "local" };
    setNotice(result.restart_required ? t("passkeyRestartRequired") : t("passkeySettingsSaved"), "success");
    return result;
  }

  async function saveSSHProtectionSettings(draft, options = {}) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection`, {
      method: "PUT",
      headers: (options.etag ?? state.sshSettingsETag) ? { "If-Match": options.etag ?? state.sshSettingsETag } : {},
      onResponse: (response) => { if (nodeID === state.nodeId) captureConfigurationResponse(response); },
      body: JSON.stringify({ ...state.sshProtection.settings, ...(draft || {}) }),
    });
    if (nodeID !== state.nodeId) return response;
    applySSHProtectionSnapshot(response, nodeID);
    await refreshAfterWrite("management");
    setNotice(t("sshProtectionSaved"), "success");
    return response;
  }

  async function saveSSHAuthenticationPolicy(allowPasswordLogin, currentPassword, options = {}) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/authentication`, {
      method: "PUT",
      headers: (options.etag ?? state.sshSettingsETag) ? { "If-Match": options.etag ?? state.sshSettingsETag } : {},
      onResponse: (response) => { if (nodeID === state.nodeId) captureConfigurationResponse(response); },
      body: JSON.stringify({
        allow_password_login: Boolean(allowPasswordLogin),
        current_password: currentPassword,
      }),
    });
    if (nodeID !== state.nodeId) return response;
    applySSHProtectionSnapshot(response, nodeID);
    setNotice(t("sshAuthenticationSaved"), "success");
    return response;
  }

  async function refreshSSHKeys() {
    const nodeID = state.nodeId;
    if (!nodeID) return [];
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/keys`);
    if (nodeID === state.nodeId) {
      state.sshProtection.keys = Array.isArray(response?.keys) ? response.keys : [];
    }
    return state.sshProtection.keys;
  }

  async function addSSHKey(publicKey, comment, currentPassword) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/keys`, {
      method: "POST",
      body: JSON.stringify({ public_key: publicKey, comment, current_password: currentPassword }),
    });
    if (nodeID !== state.nodeId) return response;
    state.sshProtection.keys = Array.isArray(response?.keys) ? response.keys : state.sshProtection.keys;
    setNotice(t("sshKeyAdded"), "success");
    return response;
  }

  async function removeSSHKey(fingerprint, currentPassword) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/keys/${encodeURIComponent(fingerprint)}`, {
      method: "DELETE",
      body: currentPassword ? JSON.stringify({ current_password: currentPassword }) : undefined,
    });
    if (nodeID !== state.nodeId) return response;
    state.sshProtection.keys = Array.isArray(response?.keys) ? response.keys : state.sshProtection.keys.filter((item) => item.fingerprint !== fingerprint);
    setNotice(t("sshKeyRemoved"), "info");
    return response;
  }

  async function saveSSHTransferPolicy(draft, options = {}) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const transfer = { ...(draft || state.sshProtection.settings.transfer) };
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/transfer`, {
      method: "PUT",
      headers: (options.etag ?? state.sshSettingsETag) ? { "If-Match": options.etag ?? state.sshSettingsETag } : {},
      onResponse: (response) => { if (nodeID === state.nodeId) captureConfigurationResponse(response); },
      body: JSON.stringify(transfer),
    });
    if (nodeID !== state.nodeId) return response;
    applySSHProtectionSnapshot(response, nodeID);
    setNotice(t("sshTransferPolicySaved"), "success");
    return response;
  }

  async function refreshSSHActivity() {
    const nodeID = state.nodeId;
    if (!nodeID) return [];
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/activity?limit=100`);
    if (nodeID !== state.nodeId) return state.sshProtection.activity;
    state.sshProtection.activity = Array.isArray(response?.records) ? response.records : [];
    return state.sshProtection.activity;
  }

  async function createSSHIntegrityBaseline(currentPassword) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/integrity/baseline`, {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword }),
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.integrity) {
      state.sshProtection.integrity = { ...state.sshProtection.integrity, ...response.integrity };
    }
    setNotice(t("sshIntegrityBaselineSaved"), "success");
  }

  async function verifySSHIntegrity() {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    const response = await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/integrity/verify`, {
      method: "POST",
    });
    if (nodeID !== state.nodeId) return response;
    if (response?.integrity) {
      state.sshProtection.integrity = { ...state.sshProtection.integrity, ...response.integrity };
    }
    setNotice(t("sshIntegrityChecked"), "success");
    return response;
  }

  async function releaseSSHProtectionBlock(id) {
    const nodeID = state.nodeId;
    if (!nodeID) return;
    await request(`/nodes/${encodeURIComponent(nodeID)}/ssh-protection/blocks/${encodeURIComponent(id)}`, {
      method: "DELETE",
    });
    if (nodeID !== state.nodeId) return;
    await refreshAfterWrite("management");
    setNotice(t("sshProtectionReleased"), "info");
  }

  async function changePassword(currentPassword, newPassword) {
    const current = String(currentPassword !== undefined ? currentPassword : state.forms.currentPassword || "").trim();
    const next = String(newPassword !== undefined ? newPassword : state.forms.newPassword || "").trim();
    if (!current || !next) throw new Error(t("passwordRequired"));
    await request("/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: current,
        new_password: next,
      }),
    });
    state.forms.currentPassword = "";
    state.forms.newPassword = "";
    setNotice(t("passwordChanged"), "success");
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
    isNodeOnline,
    currentInterface,
    currentInterfaceRecord,
    currentPolicy,
    currentNode,
    metrics,
    filteredLogs,
    eventRows,
    pendingEventCount,
    visibleInterfaces,
    formatNumber,
    formatLogReason,
    setSection,
    logout,
    setSecurityFeature,
    setManagementScope,
    setEventsView,
    setMonitoringStreamQuery,
    setDirection,
    setInterface,
    setNode,
    setOverviewScope,
    refreshAccountSecurity,
    refreshManagementSettings,
    setupOTP,
    verifyOTP,
    disableOTP,
    requestEmailVerification,
    confirmEmailVerification,
    registerPasskey,
    deletePasskey,
    saveSMTPSettings,
    testSMTP,
    deleteNode,
    updateNode,
    bootstrap,
    dispose,
    refreshAll,
    refreshData,
    addCIDR,
    addPort,
    addRuleToNodes,
    saveRuleDescription,
    saveIPv6Action,
    removeCIDR,
    removePort,
    changeRuleStrategy,
    updateRule,
    attachCurrent,
    detachCurrent,
    enableProtectionBaseline,
    disableProtectionBaseline,
    copyPolicyToNodes,
    trialProtectionBaseline,
    confirmProtectionTrial,
    rollbackProtectionTrial,
    runLogAction,
    toggleLogSelection,
    clearSelection,
    saveLoggingSettings,
    saveAuthSettings,
    savePasskeySettings,
    saveSSHProtectionSettings,
    saveSSHAuthenticationPolicy,
    saveSSHTransferPolicy,
    refreshSSHKeys,
    addSSHKey,
    removeSSHKey,
    refreshSSHActivity,
    createSSHIntegrityBaseline,
    verifySSHIntegrity,
    releaseSSHProtectionBlock,
    refreshSSHProtectionData,
    refreshEventDispositions,
    refreshEventsData,
    updateEventDisposition,
    refreshSecurityData,
    refreshSecurityScan,
    refreshSecurityQuarantine,
    startSecurityScan,
    stopSecurityScan,
    quarantineSecurityFinding,
    ignoreSecurityFinding,
    terminateSecurityProcess,
    deleteSecurityQuarantine,
    restoreSecurityQuarantine,
    loadSecurityQuarantineModule,
    unloadSecurityQuarantineModule,
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
    setNotice,
    handleError,
  });
}
