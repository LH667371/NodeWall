import { firewallEventID, scanEventID, sshEventID } from "./eventIds";
import { firewallSourceLabel } from "./firewallLogs";

// The table, overview feed, and notification badge use the same cluster event
// snapshot. Never infer provenance from the security page's selected node.
export function buildEventRecords(snapshot, { t = (key) => key, formatLogReason = (reason) => reason, statusFor = (_id, _node, fallback) => fallback } = {}) {
  const rows = [];
  for (const [index, item] of (snapshot?.logs || []).entries()) {
    const hits = Number(item?.drops ?? item?.count ?? 0);
    if (!item.node_id || hits <= 0) continue;
    const node = item.node_id;
    const id = firewallEventID(item, index, node);
    const port = Number(item.port || 0);
    rows.push({
      id, node, time: item.timestamp, sourceKey: "firewall", module: t("securityOverviewFirewall"), type: t("securityOverviewFirewallEvent"),
      severity: hits >= 100 || ["blocked_source", "denied_port"].includes(String(item.reason).replace(/^nodewall:/, "")) ? "high" : item.reason === "dhcp_broadcast" ? "low" : "medium",
      description: `${formatLogReason(item.reason)} · ${hits} ${t("hitCount")}${port > 0 ? ` · ${t("targetPort")} ${port}` : ""}`,
      source: firewallSourceLabel(item, t),
      status: statusFor(id, node, "pending"), raw: item,
    });
  }
  for (const entry of snapshot?.nodes || []) {
    const node = entry.node_id;
    if (!node) continue;
    for (const [index, item] of (entry.ssh_activity || []).entries()) {
      const id = sshEventID({ ...item, node_id: node }, index, node);
      const blocked = ["blocked", "failed", "denied"].includes(String(item.action || "").toLowerCase());
      rows.push({
        id, node, time: item.at || item.timestamp || item.created_at, sourceKey: "ssh", module: t("securityOverviewSSH"),
        type: item.event === "command" ? t("securityOverviewCommandEvent") : t("securityOverviewSSHEvent"), severity: blocked ? "high" : "medium",
        description: item.command || item.path || item.action || "-",
        source: [item.user, item.source_ip, item.source_port ? `:${item.source_port}` : ""].filter(Boolean).join(" ") || "-",
        status: statusFor(id, node, blocked ? "pending" : "handled"), raw: { ...item, node_id: node },
      });
    }
    const seen = new Set();
    for (const scan of entry.scans || []) {
      if (!["completed", "failed", "cancelled", "canceled", "stopped"].includes(scan.status)) continue;
      const id = scanEventID({ ...scan, node_id: node }, node);
      if (seen.has(id)) continue;
      seen.add(id);
      const findings = Number(scan.findings_count ?? scan.findings?.length ?? 0);
      const failed = scan.status === "failed";
      rows.push({
        id, node, time: scan.finished_at || scan.started_at, sourceKey: "malware", module: t("securityOverviewMalware"), type: t("securityOverviewScanEvent"),
        severity: findings ? "high" : failed ? "medium" : "low",
        description: failed ? t("eventsScanFailed", { error: scan.error || t("securityScanFailed") })
          : scan.status !== "completed" ? t("eventsScanStopped") : t("securityOverviewScanEventDetails", { count: findings }),
        source: scan.root || "-", status: statusFor(id, node, findings || failed ? "pending" : "handled"), raw: { ...scan, node_id: node },
      });
    }
  }
  return rows.sort((a, b) => (Date.parse(b.time) || 0) - (Date.parse(a.time) || 0) || a.id.localeCompare(b.id));
}
