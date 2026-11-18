// A rule's CIDR counter is not an observed endpoint. Keep its label and action
// eligibility consistent in the event center, log table, and bulk actions.
export function firewallSourceLabel(item, t = (key) => key) {
  if (item?.source_cidr) return `${t("firewallRuleAggregateSource")} · ${item.source_cidr}`;
  const ip = String(item?.source_ip || "");
  if (ip === "0.0.0.0" && item?.reason === "dhcp_broadcast") {
    return `0.0.0.0 · ${t("firewallDHCPUnassigned")}`;
  }
  return [item?.source_domain, ip].filter(Boolean).join(" ") || "-";
}

export function canActOnFirewallSource(item) {
  if (item?.source_cidr) return false;
  const ip = String(item?.source_ip || "").trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return false;
  const octets = ip.split(".").map(Number);
  return octets.every((value) => value >= 0 && value <= 255) && octets[0] > 0 && octets[0] < 224;
}
