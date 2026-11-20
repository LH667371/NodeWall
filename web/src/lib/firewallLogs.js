// A rule's CIDR counter is not an observed endpoint. Keep its label and action
// eligibility consistent in the event center, log table, and bulk actions.
export function isFirewallRuleCounter(item) {
  if (item?.traffic?.evidence) return item.traffic.evidence === "rule_counter";
  const reason = String(item?.reason || "");
  return Boolean(item?.source_cidr) || reason.startsWith("nodewall:") || reason === "iptables_drop";
}

export function firewallSourceLabel(item, t = (key) => key) {
  if (isFirewallRuleCounter(item)) return [t("firewallRuleAggregateSource"), item.source_cidr || item.source_ip].filter(Boolean).join(" · ");
  const ip = String(item?.source_ip || "");
  if (ip === "0.0.0.0" && item?.reason === "dhcp_broadcast") {
    return `0.0.0.0 · ${t("firewallDHCPUnassigned")}`;
  }
  return [item?.source_domain, ip].filter(Boolean).join(" ") || "-";
}

export function firewallLogKey(item) {
  return JSON.stringify([item.node_id, item.interface, item.direction || "ingress", item.source_ip, item.source_cidr,
    item.port, item.timestamp, item.reason, Number(item.drops) > 0, item.traffic]);
}

export function firewallTrafficLabels(item, t = (key) => key) {
  const traffic = item?.traffic || {};
  const originKey = { vm: "firewallOriginVM", tap: "firewallOriginTAP", veth: "firewallOriginVeth", uplink: "firewallOriginUplink", host: "firewallOriginHost" }[traffic.origin];
  const hookKey = { input: "firewallHookInput", output: "firewallHookOutput", protected_ingress: "firewallHookIngress", tc_egress: "firewallHookTCEgress" }[traffic.hook];
  const deliveryKey = { broadcast: "firewallDeliveryBroadcast", multicast: "firewallDeliveryMulticast" }[traffic.delivery];
  const basisKey = { ingress_device: "firewallBasisDevice", bridge_fdb: "firewallBasisFDB" }[traffic.basis];
  return {
    origin: [t(originKey || "firewallOriginUnknown"), traffic.guest, traffic.device, traffic.bridge].filter(Boolean).join(" · "),
    hook: [hookKey && t(hookKey), item?.interface].filter(Boolean).join(" · "),
    local: [traffic.local_ip, deliveryKey && t(deliveryKey)].filter(Boolean).join(" · "),
    evidence: [t(isFirewallRuleCounter(item) ? "firewallEvidenceRule" : traffic.evidence === "packet_sample" ? "firewallEvidenceSample" : "firewallEvidencePacket"), basisKey && t(basisKey)].filter(Boolean).join(" · "),
  };
}

export function canActOnFirewallSource(item) {
  if (isFirewallRuleCounter(item)) return false;
  const ip = String(item?.source_ip || "").trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) return false;
  const octets = ip.split(".").map(Number);
  return octets.every((value) => value >= 0 && value <= 255) && octets[0] > 0 && octets[0] < 224;
}
