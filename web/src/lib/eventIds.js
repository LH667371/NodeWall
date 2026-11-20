// Event identifiers are shared by the event table and the global alert badge.
// Keep the node in every key so two Agents producing the same timestamp cannot
// overwrite one another's disposition.
export function eventDispositionKey(nodeID, eventID) {
  return `${String(nodeID || "").trim()}\u0000${String(eventID || "").trim()}`;
}

export function firewallEventID(item, index, fallbackNode = "-") {
  const node = item?.node_id || fallbackNode || "-";
  const parts = [item?.timestamp || index, item?.source_ip || item?.source_cidr || "unknown", item?.port || "", item?.reason || ""];
  if (item?.traffic?.evidence) parts.push(item.interface, item.direction, item.traffic.evidence, item.traffic.device, item.traffic.local_ip, item.traffic.protocol);
  const token = item?.event_id || parts.join("-");
  return `firewall-${node}-${token}`;
}

export function sshEventID(item, index, fallbackNode = "-") {
  const node = item?.node_id || fallbackNode || "-";
  const token = item?.event_id || [item?.at || item?.timestamp || index, item?.source_ip || "unknown", item?.command || item?.path || item?.action || ""].join("-");
  return `ssh-${node}-${token}`;
}

export function scanEventID(scan, fallbackNode = "-") {
  const node = scan?.node_id || fallbackNode || "-";
  return `scan-${node}-${scan?.id || scan?.finished_at || "latest"}`;
}
