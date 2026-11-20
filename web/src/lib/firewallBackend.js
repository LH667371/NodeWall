function reportedMode(mode) {
  return ["native", "generic", "iptables"].includes(mode) ? mode : "unknown";
}

export function interfaceFirewallBackend(health, iface, dataStatus) {
  const current = iface && health?.interfaces?.find((item) => item.interface === iface);
  if (current) {
    if (current.xdp_attached === false) return "detached";
    return current.xdp_attached === true ? reportedMode(current.dataplane_mode) : "unknown";
  }
  // The Agent can omit inactive NICs from a successful health response.
  if (iface && health?.agent_ok === true) return "detached";
  return dataStatus === "loading" ? "loading" : "unavailable";
}

export function nodeFirewallBackends(status) {
  if (!status || status.protection_status === "loading") return [{ mode: "loading", interfaces: [] }];
  const modes = status.dataplane_modes;
  if (!modes) {
    const unavailable = status.reachable === false || status.connection_status === "unreachable"
      || status.protection_status === "unavailable";
    return [{ mode: unavailable ? "unavailable" : "unknown", interfaces: [] }];
  }

  const grouped = new Map();
  for (const iface of Object.keys(modes).sort()) {
    const mode = reportedMode(modes[iface]);
    if (!grouped.has(mode)) grouped.set(mode, []);
    grouped.get(mode).push(iface);
  }
  if (!grouped.size) return [{ mode: "detached", interfaces: [] }];
  return Array.from(grouped, ([mode, interfaces]) => ({ mode, interfaces }));
}
