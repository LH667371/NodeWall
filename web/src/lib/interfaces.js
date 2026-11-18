function ipv4(address) {
  return /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/.test(String(address || ""));
}

export function interfaceAddress(item) {
  const own = Array.isArray(item?.addresses) ? item.addresses : [];
  const related = Array.isArray(item?.related_addresses) ? item.related_addresses : [];
  const direct = own.find(ipv4);
  if (direct) return { address: direct, via: "" };
  const parent = related.find(ipv4);
  if (parent && item.address_interface) return { address: parent, via: item.address_interface };
  return { address: own.find((address) => !String(address).startsWith("fe80:")) || own[0] || "—", via: "" };
}

export function interfaceAddressLabel(item) {
  const { address, via } = interfaceAddress(item);
  return via ? `${address} (${via})` : address;
}
