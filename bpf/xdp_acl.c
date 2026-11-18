#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_acl.h"

char LICENSE[] SEC("license") = "GPL";

#define NODEWALL_BRIDGE_METADATA_MAGIC 0x4e57424d

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bridge_scope_value);
    __uint(max_entries, 1);
} bridge_scope SEC(".maps");

struct nodewall_vlan_header {
    __be16 tag_control;
    __be16 encapsulated_protocol;
};

#define NODEWALL_DROP_BLOCKED_SOURCE 1
#define NODEWALL_DROP_DENIED_PORT 2
#define NODEWALL_DROP_RESTRICTED_POLICY 3
#define NODEWALL_DROP_SOURCE_NOT_ALLOWED 4
#define NODEWALL_DROP_RATE_LIMITED 5
#define NODEWALL_DROP_DHCP_BROADCAST 6

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allow_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} bypass_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} block_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} icmp_allow_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} icmp_block_ipv4 SEC(".maps");

// Egress policy maps are deliberately separate from the XDP ingress maps.
// A host can publish one allowlist for traffic arriving at the NIC and a
// different allowlist for traffic leaving it; sharing the maps would make an
// egress update silently rewrite the ingress firewall.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_allow_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_bypass_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_block_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_icmp_allow_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct allow_value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} egress_icmp_block_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_value);
    __uint(max_entries, 1);
} stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config_value);
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} allow_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} public_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} deny_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} egress_allow_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} egress_public_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct port_rule_key);
    __type(value, struct port_value);
    __uint(max_entries, 256);
} egress_deny_ports SEC(".maps");

struct {
    // bpf_spin_lock values are supported consistently by HASH maps on the
    // older kernels still used by some nodes. LRU_HASH rejects this map
    // value layout during verification on Ubuntu 5.15, so the control plane
    // clears and repopulates this bounded map on every rule update instead.
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rate_limit_key);
    __type(value, struct rate_limit_value);
    __uint(max_entries, 4096);
} rate_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rate_limit_key);
    __type(value, struct rate_limit_value);
    __uint(max_entries, 4096);
} egress_rate_limits SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct source_stats_value);
    __uint(max_entries, 4096);
} source_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);
    __type(value, struct port_stats_value);
    __uint(max_entries, 256);
} port_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct drop_log_key);
    __type(value, struct drop_log_value);
    __uint(max_entries, 512);
} drop_logs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct reply_flow_key);
    __type(value, struct reply_flow_value);
    __uint(max_entries, 16384);
} reply_flows SEC(".maps");

// Only ingress accepted by the host policy can authorize an egress reply.
// Sharing this with outbound requests lets the packet authorize itself before
// the egress verdict, silently defeating a default-deny policy.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct reply_flow_key);
    __type(value, struct reply_flow_value);
    __uint(max_entries, 16384);
} inbound_reply_flows SEC(".maps");

// Keep service-level reply state separate from the exact five-tuple map. A
// busy container host can have many short-lived ephemeral flows; putting the
// wildcard entries in reply_flows would halve its useful capacity and make
// unrelated exact entries more likely to be evicted.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct reply_flow_key);
    __type(value, struct reply_flow_value);
    __uint(max_entries, 4096);
} reply_service_flows SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct reply_log_key);
    __type(value, struct reply_log_value);
    __uint(max_entries, 1024);
} reply_allow_logs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct stats_value);
    __uint(max_entries, 1);
} egress_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, struct source_stats_value);
    __uint(max_entries, 4096);
} egress_source_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u16);
    __type(value, struct port_stats_value);
    __uint(max_entries, 256);
} egress_port_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct drop_log_key);
    __type(value, struct drop_log_value);
    __uint(max_entries, 512);
} egress_drop_logs SEC(".maps");

static __always_inline void update_stats(__u8 passed)
{
    __u32 key = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&stats_map, &key);

    if (!stats) {
        return;
    }

    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }
}

static __always_inline void update_source_stats(__u32 source_ip, __u8 passed)
{
    struct source_stats_value zero = {};
    struct source_stats_value *stats = bpf_map_lookup_elem(&source_stats, &source_ip);

    if (!stats) {
        bpf_map_update_elem(&source_stats, &source_ip, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&source_stats, &source_ip);
        if (!stats) {
            return;
        }
    }

    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }

    stats->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline int ipv6_action(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg || cfg->non_ipv4_action == NODEWALL_NON_IPV4_PASS || cfg->reserved[4]) {
        return XDP_PASS;
    }

    return XDP_DROP;
}

// Parse the same L2 layout for ingress filtering and egress reply tracking.
// Unknown or truncated VLAN stacks must not become an IPv4 policy bypass.
static __always_inline int parse_ethernet(void *data, void *data_end, void **network_header)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    __u16 protocol = bpf_ntohs(eth->h_proto);
    void *header = (void *)(eth + 1);

#pragma unroll
    for (int i = 0; i < 2; i++) {
        if (protocol != ETH_P_8021Q && protocol != ETH_P_8021AD) {
            break;
        }
        struct nodewall_vlan_header *vlan = header;
        if ((void *)(vlan + 1) > data_end) {
            return -1;
        }
        protocol = bpf_ntohs(vlan->encapsulated_protocol);
        header = (void *)(vlan + 1);
    }

    if (protocol == ETH_P_8021Q || protocol == ETH_P_8021AD) {
        return -1;
    }
    *network_header = header;
    return protocol;
}

static __always_inline __u8 observe_only(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    return cfg && cfg->reserved[4];
}

static __always_inline int drop_action(void)
{
    return observe_only() ? XDP_PASS : XDP_DROP;
}

static __always_inline __u8 port_policy_enabled(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg) {
        return 0;
    }

    return cfg->port_policy_enabled;
}

static __always_inline __u8 rate_limit_enabled(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        return 0;
    }

    return cfg->reserved[3];
}

static __always_inline __u8 policy_enforced(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);

    if (!cfg) {
        return 0;
    }

    return cfg->reserved[0];
}

static __always_inline __u8 egress_policy_enforced(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg) {
        return 0;
    }

    return cfg->reserved[2];
}

static __always_inline __u8 egress_observe_only(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    return cfg && cfg->reserved[5];
}

static __always_inline __u8 egress_non_ipv4_action(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || cfg->reserved[6] == NODEWALL_NON_IPV4_PASS || egress_observe_only()) {
        return NODEWALL_NON_IPV4_PASS;
    }
    return NODEWALL_NON_IPV4_DROP;
}

static __always_inline __u8 egress_port_policy_enabled(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    return cfg && (cfg->reserved[7] & 1);
}

static __always_inline __u8 egress_rate_limit_enabled(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    return cfg && (cfg->reserved[7] & 2);
}

static __always_inline __u8 egress_default_deny_enabled(void)
{
    __u32 key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &key);
    return cfg && (cfg->reserved[7] & 4);
}

static __always_inline int egress_drop_action(void)
{
    // TC_ACT_SHOT is 2. Observe mode records the would-be drop and lets the
    // packet continue so an operator can validate the policy safely.
    return egress_observe_only() ? 0 : 2;
}

static __always_inline void update_port_stats(__u16 port, __u8 passed)
{
    struct port_stats_value zero = {};
    struct port_stats_value *stats = bpf_map_lookup_elem(&port_stats, &port);

    if (!stats) {
        bpf_map_update_elem(&port_stats, &port, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&port_stats, &port);
        if (!stats) {
            return;
        }
    }

    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }
}

static __always_inline void update_drop_log(__u32 source_ip, __u16 port, __u8 reason)
{
    struct drop_log_key key = {};
    key.source_ip = source_ip;
    key.dest_port = port;
    key.reason = reason;
    key.reserved = observe_only() ? 1 : 0;
    struct drop_log_value zero = {};
    struct drop_log_value *value = bpf_map_lookup_elem(&drop_logs, &key);

    if (!value) {
        bpf_map_update_elem(&drop_logs, &key, &zero, BPF_ANY);
        value = bpf_map_lookup_elem(&drop_logs, &key);
        if (!value) {
            return;
        }
    }

    __sync_fetch_and_add(&value->drops, 1);
    value->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline void update_egress_stats(__u8 passed)
{
    __u32 key = 0;
    struct stats_value *stats = bpf_map_lookup_elem(&egress_stats_map, &key);
    if (!stats) {
        return;
    }
    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }
}

static __always_inline void update_egress_source_stats(__u32 remote_ip, __u8 passed)
{
    struct source_stats_value zero = {};
    struct source_stats_value *stats = bpf_map_lookup_elem(&egress_source_stats, &remote_ip);
    if (!stats) {
        bpf_map_update_elem(&egress_source_stats, &remote_ip, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&egress_source_stats, &remote_ip);
        if (!stats) {
            return;
        }
    }
    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }
    stats->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline void update_egress_port_stats(__u16 port, __u8 passed)
{
    struct port_stats_value zero = {};
    struct port_stats_value *stats = bpf_map_lookup_elem(&egress_port_stats, &port);
    if (!stats) {
        bpf_map_update_elem(&egress_port_stats, &port, &zero, BPF_ANY);
        stats = bpf_map_lookup_elem(&egress_port_stats, &port);
        if (!stats) {
            return;
        }
    }
    if (passed) {
        __sync_fetch_and_add(&stats->passed, 1);
    } else {
        __sync_fetch_and_add(&stats->dropped, 1);
    }
}

static __always_inline void update_egress_drop_log(__u32 remote_ip, __u16 port, __u8 reason)
{
    struct drop_log_key key = {};
    key.source_ip = remote_ip;
    key.dest_port = port;
    key.reason = reason;
    key.reserved = egress_observe_only() ? 1 : 0;
    struct drop_log_value zero = {};
    struct drop_log_value *value = bpf_map_lookup_elem(&egress_drop_logs, &key);
    if (!value) {
        bpf_map_update_elem(&egress_drop_logs, &key, &zero, BPF_ANY);
        value = bpf_map_lookup_elem(&egress_drop_logs, &key);
        if (!value) {
            return;
        }
    }
    __sync_fetch_and_add(&value->drops, 1);
    value->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline __u16 parse_dest_port(__u8 protocol, void *trans_hdr, void *data_end)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = trans_hdr;
        if ((void *)(tcp + 1) > data_end) {
            return 0;
        }
        return bpf_ntohs(tcp->dest);
    }
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = trans_hdr;
        if ((void *)(udp + 1) > data_end) {
            return 0;
        }
        return bpf_ntohs(udp->dest);
    }
    return 0;
}

static __always_inline __u16 parse_source_port(__u8 protocol, void *trans_hdr, void *data_end)
{
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = trans_hdr;
        if ((void *)(tcp + 1) > data_end) {
            return 0;
        }
        return bpf_ntohs(tcp->source);
    }
    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = trans_hdr;
        if ((void *)(udp + 1) > data_end) {
            return 0;
        }
        return bpf_ntohs(udp->source);
    }
    return 0;
}

static __always_inline int reply_flow_alive(struct reply_flow_value *value)
{
    if (!value)
        return 0;
    __u32 cfg_key = NODEWALL_CONFIG_KEY;
    struct config_value *cfg = bpf_map_lookup_elem(&config_map, &cfg_key);
    __u64 timeout_ns = 60000000000ULL;
    if (cfg && cfg->reserved[1] > 0) {
        timeout_ns = ((__u64)cfg->reserved[1]) * 1000000000ULL;
    }

    __u64 now = bpf_ktime_get_ns();
    if (now > value->last_seen_ns && now - value->last_seen_ns > timeout_ns) {
        return 0;
    }

    return 1;
}

static __always_inline int is_established_reply(__u32 remote_ip, __u16 remote_port, __u16 local_port, __u8 protocol)
{
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || remote_port == 0 || local_port == 0) {
        return 0;
    }

    struct reply_flow_key key = {};
    key.remote_ip = remote_ip;
    key.remote_port = remote_port;
    key.local_port = local_port;
    key.protocol = protocol;
    struct reply_flow_value *value = bpf_map_lookup_elem(&reply_flows, &key);
    // Forwarded traffic can be source-NATed between the bridge and the
    // physical NIC. In that case the local ephemeral port seen by TC egress
    // is not always the port seen by ingress XDP on the reply. TC also keeps
    // a service-level wildcard entry (local_port == 0); use it only after
    // the exact five-tuple lookup so an unrelated service cannot open a
    // destination port by accident.
    if (!value) {
        key.local_port = 0;
        value = bpf_map_lookup_elem(&reply_service_flows, &key);
    }
    if (!value) {
        return 0;
    }

    return reply_flow_alive(value);
}

// Egress replies consult only accepted inbound flows, never outbound state
// or a service wildcard created by this same packet.
static __always_inline int is_inbound_reply(__u32 remote_ip, __u16 remote_port, __u16 local_port, __u8 protocol)
{
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || remote_port == 0 || local_port == 0)
        return 0;
    struct reply_flow_key key = {};
    key.remote_ip = remote_ip;
    key.remote_port = remote_port;
    key.local_port = local_port;
    key.protocol = protocol;
    return reply_flow_alive(bpf_map_lookup_elem(&inbound_reply_flows, &key));
}

// Record the reverse direction of an ingress flow after the packet has been
// accepted. TC egress uses this separate bounded map to let SSH/HTTP/DNS
// responses leave the host even though their destination port is usually a
// client ephemeral port rather than the service port that was allowed inbound.
static __always_inline void track_inbound_reply(__u32 remote_ip, __u16 remote_port, __u16 local_port, __u8 protocol)
{
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || remote_port == 0 || local_port == 0) {
        return;
    }

    struct reply_flow_key key = {};
    key.remote_ip = remote_ip;
    key.remote_port = remote_port;
    key.local_port = local_port;
    key.protocol = protocol;
    struct reply_flow_value value = {
        .last_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&inbound_reply_flows, &key, &value, BPF_ANY);
}

static __always_inline void update_reply_allow_log(__u32 source_ip, __u16 port, __u8 protocol)
{
    struct reply_log_key key = {};
    key.source_ip = source_ip;
    key.dest_port = port;
    key.protocol = protocol;
    struct reply_log_value zero = {};
    struct reply_log_value *value = bpf_map_lookup_elem(&reply_allow_logs, &key);

    if (!value) {
        bpf_map_update_elem(&reply_allow_logs, &key, &zero, BPF_ANY);
        value = bpf_map_lookup_elem(&reply_allow_logs, &key);
        if (!value) {
            return;
        }
    }

    __sync_fetch_and_add(&value->allowed, 1);
    value->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline int port_allowed(__u8 protocol, void *trans_hdr, void *data_end, __u16 *port_out)
{
    __u16 dport = parse_dest_port(protocol, trans_hdr, data_end);
    if (dport == 0) {
        return 0;
    }

    if (port_out) {
        *port_out = dport;
    }

    struct port_rule_key key = {};
    key.protocol = protocol;
    key.port = dport;
    struct port_value *allow = bpf_map_lookup_elem(&allow_ports, &key);
    return allow && allow->allow;
}

static __always_inline int public_port_allowed(__u8 protocol, void *trans_hdr, void *data_end, __u16 *port_out)
{
    __u16 dport = parse_dest_port(protocol, trans_hdr, data_end);
    if (dport == 0) {
        return 0;
    }

    if (port_out && *port_out == 0) {
        *port_out = dport;
    }

    struct port_rule_key key = {};
    key.protocol = protocol;
    key.port = dport;
    struct port_value *allow = bpf_map_lookup_elem(&public_ports, &key);
    return allow && allow->allow;
}

static __always_inline int port_denied(__u8 protocol, void *trans_hdr, void *data_end, __u16 *port_out)
{
    __u16 dport = parse_dest_port(protocol, trans_hdr, data_end);
    if (dport == 0) {
        return 0;
    }

    if (port_out && *port_out == 0) {
        *port_out = dport;
    }

    struct port_rule_key key = {};
    key.protocol = protocol;
    key.port = dport;
    struct port_value *deny = bpf_map_lookup_elem(&deny_ports, &key);
    return deny && deny->allow;
}

static __always_inline int rate_limited(__u32 source_ip, __u8 protocol, __u16 dest_port)
{
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || dest_port == 0) {
        return 0;
    }

    struct rate_limit_key key = {};
    key.source_ip = source_ip;
    key.dest_port = dest_port;
    key.protocol = protocol;
    struct rate_limit_value *limit = bpf_map_lookup_elem(&rate_limits, &key);
    if (!limit || limit->requests_per_minute == 0 || limit->burst == 0) {
        return 0;
    }

    __u64 now_ms = bpf_ktime_get_ns() / 1000000ULL;
    __u8 allowed = 0;
    bpf_spin_lock(&limit->lock);

    if (limit->last_refill_ms == 0) {
        limit->last_refill_ms = now_ms;
        if (limit->tokens > limit->burst) {
            limit->tokens = limit->burst;
        }
    } else if (now_ms > limit->last_refill_ms) {
        __u64 elapsed_ms = now_ms - limit->last_refill_ms;
        if (elapsed_ms > 60000ULL) {
            elapsed_ms = 60000ULL;
        }
        __u64 refill = (elapsed_ms * limit->requests_per_minute) / 60000ULL;
        if (refill > 0) {
            limit->tokens = limit->tokens + refill;
            if (limit->tokens > limit->burst) {
                limit->tokens = limit->burst;
            }
            limit->last_refill_ms = now_ms;
        }
    }

    if (limit->tokens > 0) {
        limit->tokens--;
        allowed = 1;
    }
    bpf_spin_unlock(&limit->lock);
    return !allowed;
}

static __always_inline int egress_rate_limited(__u32 remote_ip, __u8 protocol, __u16 dest_port)
{
    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) || dest_port == 0) {
        return 0;
    }

    struct rate_limit_key key = {};
    key.source_ip = remote_ip;
    key.dest_port = dest_port;
    key.protocol = protocol;
    struct rate_limit_value *limit = bpf_map_lookup_elem(&egress_rate_limits, &key);
    if (!limit || limit->requests_per_minute == 0 || limit->burst == 0) {
        return 0;
    }

    __u64 now_ms = bpf_ktime_get_ns() / 1000000ULL;
    __u8 allowed = 0;
    bpf_spin_lock(&limit->lock);
    if (limit->last_refill_ms == 0) {
        limit->last_refill_ms = now_ms;
        if (limit->tokens > limit->burst) {
            limit->tokens = limit->burst;
        }
    } else if (now_ms > limit->last_refill_ms) {
        __u64 elapsed_ms = now_ms - limit->last_refill_ms;
        if (elapsed_ms > 60000ULL) {
            elapsed_ms = 60000ULL;
        }
        __u64 refill = (elapsed_ms * limit->requests_per_minute) / 60000ULL;
        if (refill > 0) {
            limit->tokens = limit->tokens + refill;
            if (limit->tokens > limit->burst) {
                limit->tokens = limit->burst;
            }
            limit->last_refill_ms = now_ms;
        }
    }
    if (limit->tokens > 0) {
        limit->tokens--;
        allowed = 1;
    }
    bpf_spin_unlock(&limit->lock);
    return !allowed;
}

// Classify a complete DHCP client broadcast for the audit log only. Never
// allow all port-67 traffic or source 0.0.0.0: a host DHCP service still needs
// an explicit policy, while guest forwarding belongs to the bridge/CNI.
static __always_inline int is_dhcp_broadcast(struct ethhdr *eth, struct iphdr *ip,
                                             void *transport, void *data_end)
{
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP ||
        ip->daddr != bpf_htonl(0xffffffff) || (ip->frag_off & bpf_htons(0x3fff)))
        return 0;
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (eth->h_dest[i] != 0xff)
            return 0;
    }
    struct udphdr *udp = transport;
    if ((void *)(udp + 1) > data_end || udp->source != bpf_htons(68) || udp->dest != bpf_htons(67))
        return 0;
    __u32 length = bpf_ntohs(udp->len);
    // Linux 5.4 does not retain the 16-bit bound across every byte-swap path.
    // Bound the IPv4 UDP length explicitly before adding it to a packet
    // pointer; the maximum excludes the minimum IPv4 header itself.
    if (length < sizeof(*udp) + 240 || length > 65535 - sizeof(struct iphdr))
        return 0;
    if ((void *)udp + length > data_end ||
        bpf_ntohs(ip->tot_len) < ip->ihl * 4 + length)
        return 0;
    __u8 *bootp = (void *)(udp + 1);
    if ((void *)bootp + 240 > data_end || bootp[0] != 1 || bootp[1] != 1 || bootp[2] != ETH_ALEN ||
        bootp[236] != 99 || bootp[237] != 130 || bootp[238] != 83 || bootp[239] != 99)
        return 0;
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (bootp[28 + i] != eth->h_source[i])
            return 0;
    }
    return 1;
}

static __always_inline int enforce_host_ingress(void *data, void *data_end)
{
    // An attach with no active policy is a fail-open operation. Keep this
    // before packet parsing so an unexpected L2/L3 layout cannot interrupt
    // management traffic while the policy is still being prepared.
    if (!policy_enforced() && !rate_limit_enabled() && !egress_policy_enforced() && ipv6_action() == XDP_PASS) {
        update_stats(1);
        return XDP_PASS;
    }

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        update_stats(0);
        return drop_action();
    }

    void *network_header = NULL;
    int protocol = parse_ethernet(data, data_end, &network_header);
    if (protocol < 0) {
        update_stats(0);
        return drop_action();
    }
    if (protocol == ETH_P_IPV6) {
        int action = ipv6_action();
        update_stats(action == XDP_PASS);
        return action;
    }

    if (protocol != ETH_P_IP) {
        // ARP and other non-IP Ethernet protocols must remain available even
        // when the operator chooses to deny IPv6 traffic.
        update_stats(1);
        return XDP_PASS;
    }

    struct iphdr *ip = network_header;
    if ((void *)(ip + 1) > data_end) {
        update_stats(0);
        return drop_action();
    }

    __u32 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(*ip) || (void *)ip + ip_header_len > data_end) {
        update_stats(0);
        return drop_action();
    }

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = ip->saddr,
    };
    struct allow_value *allow = bpf_map_lookup_elem(&allow_ipv4, &key);
    struct allow_value *bypass = bpf_map_lookup_elem(&bypass_ipv4, &key);
    struct allow_value *block = bpf_map_lookup_elem(&block_ipv4, &key);
    struct allow_value *icmp_allow_src = bpf_map_lookup_elem(&icmp_allow_ipv4, &key);
    struct allow_value *icmp_block_src = bpf_map_lookup_elem(&icmp_block_ipv4, &key);
    void *trans_hdr = (void *)ip + (ip->ihl * 4);
    __u16 dport = 0;
    __u16 sport = 0;
    int deny_port = port_denied(ip->protocol, trans_hdr, data_end, &dport);
    int public_allow = public_port_allowed(ip->protocol, trans_hdr, data_end, &dport);
    int port_allow = port_allowed(ip->protocol, trans_hdr, data_end, &dport);
    sport = parse_source_port(ip->protocol, trans_hdr, data_end);
    int is_port_proto = (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP);
    struct port_rule_key icmp_key = {};
    int icmp_public_allow = 0;
    int icmp_port_allow = 0;
    int icmp_deny = 0;
    if (ip->protocol == IPPROTO_ICMP) {
        icmp_key.protocol = IPPROTO_ICMP;
        icmp_key.port = 0;
        struct port_value *icmp_public = bpf_map_lookup_elem(&public_ports, &icmp_key);
        struct port_value *icmp_allow = bpf_map_lookup_elem(&allow_ports, &icmp_key);
        struct port_value *icmp_block = bpf_map_lookup_elem(&deny_ports, &icmp_key);
        icmp_public_allow = icmp_public && icmp_public->allow;
        icmp_port_allow = icmp_allow && icmp_allow->allow;
        icmp_deny = icmp_block && icmp_block->allow;
    }

    if (rate_limit_enabled() && rate_limited(ip->saddr, ip->protocol, dport)) {
        update_drop_log(ip->saddr, dport, NODEWALL_DROP_RATE_LIMITED);
        update_source_stats(ip->saddr, 0);
        if (dport != 0) {
            update_port_stats(dport, 0);
        }
        update_stats(0);
        return drop_action();
    }

    if (!policy_enforced()) {
        track_inbound_reply(ip->saddr, sport, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (bypass && bypass->allow) {
        track_inbound_reply(ip->saddr, sport, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (block && block->allow) {
        update_drop_log(ip->saddr, dport, NODEWALL_DROP_BLOCKED_SOURCE);
        update_source_stats(ip->saddr, 0);
        if (dport != 0) {
            update_port_stats(dport, 0);
        }
        update_stats(0);
        return drop_action();
    }

    if (ip->protocol == IPPROTO_ICMP && icmp_block_src && icmp_block_src->allow) {
        update_drop_log(ip->saddr, 0, NODEWALL_DROP_BLOCKED_SOURCE);
        update_source_stats(ip->saddr, 0);
        update_stats(0);
        return drop_action();
    }

    // A port deny is an explicit revocation and must take precedence over a
    // reply-flow entry. Otherwise a browser's existing keep-alive connection
    // can keep refreshing that entry after the operator has denied the port.
    if (deny_port) {
        update_drop_log(ip->saddr, dport, NODEWALL_DROP_DENIED_PORT);
        update_source_stats(ip->saddr, 0);
        if (dport != 0) {
            update_port_stats(dport, 0);
        }
        update_stats(0);
        return drop_action();
    }

    // An outbound policy must not break the return half of an established
    // DNS/HTTP/HTTPS connection. Explicit ingress block and deny rules have
    // already run above, so the reply-flow entry is safe to honor here even
    // while TC egress enforcement is enabled.
    if (is_established_reply(ip->saddr, sport, dport, ip->protocol)) {
        update_reply_allow_log(ip->saddr, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (public_allow) {
        track_inbound_reply(ip->saddr, sport, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (icmp_deny) {
        update_drop_log(ip->saddr, 0, NODEWALL_DROP_DENIED_PORT);
        update_source_stats(ip->saddr, 0);
        update_stats(0);
        return drop_action();
    }

    if (icmp_public_allow) {
        update_source_stats(ip->saddr, 1);
        update_stats(1);
        return XDP_PASS;
    }

    if (!is_port_proto) {
        if (ip->protocol == IPPROTO_ICMP && icmp_allow_src && icmp_allow_src->allow) {
            update_source_stats(ip->saddr, 1);
            update_stats(1);
            return XDP_PASS;
        }
        if (ip->protocol == IPPROTO_ICMP && port_policy_enabled() && allow && allow->allow && icmp_port_allow) {
            update_source_stats(ip->saddr, 1);
            update_stats(1);
            return XDP_PASS;
        }
        if (allow && allow->allow) {
            update_source_stats(ip->saddr, 1);
            update_stats(1);
            return XDP_PASS;
        }
        update_drop_log(ip->saddr, dport, NODEWALL_DROP_SOURCE_NOT_ALLOWED);
        update_source_stats(ip->saddr, 0);
        update_stats(0);
        return drop_action();
    }

    if (port_policy_enabled()) {
        // An allowed port is an interface-level ingress rule. It must not
        // depend on an unrelated source-IP allowlist entry; otherwise a
        // node can publish TCP/22 and still lose SSH when the source is not
        // also present in allow_ipv4. A source allowlist entry remains a
        // separate broader bypass below.
        if (port_allow) {
            track_inbound_reply(ip->saddr, sport, dport, ip->protocol);
            update_source_stats(ip->saddr, 1);
            if (dport != 0) {
                update_port_stats(dport, 1);
            }
            update_stats(1);
            return XDP_PASS;
        }

        update_drop_log(ip->saddr, dport, is_dhcp_broadcast(eth, ip, trans_hdr, data_end)
                        ? NODEWALL_DROP_DHCP_BROADCAST : NODEWALL_DROP_RESTRICTED_POLICY);
        update_source_stats(ip->saddr, 0);
        if (dport != 0) {
            update_port_stats(dport, 0);
        }
        update_stats(0);
        return drop_action();
    }

    if (allow && allow->allow) {
        track_inbound_reply(ip->saddr, sport, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    update_drop_log(ip->saddr, dport, is_dhcp_broadcast(eth, ip, trans_hdr, data_end)
                    ? NODEWALL_DROP_DHCP_BROADCAST : NODEWALL_DROP_SOURCE_NOT_ALLOWED);
    update_source_stats(ip->saddr, 0);
    if (dport != 0) {
        update_port_stats(dport, 0);
    }
    update_stats(0);
    return drop_action();
}

static __always_inline int packet_routes_away(void *ctx, void *data, void *data_end,
                                             __u32 ingress_ifindex)
{
    void *network_header = NULL;
    int protocol = parse_ethernet(data, data_end, &network_header);
    struct bpf_fib_lookup route = {};
    route.ifindex = ingress_ifindex;
    if (protocol == ETH_P_IP) {
        struct iphdr *ip = network_header;
        if ((void *)(ip + 1) > data_end)
            return 0;
        route.family = 2; // AF_INET; use the kernel's local/routing tables.
        route.l4_protocol = ip->protocol;
        route.tos = ip->tos;
        route.tot_len = bpf_ntohs(ip->tot_len);
        route.ipv4_src = ip->saddr;
        route.ipv4_dst = ip->daddr;
    } else if (protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip = network_header;
        if ((void *)(ip + 1) > data_end)
            return 0;
        route.family = 10; // AF_INET6
        route.l4_protocol = ip->nexthdr;
        route.tot_len = bpf_ntohs(ip->payload_len) + sizeof(*ip);
        __builtin_memcpy(route.ipv6_src, &ip->saddr, sizeof(ip->saddr));
        __builtin_memcpy(route.ipv6_dst, &ip->daddr, sizeof(ip->daddr));
    } else {
        return 0;
    }
    int result = bpf_fib_lookup(ctx, &route, sizeof(route), 0);
    // Local, multicast, unavailable and prohibited routes never create a
    // bypass. An unresolved neighbour/MTU still belongs to the forwarding
    // stack, which must retain its own resolution and fragmentation handling.
    return result == BPF_FIB_LKUP_RET_SUCCESS || result == BPF_FIB_LKUP_RET_NO_NEIGH ||
           result == BPF_FIB_LKUP_RET_FRAG_NEEDED || result == BPF_FIB_LKUP_RET_UNSUPP_LWT;
}

static __always_inline int bridge_host_mac(struct ethhdr *eth, struct bridge_scope_value *scope)
{
    __u32 port_difference = 0, bridge_difference = 0;
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        port_difference |= eth->h_dest[i] ^ scope->interface_mac[i];
        bridge_difference |= eth->h_dest[i] ^ scope->bridge_mac[i];
    }
    return port_difference == 0 || bridge_difference == 0;
}

SEC("xdp")
int xdp_acl(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 key = 0;
    struct bridge_scope_value *scope = bpf_map_lookup_elem(&bridge_scope, &key);
    struct ethhdr *eth = data;
    if (scope && scope->bridge_ifindex && (void *)(eth + 1) <= data_end &&
        ((eth->h_dest[0] & 1) || !bridge_host_mac(eth, scope) ||
         packet_routes_away(ctx, data, data_end, scope->bridge_ifindex))) {
        // A physical XDP DROP would discard the guest's copy too, including
        // DHCP, IPv6 discovery and multicast. Defer only the host-local copy
        // to bridge TC ingress; ordinary bridge forwarding never visits it.
        __u32 origin = scope->ingress_ifindex;
        if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct bridge_ingress_metadata)) < 0)
            return drop_action();
        data = (void *)(long)ctx->data;
        struct bridge_ingress_metadata *metadata = (void *)(long)ctx->data_meta;
        if ((void *)(metadata + 1) > data)
            return drop_action();
        metadata->magic = NODEWALL_BRIDGE_METADATA_MAGIC;
        metadata->ingress_ifindex = origin;
        return XDP_PASS;
    }
    // Routed CNIs and Docker uplinks need not be bridge slaves. Let the
    // kernel route their forwarded packets to the existing CNI/FORWARD rules;
    // local routes still enter the host policy. Private-address allowlists
    // would both miss pod networks and expose host ports to those networks.
    if ((!scope || !scope->bridge_ifindex) &&
        packet_routes_away(ctx, data, data_end, ctx->ingress_ifindex))
        return XDP_PASS;
    return enforce_host_ingress(data, data_end);
}

SEC("tc/ingress")
int tc_bridge_host(struct __sk_buff *skb)
{
    // Continue classification after an allowed/unrelated packet. Returning
    // TC_ACT_OK would skip another uplink's policy or a platform TC filter.
    // A promiscuous bridge can also hand the host an observation copy of a
    // guest unicast. It is not local delivery and must not create host drops.
    if (skb->pkt_type == 3) // PACKET_OTHERHOST
        return TC_ACT_UNSPEC;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct bridge_ingress_metadata *metadata = (void *)(long)skb->data_meta;
    if ((void *)(metadata + 1) > data || metadata->magic != NODEWALL_BRIDGE_METADATA_MAGIC)
        return TC_ACT_UNSPEC;
    __u32 key = 0;
    struct bridge_scope_value *scope = bpf_map_lookup_elem(&bridge_scope, &key);
    if (!scope || metadata->ingress_ifindex != scope->ingress_ifindex)
        return TC_ACT_UNSPEC;
    if (packet_routes_away(skb, data, data_end, scope->bridge_ifindex)) {
        return TC_ACT_UNSPEC;
    }
    return enforce_host_ingress(data, data_end) == XDP_DROP ? TC_ACT_SHOT : TC_ACT_UNSPEC;
}

static __always_inline int enforce_host_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    void *network_header = NULL;
    int protocol = parse_ethernet(data, data_end, &network_header);
    if (protocol < 0) {
        // A malformed packet must not become a way to interrupt the host's
        // recovery path. Fail open and leave the evidence to the kernel logs.
        return 0;
    }

    // At the physical NIC's TC egress hook, a non-zero ingress_ifindex marks
    // a packet forwarded from another interface (for example a VM tap, a
    // container veth, or a Linux bridge). The host firewall must not apply its
    // host-originated egress allowlist to that traffic; the bridge/CNI owns
    // its forwarding policy. The wrapper records allowed IPv4 flows so their
    // corresponding replies can pass the physical NIC's ingress XDP hook.
    __u8 forwarded = skb->ingress_ifindex != 0;

    if (protocol == ETH_P_IPV6) {
        __u8 drop = !forwarded && egress_policy_enforced() && egress_non_ipv4_action() == NODEWALL_NON_IPV4_DROP;
        update_egress_stats(!drop);
        return drop ? egress_drop_action() : 0;
    }
    if (protocol != ETH_P_IP) {
        update_egress_stats(1);
        return 0;
    }

    struct iphdr *ip = network_header;
    if ((void *)(ip + 1) > data_end) {
        update_egress_stats(1);
        return 0;
    }

    __u32 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(*ip) || (void *)ip + ip_header_len > data_end) {
        update_egress_stats(1);
        return 0;
    }

    __u32 remote_ip = ip->daddr;
    void *trans_hdr = (void *)ip + ip_header_len;
    __u16 dport = parse_dest_port(ip->protocol, trans_hdr, data_end);
    __u16 sport = parse_source_port(ip->protocol, trans_hdr, data_end);

    if (forwarded) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }

    if (!egress_policy_enforced() && !egress_rate_limit_enabled()) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }

    struct ipv4_lpm_key key = {
        .prefixlen = 32,
        .addr = remote_ip,
    };
    struct allow_value *allow = bpf_map_lookup_elem(&egress_allow_ipv4, &key);
    struct allow_value *bypass = bpf_map_lookup_elem(&egress_bypass_ipv4, &key);
    struct allow_value *block = bpf_map_lookup_elem(&egress_block_ipv4, &key);
    struct allow_value *icmp_allow_src = bpf_map_lookup_elem(&egress_icmp_allow_ipv4, &key);
    struct allow_value *icmp_block_src = bpf_map_lookup_elem(&egress_icmp_block_ipv4, &key);
    int is_port_proto = ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP;
    int deny_port = 0;
    int public_allow = 0;
    int port_allow = 0;
    int icmp_public_allow = 0;
    int icmp_port_allow = 0;
    int icmp_deny = 0;

    if (is_port_proto) {
        struct port_rule_key port_key = {};
        port_key.protocol = ip->protocol;
        port_key.port = dport;
        struct port_value *deny = bpf_map_lookup_elem(&egress_deny_ports, &port_key);
        struct port_value *public = bpf_map_lookup_elem(&egress_public_ports, &port_key);
        struct port_value *allowed = bpf_map_lookup_elem(&egress_allow_ports, &port_key);
        deny_port = deny && deny->allow;
        public_allow = public && public->allow;
        port_allow = allowed && allowed->allow;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct port_rule_key icmp_key = {};
        icmp_key.protocol = IPPROTO_ICMP;
        struct port_value *public = bpf_map_lookup_elem(&egress_public_ports, &icmp_key);
        struct port_value *allowed = bpf_map_lookup_elem(&egress_allow_ports, &icmp_key);
        struct port_value *deny = bpf_map_lookup_elem(&egress_deny_ports, &icmp_key);
        icmp_public_allow = public && public->allow;
        icmp_port_allow = allowed && allowed->allow;
        icmp_deny = deny && deny->allow;
    }

    if (egress_rate_limit_enabled() && egress_rate_limited(remote_ip, ip->protocol, dport)) {
        update_egress_drop_log(remote_ip, dport, NODEWALL_DROP_RATE_LIMITED);
        update_egress_source_stats(remote_ip, 0);
        if (dport != 0) {
            update_egress_port_stats(dport, 0);
        }
        update_egress_stats(0);
        return egress_drop_action();
    }
    if (bypass && bypass->allow) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }
    if (block && block->allow) {
        update_egress_drop_log(remote_ip, dport, NODEWALL_DROP_BLOCKED_SOURCE);
        update_egress_source_stats(remote_ip, 0);
        if (dport != 0) {
            update_egress_port_stats(dport, 0);
        }
        update_egress_stats(0);
        return egress_drop_action();
    }
    if (ip->protocol == IPPROTO_ICMP && icmp_block_src && icmp_block_src->allow) {
        update_egress_drop_log(remote_ip, 0, NODEWALL_DROP_BLOCKED_SOURCE);
        update_egress_source_stats(remote_ip, 0);
        update_egress_stats(0);
        return egress_drop_action();
    }
    if (deny_port || icmp_deny) {
        update_egress_drop_log(remote_ip, dport, NODEWALL_DROP_DENIED_PORT);
        update_egress_source_stats(remote_ip, 0);
        if (dport != 0) {
            update_egress_port_stats(dport, 0);
        }
        update_egress_stats(0);
        return egress_drop_action();
    }
    // Replies to an inbound SSH/HTTP/DNS connection use the client's
    // ephemeral destination port. Let the reverse flow through after explicit
    // egress blocks/denies, even when the outbound policy is default-deny.
    if (is_inbound_reply(remote_ip, dport, sport, ip->protocol)) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }
    if (public_allow || icmp_public_allow) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }
    if (ip->protocol == IPPROTO_ICMP && icmp_allow_src && icmp_allow_src->allow) {
        update_egress_source_stats(remote_ip, 1);
        update_egress_stats(1);
        return 0;
    }
    if (ip->protocol == IPPROTO_ICMP && egress_port_policy_enabled() && icmp_port_allow) {
        update_egress_source_stats(remote_ip, 1);
        update_egress_stats(1);
        return 0;
    }
    if (is_port_proto && egress_port_policy_enabled() && port_allow) {
        update_egress_source_stats(remote_ip, 1);
        update_egress_port_stats(dport, 1);
        update_egress_stats(1);
        return 0;
    }
    if (allow && allow->allow) {
        update_egress_source_stats(remote_ip, 1);
        if (dport != 0) {
            update_egress_port_stats(dport, 1);
        }
        update_egress_stats(1);
        return 0;
    }
    if (is_port_proto && egress_port_policy_enabled()) {
        update_egress_drop_log(remote_ip, dport, NODEWALL_DROP_RESTRICTED_POLICY);
        update_egress_source_stats(remote_ip, 0);
        update_egress_port_stats(dport, 0);
        update_egress_stats(0);
        return egress_drop_action();
    }
    if (egress_default_deny_enabled()) {
        update_egress_drop_log(remote_ip, dport, NODEWALL_DROP_SOURCE_NOT_ALLOWED);
        update_egress_source_stats(remote_ip, 0);
        if (dport != 0) {
            update_egress_port_stats(dport, 0);
        }
        update_egress_stats(0);
        return egress_drop_action();
    }

    update_egress_source_stats(remote_ip, 1);
    if (dport != 0) {
        update_egress_port_stats(dport, 1);
    }
    update_egress_stats(1);
    return 0;
}

SEC("tc/egress")
int tc_egress_track(struct __sk_buff *skb)
{
    int action = enforce_host_egress(skb);
    if (action == TC_ACT_SHOT)
        return action;

    // Record state only after the egress verdict. A rejected request must not
    // open either an exact return flow or a DNS/NAT service wildcard.
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    void *header = NULL;
    if (parse_ethernet(data, data_end, &header) == ETH_P_IP) {
        struct iphdr *ip = header;
        if ((void *)(ip + 1) <= data_end) {
            __u32 length = ip->ihl * 4;
            if (length >= sizeof(*ip) && (void *)ip + length <= data_end) {
                void *transport = (void *)ip + length;
                __u16 sport = parse_source_port(ip->protocol, transport, data_end);
                __u16 dport = parse_dest_port(ip->protocol, transport, data_end);
                if ((ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) && sport && dport) {
                    struct reply_flow_key key = {};
                    key.remote_ip = ip->daddr;
                    key.remote_port = dport;
                    key.local_port = sport;
                    key.protocol = ip->protocol;
                    struct reply_flow_value value = {.last_seen_ns = bpf_ktime_get_ns()};
                    bpf_map_update_elem(&reply_flows, &key, &value, BPF_ANY);
                    // Preserve the existing bounded NAT/DNS fallback after an
                    // actual allowed outbound request to that remote service.
                    if (skb->ingress_ifindex || dport == 53) {
                        key.local_port = 0;
                        bpf_map_update_elem(&reply_service_flows, &key, &value, BPF_ANY);
                    }
                }
            }
        }
    }
    // Cooperate with platform TC programs instead of terminating their chain.
    return TC_ACT_UNSPEC;
}
