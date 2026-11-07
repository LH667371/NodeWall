#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_acl.h"

char LICENSE[] SEC("license") = "GPL";

struct nodewall_vlan_header {
    __be16 tag_control;
    __be16 encapsulated_protocol;
};

#define NODEWALL_DROP_BLOCKED_SOURCE 1
#define NODEWALL_DROP_DENIED_PORT 2
#define NODEWALL_DROP_RESTRICTED_POLICY 3
#define NODEWALL_DROP_SOURCE_NOT_ALLOWED 4
#define NODEWALL_DROP_RATE_LIMITED 5

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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct reply_log_key);
    __type(value, struct reply_log_value);
    __uint(max_entries, 1024);
} reply_allow_logs SEC(".maps");

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
    if (!value) {
        return 0;
    }

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

SEC("xdp")
int xdp_acl(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // An attach with no active policy is a fail-open operation. Keep this
    // before packet parsing so an unexpected L2/L3 layout cannot interrupt
    // management traffic while the policy is still being prepared.
    if (!policy_enforced() && !rate_limit_enabled() && ipv6_action() == XDP_PASS) {
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
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (bypass && bypass->allow) {
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

    if (!egress_policy_enforced() && is_established_reply(ip->saddr, sport, dport, ip->protocol)) {
        update_reply_allow_log(ip->saddr, dport, ip->protocol);
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    if (public_allow) {
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
            update_source_stats(ip->saddr, 1);
            if (dport != 0) {
                update_port_stats(dport, 1);
            }
            update_stats(1);
            return XDP_PASS;
        }

        update_drop_log(ip->saddr, dport, NODEWALL_DROP_RESTRICTED_POLICY);
        update_source_stats(ip->saddr, 0);
        if (dport != 0) {
            update_port_stats(dport, 0);
        }
        update_stats(0);
        return drop_action();
    }

    if (allow && allow->allow) {
        update_source_stats(ip->saddr, 1);
        if (dport != 0) {
            update_port_stats(dport, 1);
        }
        update_stats(1);
        return XDP_PASS;
    }

    update_drop_log(ip->saddr, dport, NODEWALL_DROP_SOURCE_NOT_ALLOWED);
    update_source_stats(ip->saddr, 0);
    if (dport != 0) {
        update_port_stats(dport, 0);
    }
    update_stats(0);
    return drop_action();
}

SEC("tc/egress")
int tc_egress_track(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return 0;
    }

    void *network_header = NULL;
    if (parse_ethernet(data, data_end, &network_header) != ETH_P_IP) {
        return 0;
    }

    struct iphdr *ip = network_header;
    if ((void *)(ip + 1) > data_end) {
        return 0;
    }

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        return 0;
    }

    void *trans_hdr = (void *)ip + (ip->ihl * 4);
    __u16 remote_port = parse_dest_port(ip->protocol, trans_hdr, data_end);
    __u16 local_port = parse_source_port(ip->protocol, trans_hdr, data_end);
    if (remote_port == 0 || local_port == 0) {
        return 0;
    }

    struct reply_flow_key key = {};
    key.remote_ip = ip->daddr;
    key.remote_port = remote_port;
    key.local_port = local_port;
    key.protocol = ip->protocol;
    struct reply_flow_value value = {
        .last_seen_ns = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&reply_flows, &key, &value, BPF_ANY);
    return 0;
}
