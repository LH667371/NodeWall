#ifndef NODEWALL_XDP_ACL_H
#define NODEWALL_XDP_ACL_H

#define NODEWALL_CONFIG_KEY 0
#define NODEWALL_NON_IPV4_PASS 0
#define NODEWALL_NON_IPV4_DROP 1

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

struct allow_value {
    __u8 allow;
};

struct port_value {
    __u8 allow;
};

struct port_rule_key {
    __u8 protocol;
    __u16 port;
    __u8 reserved;
};

struct rate_limit_key {
    __u32 source_ip;
    __u16 dest_port;
    __u8 protocol;
    __u8 reserved;
};

struct rate_limit_value {
    struct bpf_spin_lock lock;
    __u64 requests_per_minute;
    __u64 burst;
    __u64 tokens;
    __u64 last_refill_ms;
};

struct stats_value {
    __u64 passed;
    __u64 dropped;
};

struct source_stats_value {
    __u64 passed;
    __u64 dropped;
    __u64 last_seen_ns;
};

struct port_stats_value {
    __u64 passed;
    __u64 dropped;
};

struct drop_log_key {
    __u32 source_ip;
    __u16 dest_port;
    __u8 reason;
    // Bit 0 marks an observe-only match. Zero remains the legacy real drop.
    __u8 reserved;
};

struct drop_log_value {
    __u64 drops;
    __u64 last_seen_ns;
};

struct reply_log_key {
    __u32 source_ip;
    __u16 dest_port;
    __u8 protocol;
    __u8 reserved;
};

struct reply_log_value {
    __u64 allowed;
    __u64 last_seen_ns;
};

struct reply_flow_key {
    __u32 remote_ip;
    __u16 remote_port;
    __u16 local_port;
    __u8 protocol;
    __u8 reserved[3];
};

struct reply_flow_value {
    __u64 last_seen_ns;
};

struct bridge_scope_value {
    __u32 ingress_ifindex;
    __u32 bridge_ifindex;
    __u8 interface_mac[6];
    __u8 bridge_mac[6];
};

struct bridge_ingress_metadata {
    __u32 magic;
    __u32 ingress_ifindex;
};

struct config_value {
    __u8 non_ipv4_action;
    __u8 port_policy_enabled;
    // reserved[0]: ingress policy enforced
    // reserved[1]: reply flow timeout in seconds
    // reserved[2]: egress policy enforced
    // reserved[3]: ingress rate limit enabled
    // reserved[4]: ingress observe only; account for drops but always pass
    // reserved[5]: egress observe only; account for drops but always pass
    // reserved[6]: egress non-IPv4 action (0=pass, 1=drop)
    // reserved[7]: egress feature flags (bit 0=port policy, bit 1=rate limit,
    // bit 2=default deny for an allowlist/allowed-port policy)
    __u8 reserved[8];
};

#endif
