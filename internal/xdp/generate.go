package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel -type ipv4_lpm_key -type allow_value -type stats_value -type config_value -type source_stats_value -type drop_log_key -type drop_log_value -type reply_flow_key -type reply_flow_value -type reply_log_key -type reply_log_value -no-global-types -no-strip -output-dir ../../bpf/gen xdpacl ../../bpf/xdp_acl.c -- -I../../bpf
