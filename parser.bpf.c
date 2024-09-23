#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

const __u32 port = 8000;
const __u32 key = 1;

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

SEC("sockops")
int sock_ops(struct bpf_sock_ops *ops) {
    __u32 lport = ops->local_port;
    __u32 rport = bpf_ntohl(ops->remote_port);

    if (lport == port || rport == port) {
        bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
        bpf_printk("sockop: %d (%d -> %d)", ops->op, lport, rport);
    }

    if (lport == port) {
        if (ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
            if (bpf_sock_hash_update(ops, &sock_map, (void*)&key, BPF_NOEXIST) < 0) {
                bpf_printk("ERROR: Adding socket failed.");
            }

            bpf_printk("Added socket (%d)", key);
        }
    }

    return 0;
}

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    bpf_printk("Parser %dB (%d -> %d)", skb->len, skb->local_port, bpf_ntohl(skb->remote_port));
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    bpf_printk("Verdict %dB (%d -> %d)", skb->len, skb->local_port, bpf_ntohl(skb->remote_port));

    #ifdef REDIRECT
    int r = bpf_sk_redirect_hash(skb, &sock_map, (void*)&key, BPF_F_INGRESS);
    bpf_printk("Success: %d", r);
    return r;
    #else
    return SK_PASS;
    #endif
}