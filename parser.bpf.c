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
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

SEC("sockops")
int sock_ops(struct bpf_sock_ops *ops) {
    int op = (int)ops->op;
    bpf_printk("local: %d, remote: %d, op: %d", ops->local_port, bpf_ntohl(ops->remote_port), op);

    if (bpf_ntohl(ops->remote_port) != port) {
        return 1;
    }

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        if (bpf_sock_hash_update(ops, &sock_map, (void*)&key, BPF_NOEXIST) < 0) {
            bpf_printk("ERROR: Adding socket failed.");
        }

        bpf_printk("Added socket (%d)", key);
    }

    return 1;
}

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    bpf_printk("Parser %d bytes", skb->len);
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    bpf_printk("Verdict %d bytes", skb->len);

    #ifdef REDIRECT
    return bpf_sk_redirect_hash(skb, &sock_map, (void*)&key, 0);
    #else
    return SK_PASS;
    #endif
}