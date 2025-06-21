#include <linux/bpf.h>
#include <bpf_helpers.h>
#include "nkbinder.h"

DEFINE_BPF_MAP(binder_transaction_map, LRU_HASH, int, struct  binder_transaction_event, 1024);

struct binder_transaction_args {
    unsigned long long ignore;

    int debug_id;
    int target_node;
    int to_proc;
    int to_thread;
    int reply;
    unsigned int code;
    unsigned int flags;
};

DEFINE_BPF_PROG("tracepoint/binder/binder_transaction", AID_ROOT, AID_SYSTEM, tp_binder_transaction)
(struct binder_transaction_args *args) {
     __u64 uid_gid = bpf_get_current_uid_gid();
     __u32 uid = uid_gid >> 32;
     __u64 pid_tgid = bpf_get_current_pid_tgid();
     __u32 pid = pid_tgid >> 32;
     struct binder_transaction_event event = {
        uid,pid,
        args->to_proc,
        args->code,
        args->flags,
     };
    int debug_id = args->debug_id;
    bpf_binder_transaction_map_update_elem(&debug_id, &event, BPF_ANY);
    return 0;
}

LICENSE("GPL");

