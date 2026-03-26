#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

#define EVT_CONNECT 1
#define EVT_SEND    2
#define EVT_RECV    3
#define EVT_CLOSE   4

struct net_event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u32 bytes;
    u8  event_type;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

/* Optional: filter to specific PIDs */
BPF_HASH(target_pids, u32, u8);

static __always_inline int submit_event(
    struct pt_regs *ctx,
    u8 event_type,
    u32 bytes
) {
    struct net_event_t e = {};
    struct task_struct *task;

    e.ts_ns = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    e.ppid = task->real_parent->tgid;

    e.bytes = bytes;
    e.event_type = event_type;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
/* Connection start */
int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    return submit_event(ctx, EVT_CONNECT, 0);
}

/* Data sent */
int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 size = (u32)PT_REGS_PARM3(ctx);
    return submit_event(ctx, EVT_SEND, size);
}

/* Data received */
int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    u32 size = (u32)PT_REGS_PARM3(ctx);
    return submit_event(ctx, EVT_RECV, size);
}

/* Connection close */
int kprobe__tcp_close(struct pt_regs *ctx) {
    return submit_event(ctx, EVT_CLOSE, 0);
}
