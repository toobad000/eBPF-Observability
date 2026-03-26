#!/usr/bin/env python3
import os
import time
import json
import socket
import threading
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from bcc import BPF

TCP_PAYLOAD = b"A" * (1024 * 256)
UDP_PAYLOAD = b"B" * 4096
HTTP_PORT = 8080
UDP_PORT = 9090
NUM_TCP_REQUESTS = 10
NUM_UDP_REQUESTS = 10

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/in.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16

#define K_SYSCALL_SEND   10
#define K_SYSCALL_RECV   11
#define K_SYSCALL_CONN   12
#define K_SYSCALL_CLOSE  13

#define K_TCP_SEND       20
#define K_TCP_RECV       21
#define K_TCP_CONN       22
#define K_TCP_CLOSE      23

#define K_SOFTIRQ_NET_RX 30
#define K_SOFTIRQ_NET_TX 31

#define K_MARK_NETDEV_Q  40
#define K_MARK_NETDEV_X  41
#define K_TCP_BUF_QUEUE  50

#define K_UDP_SEND       60
#define K_UDP_RECV       61

#define NET_TX_SOFTIRQ   2
#define NET_RX_SOFTIRQ   3

struct lat_event_t {
    u64 ts_ns;
    u64 dur_ns;
    u32 pid;
    u32 tid;
    u16 kind;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

BPF_HASH(start_sys_send,  u32, u64);
BPF_HASH(start_sys_recv,  u32, u64);
BPF_HASH(start_sys_conn,  u32, u64);
BPF_HASH(start_sys_close, u32, u64);

BPF_HASH(start_tcp_send,  u32, u64);
BPF_HASH(start_tcp_recv,  u32, u64);
BPF_HASH(start_tcp_conn,  u32, u64);
BPF_HASH(start_tcp_close, u32, u64);

BPF_HASH(start_udp_send,  u32, u64);
BPF_HASH(start_udp_recv,  u32, u64);

BPF_HASH(start_softirq,   u32, u64);

static __always_inline void emit_kprobe(struct pt_regs *ctx, u16 kind, u64 start_ns) {
    struct lat_event_t e = {};
    u64 now = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();

    e.ts_ns = now;
    e.dur_ns = start_ns ? now - start_ns : 0;
    e.pid = id >> 32;
    e.tid = (u32)id;
    e.kind = kind;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(ctx, &e, sizeof(e));
}

static __always_inline void emit_tp(void *args, u16 kind, u64 start_ns) {
    struct lat_event_t e = {};
    u64 now = bpf_ktime_get_ns();
    u64 id = bpf_get_current_pid_tgid();

    e.ts_ns = now;
    e.dur_ns = start_ns ? now - start_ns : 0;
    e.pid = id >> 32;
    e.tid = (u32)id;
    e.kind = kind;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));

    events.perf_submit(args, &e, sizeof(e));
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_sys_send.update(&tid, &ts);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_sendto) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_sys_send.lookup(&tid);
    if (!tsp) return 0;
    emit_tp(args, K_SYSCALL_SEND, *tsp);
    start_sys_send.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_sys_recv.update(&tid, &ts);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_sys_recv.lookup(&tid);
    if (!tsp) return 0;
    emit_tp(args, K_SYSCALL_RECV, *tsp);
    start_sys_recv.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_sys_conn.update(&tid, &ts);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_sys_conn.lookup(&tid);
    if (!tsp) return 0;
    emit_tp(args, K_SYSCALL_CONN, *tsp);
    start_sys_conn.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_sys_close.update(&tid, &ts);
    return 0;
}
TRACEPOINT_PROBE(syscalls, sys_exit_close) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_sys_close.lookup(&tid);
    if (!tsp) return 0;
    emit_tp(args, K_SYSCALL_CLOSE, *tsp);
    start_sys_close.delete(&tid);
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_tcp_send.update(&tid, &ts);
    return 0;
}
int kretprobe__tcp_sendmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_tcp_send.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_TCP_SEND, *tsp);
    start_tcp_send.delete(&tid);
    return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_tcp_recv.update(&tid, &ts);
    return 0;
}
int kretprobe__tcp_recvmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_tcp_recv.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_TCP_RECV, *tsp);
    start_tcp_recv.delete(&tid);
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_tcp_conn.update(&tid, &ts);
    return 0;
}
int kretprobe__tcp_v4_connect(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_tcp_conn.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_TCP_CONN, *tsp);
    start_tcp_conn.delete(&tid);
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_tcp_close.update(&tid, &ts);
    return 0;
}
int kretprobe__tcp_close(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_tcp_close.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_TCP_CLOSE, *tsp);
    start_tcp_close.delete(&tid);
    return 0;
}

int kprobe__udp_sendmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_udp_send.update(&tid, &ts);
    return 0;
}
int kretprobe__udp_sendmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_udp_send.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_UDP_SEND, *tsp);
    start_udp_send.delete(&tid);
    return 0;
}

int kprobe__udp_recvmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start_udp_recv.update(&tid, &ts);
    return 0;
}
int kretprobe__udp_recvmsg(struct pt_regs *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 *tsp = start_udp_recv.lookup(&tid);
    if (!tsp) return 0;
    emit_kprobe(ctx, K_UDP_RECV, *tsp);
    start_udp_recv.delete(&tid);
    return 0;
}

TRACEPOINT_PROBE(irq, softirq_entry) {
    u32 vec = args->vec;
    if (vec != NET_RX_SOFTIRQ && vec != NET_TX_SOFTIRQ) return 0;
    u64 ts = bpf_ktime_get_ns();
    start_softirq.update(&vec, &ts);
    return 0;
}
TRACEPOINT_PROBE(irq, softirq_exit) {
    u32 vec = args->vec;
    if (vec != NET_RX_SOFTIRQ && vec != NET_TX_SOFTIRQ) return 0;
    u64 *tsp = start_softirq.lookup(&vec);
    if (!tsp) return 0;
    emit_tp(args, vec == NET_RX_SOFTIRQ ? K_SOFTIRQ_NET_RX : K_SOFTIRQ_NET_TX, *tsp);
    start_softirq.delete(&vec);
    return 0;
}

int handle_net_dev_queue(void *args) {
    emit_tp(args, K_MARK_NETDEV_Q, 0);
    return 0;
}

int handle_net_dev_xmit(void *args) {
    emit_tp(args, K_MARK_NETDEV_X, 0);
    return 0;
}

int handle_tcp_retransmit_skb(void *args) {
    emit_tp(args, K_TCP_BUF_QUEUE, 0);
    return 0;
}

int handle_tcp_rcv_space_adjust(void *args) {
    emit_tp(args, K_TCP_BUF_QUEUE, 0);
    return 0;
}
"""

KIND_LABEL = {
    10: "syscall_send",
    11: "syscall_recv",
    12: "syscall_connect",
    13: "syscall_close",
    20: "tcp_sendmsg",
    21: "tcp_recvmsg",
    22: "tcp_v4_connect",
    23: "tcp_close",
    30: "softirq_net_rx",
    31: "softirq_net_tx",
    40: "net_dev_queue",
    41: "net_dev_xmit",
    50: "tcp_buffer_queue",
    60: "udp_sendmsg",
    61: "udp_recvmsg",
}

def tp_exists(category, event):
    return os.path.exists(f"/sys/kernel/debug/tracing/events/{category}/{event}/id") or \
           os.path.exists(f"/sys/kernel/tracing/events/{category}/{event}/id")

class HTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(TCP_PAYLOAD)))
        self.end_headers()
        self.wfile.write(TCP_PAYLOAD)

    def log_message(self, *args):
        pass

def run_http_server():
    server = HTTPServer(("127.0.0.1", HTTP_PORT), HTTPHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server

def run_udp_server():
    stop_event = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", UDP_PORT))
    sock.settimeout(0.2)

    def loop():
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(65535)
                sock.sendto(data, addr)
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return sock, stop_event, thread

def run_tcp_requests(n=10, force_close=True):
    out = []
    for i in range(n):
        s = time.monotonic_ns()
        headers = {"Connection": "close"} if force_close else {}
        try:
            r = requests.get(f"http://127.0.0.1:{HTTP_PORT}", timeout=5, headers=headers)
            body_len = len(r.content)
            e = time.monotonic_ns()
            out.append({
                "request_id": i + 1,
                "protocol": "tcp",
                "start_ns": s,
                "end_ns": e,
                "latency_ms": (e - s) / 1e6,
                "status_code": r.status_code,
                "success": r.status_code == 200,
                "response_bytes": body_len
            })
        except Exception as ex:
            e = time.monotonic_ns()
            out.append({
                "request_id": i + 1,
                "protocol": "tcp",
                "start_ns": s,
                "end_ns": e,
                "latency_ms": (e - s) / 1e6,
                "status_code": None,
                "success": False,
                "error": str(ex),
                "response_bytes": 0
            })
        time.sleep(0.1)
    return out

def run_udp_requests(n=10):
    out = []
    for i in range(n):
        s = time.monotonic_ns()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        try:
            client.sendto(UDP_PAYLOAD, ("127.0.0.1", UDP_PORT))
            data, _ = client.recvfrom(65535)
            e = time.monotonic_ns()
            out.append({
                "request_id": i + 1,
                "protocol": "udp",
                "start_ns": s,
                "end_ns": e,
                "latency_ms": (e - s) / 1e6,
                "success": data == UDP_PAYLOAD,
                "response_bytes": len(data)
            })
        except Exception as ex:
            e = time.monotonic_ns()
            out.append({
                "request_id": i + 1,
                "protocol": "udp",
                "start_ns": s,
                "end_ns": e,
                "latency_ms": (e - s) / 1e6,
                "success": False,
                "error": str(ex),
                "response_bytes": 0
            })
        finally:
            client.close()
        time.sleep(0.1)
    return out

def correlate_requests(reqs, raw_events, pid, protocol):
    for r in reqs:
        r["kernel_breakdown_ns"] = {}
        r["kernel_counts"] = {}

        for ev in raw_events:
            if not (r["start_ns"] <= ev["timestamp_ns"] <= r["end_ns"]):
                continue

            is_context = ev["kind"] in (30, 31, 40, 41, 50)
            if not is_context and ev["pid"] != pid:
                continue

            if protocol == "tcp" and ev["kind"] in (60, 61):
                continue
            if protocol == "udp" and ev["kind"] in (20, 21, 22, 23, 40, 41, 50):
                continue

            k = ev["kind_str"]
            r["kernel_breakdown_ns"][k] = r["kernel_breakdown_ns"].get(k, 0) + ev["dur_ns"]
            r["kernel_counts"][k] = r["kernel_counts"].get(k, 0) + 1

        r["kernel_breakdown_ms"] = {k: v / 1e6 for k, v in r["kernel_breakdown_ns"].items()}

        if protocol == "tcp":
            r["views_ms"] = {
                "app_latency_ms": r["latency_ms"],
                "syscall_total_ms": (
                    r["kernel_breakdown_ns"].get("syscall_send", 0)
                    + r["kernel_breakdown_ns"].get("syscall_recv", 0)
                    + r["kernel_breakdown_ns"].get("syscall_connect", 0)
                    + r["kernel_breakdown_ns"].get("syscall_close", 0)
                ) / 1e6,
                "tcp_funcs_total_ms": (
                    r["kernel_breakdown_ns"].get("tcp_sendmsg", 0)
                    + r["kernel_breakdown_ns"].get("tcp_recvmsg", 0)
                    + r["kernel_breakdown_ns"].get("tcp_v4_connect", 0)
                    + r["kernel_breakdown_ns"].get("tcp_close", 0)
                ) / 1e6,
                "softirq_total_ms": (
                    r["kernel_breakdown_ns"].get("softirq_net_rx", 0)
                    + r["kernel_breakdown_ns"].get("softirq_net_tx", 0)
                ) / 1e6,
                "tcp_buffer_queue_events": r["kernel_counts"].get("tcp_buffer_queue", 0),
                "netdev_queue_events": (
                    r["kernel_counts"].get("net_dev_queue", 0)
                    + r["kernel_counts"].get("net_dev_xmit", 0)
                ),
            }
        else:
            r["views_ms"] = {
                "app_latency_ms": r["latency_ms"],
                "syscall_total_ms": (
                    r["kernel_breakdown_ns"].get("syscall_send", 0)
                    + r["kernel_breakdown_ns"].get("syscall_recv", 0)
                    + r["kernel_breakdown_ns"].get("syscall_connect", 0)
                    + r["kernel_breakdown_ns"].get("syscall_close", 0)
                ) / 1e6,
                "udp_funcs_total_ms": (
                    r["kernel_breakdown_ns"].get("udp_sendmsg", 0)
                    + r["kernel_breakdown_ns"].get("udp_recvmsg", 0)
                ) / 1e6,
                "softirq_total_ms": (
                    r["kernel_breakdown_ns"].get("softirq_net_rx", 0)
                    + r["kernel_breakdown_ns"].get("softirq_net_tx", 0)
                ) / 1e6,
            }

def build_output(reqs, raw_events, extra_summary):
    avg_latency = sum(r["latency_ms"] for r in reqs) / len(reqs)
    success_count = sum(1 for r in reqs if r.get("success"))
    return {
        "application_metrics": reqs,
        "summary": {
            "total_requests": len(reqs),
            "successful_requests": success_count,
            "avg_latency_ms": avg_latency,
            "total_ebpf_events": len(raw_events),
            **extra_summary
        }
    }

def main():
    print("=== Starting HTTP Server ===")
    print(f"TCP payload size: {len(TCP_PAYLOAD)} bytes")
    http_server = run_http_server()

    print("=== Starting UDP Server ===")
    print(f"UDP payload size: {len(UDP_PAYLOAD)} bytes")
    udp_sock, udp_stop, udp_thread = run_udp_server()

    time.sleep(1)

    print("=== Loading eBPF program ===")
    b = BPF(text=bpf_program, debug=0)
    pid = os.getpid()

    optional_tracepoints = [
        ("net", "net_dev_queue", "handle_net_dev_queue"),
        ("net", "net_dev_xmit", "handle_net_dev_xmit"),
        ("tcp", "tcp_retransmit_skb", "handle_tcp_retransmit_skb"),
        ("tcp", "tcp_rcv_space_adjust", "handle_tcp_rcv_space_adjust"),
    ]

    attached = []
    for cat, ev, fn in optional_tracepoints:
        if tp_exists(cat, ev):
            b.attach_tracepoint(tp=f"{cat}:{ev}", fn_name=fn)
            attached.append(f"{cat}:{ev}")

    if attached:
        print("=== Attached optional tracepoints ===")
        for tp in attached:
            print(tp)

    raw_events = []
    lock = threading.Lock()

    def handle(cpu, data, size):
        e = b["events"].event(data)
        with lock:
            raw_events.append({
                "timestamp_ns": int(e.ts_ns),
                "dur_ns": int(e.dur_ns),
                "pid": int(e.pid),
                "kind": int(e.kind),
                "kind_str": KIND_LABEL.get(int(e.kind), f"kind_{int(e.kind)}"),
            })

    b["events"].open_perf_buffer(handle, page_cnt=256)

    stop = False

    def poll():
        while not stop:
            b.perf_buffer_poll(timeout=50)

    poll_thread = threading.Thread(target=poll, daemon=True)
    poll_thread.start()

    print("=== Sending TCP HTTP requests ===")
    tcp_start_idx = 0
    tcp_reqs = run_tcp_requests(NUM_TCP_REQUESTS, force_close=True)
    time.sleep(0.5)

    with lock:
        tcp_events = list(raw_events[tcp_start_idx:])

    print("=== Sending UDP echo requests ===")
    with lock:
        udp_start_idx = len(raw_events)
    udp_reqs = run_udp_requests(NUM_UDP_REQUESTS)
    time.sleep(0.5)

    stop = True
    poll_thread.join(timeout=2)

    http_server.shutdown()
    http_server.server_close()

    udp_stop.set()
    udp_sock.close()
    udp_thread.join(timeout=2)

    with lock:
        udp_events = list(raw_events[udp_start_idx:])

    correlate_requests(tcp_reqs, tcp_events, pid, "tcp")
    correlate_requests(udp_reqs, udp_events, pid, "udp")

    tcp_out = build_output(
        tcp_reqs,
        tcp_events,
        {
            "payload_bytes": len(TCP_PAYLOAD),
            "protocol": "tcp",
            "attached_optional_tracepoints": attached,
        }
    )
    udp_out = build_output(
        udp_reqs,
        udp_events,
        {
            "payload_bytes": len(UDP_PAYLOAD),
            "protocol": "udp",
        }
    )

    with open("tcp_events_output.json", "w") as f:
        json.dump(tcp_out, f, indent=2)

    with open("udp_events_output.json", "w") as f:
        json.dump(udp_out, f, indent=2)

    print("\n=== TCP Summary ===")
    print(f"HTTP requests sent: {len(tcp_reqs)}")
    print(f"Successful requests: {sum(1 for r in tcp_reqs if r.get('success'))}")
    print(f"Average latency: {tcp_out['summary']['avg_latency_ms']:.2f} ms")
    print(f"Kernel events captured by eBPF: {len(tcp_events)}")
    print("Detailed results exported to tcp_events_output.json")

    print("\n=== TCP Per-request breakdown ===")
    for r in tcp_reqs:
        v = r.get("views_ms", {})
        print(
            f"Req {r['request_id']:02d}: "
            f"app={v.get('app_latency_ms',0):7.3f} ms | "
            f"syscall={v.get('syscall_total_ms',0):7.3f} | "
            f"tcp={v.get('tcp_funcs_total_ms',0):7.3f} | "
            f"softirq={v.get('softirq_total_ms',0):7.3f} | "
            f"tcp_buf_events={v.get('tcp_buffer_queue_events',0)} | "
            f"bytes={r.get('response_bytes',0)}"
        )

    print("\n=== UDP Summary ===")
    print(f"UDP requests sent: {len(udp_reqs)}")
    print(f"Successful requests: {sum(1 for r in udp_reqs if r.get('success'))}")
    print(f"Average latency: {udp_out['summary']['avg_latency_ms']:.2f} ms")
    print(f"Kernel events captured by eBPF: {len(udp_events)}")
    print("Detailed results exported to udp_events_output.json")

    print("\n=== UDP Per-request breakdown ===")
    for r in udp_reqs:
        v = r.get("views_ms", {})
        print(
            f"Req {r['request_id']:02d}: "
            f"app={v.get('app_latency_ms',0):7.3f} ms | "
            f"syscall={v.get('syscall_total_ms',0):7.3f} | "
            f"udp={v.get('udp_funcs_total_ms',0):7.3f} | "
            f"softirq={v.get('softirq_total_ms',0):7.3f} | "
            f"bytes={r.get('response_bytes',0)}"
        )

if __name__ == "__main__":
    main()
