#!/usr/bin/env python3
import json
import matplotlib.pyplot as plt

JSON_PATH = "tcp_events_output.json"

def get_view(v, *keys, default=0.0):
    for k in keys:
        if k in v and v[k] is not None:
            return float(v[k])
    return float(default)

def main():
    with open(JSON_PATH, "r") as f:
        data = json.load(f)

    metrics = data.get("application_metrics", [])
    if not metrics:
        raise SystemExit("No application_metrics found in JSON.")

    req_ids = []
    app = []
    syscall = []
    tcp = []
    softirq = []

    for r in metrics:
        rid = int(r.get("request_id", len(req_ids) + 1))
        v = r.get("views_ms", {})

        req_ids.append(rid)
        app.append(get_view(v, "app_latency_ms", default=r.get("latency_ms", 0.0)))
        syscall.append(get_view(v, "syscall_total_ms"))
        tcp.append(get_view(v, "tcp_funcs_total_ms", "tcp_exec_total_ms"))
        softirq.append(get_view(v, "softirq_total_ms"))

    # ---- Graph 1: Line chart ----
    plt.figure()
    plt.plot(req_ids, app, marker="o", label="app_latency_ms")
    plt.plot(req_ids, syscall, marker="o", label="syscall_total_ms")
    plt.plot(req_ids, tcp, marker="o", label="tcp_total_ms")
    plt.plot(req_ids, softirq, marker="o", label="softirq_total_ms")
    plt.title("Per-request latency (application vs kernel views)")
    plt.xlabel("Request ID")
    plt.ylabel("Milliseconds (ms)")
    plt.xticks(req_ids)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("latency_lines.png", dpi=200)

    # ---- Graph 2: Stacked bars (kernel components) + app overlay ----
    plt.figure()
    plt.bar(req_ids, syscall, label="syscall_total_ms")
    plt.bar(req_ids, tcp, bottom=syscall, label="tcp_total_ms")
    bottom2 = [syscall[i] + tcp[i] for i in range(len(req_ids))]
    plt.bar(req_ids, softirq, bottom=bottom2, label="softirq_total_ms")

    plt.plot(req_ids, app, marker="o", label="app_latency_ms")

    plt.title("Kernel components (stacked) with app latency overlay")
    plt.xlabel("Request ID")
    plt.ylabel("Milliseconds (ms)")
    plt.xticks(req_ids)
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("latency_stacked.png", dpi=200)

    print("Saved graphs:")
    print(" - latency_lines.png")
    print(" - latency_stacked.png")

if __name__ == "__main__":
    main()
