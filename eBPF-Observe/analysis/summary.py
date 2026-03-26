#!/usr/bin/env python3
import json
import numpy as np
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

    app, syscall, tcp, softirq = [], [], [], []

    for r in metrics:
        v = r.get("views_ms", {})
        app.append(get_view(v, "app_latency_ms", default=r.get("latency_ms", 0.0)))
        syscall.append(get_view(v, "syscall_total_ms"))
        tcp.append(get_view(v, "tcp_funcs_total_ms", "tcp_exec_total_ms"))
        softirq.append(get_view(v, "softirq_total_ms"))

    series = {
        "app_latency_ms": np.array(app),
        "syscall_total_ms": np.array(syscall),
        "tcp_total_ms": np.array(tcp),
        "softirq_total_ms": np.array(softirq),
    }

    labels = list(series.keys())
    means = [float(np.mean(series[k])) for k in labels]
    p95s = [float(np.percentile(series[k], 95)) for k in labels]

    x = np.arange(len(labels))
    width = 0.38

    plt.figure()
    plt.bar(x - width/2, means, width, label="mean")
    plt.bar(x + width/2, p95s, width, label="p95")

    plt.title("Summary latency stats across requests")
    plt.ylabel("Milliseconds (ms)")
    plt.xticks(x, labels, rotation=20, ha="right")
    plt.grid(True, axis="y", alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig("summary_mean_p95.png", dpi=220)
    print("Saved summary_mean_p95.png")

if __name__ == "__main__":
    main()
