# Cross-Layer Network Observability using eBPF

> Correlating application-layer HTTP metrics with kernel-layer TCP events using eBPF on Linux.

Built as a group project for NET4000 at Carleton University (2025). This project instruments a live HTTP client/server with eBPF kprobes to capture TCP events at the kernel level, then correlates them with application-layer request latency to produce cross-layer performance profiles.

*In collaboration with [@Tevfik-Can](https://github.com/Tevfik-Can), [@CameronReady2003](https://github.com/CameronReady2003), and [@andrewc4](https://github.com/andrewc4).*

---

## Results

<div align="center">
  <img src="https://raw.githubusercontent.com/Tevfik-Can/Net4000-Project/bpftools/analysis/latency_lines.png" alt="Per-request latency: application vs kernel views" width="32%"/>
  <img src="https://raw.githubusercontent.com/Tevfik-Can/Net4000-Project/bpftools/analysis/latency_stacked.png" alt="Kernel components stacked with app latency overlay" width="32%"/>
  <img src="https://raw.githubusercontent.com/Tevfik-Can/Net4000-Project/bpftools/analysis/summary_mean_p95.png" alt="Summary mean and P95 latency stats" width="32%"/>
</div>
<div align="center">
  <sub>Per-request latency (app vs kernel) &nbsp;|&nbsp; Kernel components stacked &nbsp;|&nbsp; Mean & P95 summary</sub>
</div>

---

## What It Does

The system runs an HTTP server and client on the same machine, captures kernel-level TCP events via eBPF kprobes during each request, and correlates those events back to the application request that triggered them. This allows latency to be broken down into distinct layers: application processing, syscall overhead, TCP connection handling, and softirq processing.

Both TCP and UDP traffic modes are supported. Results are exported as JSON and visualized across multiple graph types.

---

## Features

- **eBPF kprobe instrumentation** — Hooks into `tcp_v4_connect`, `tcp_sendmsg`, `tcp_recvmsg`, and `tcp_close` at the kernel level with no code modification to the target application
- **Cross-layer correlation** — Maps kernel TCP events back to their originating HTTP request by PID and timing
- **TCP & UDP support** — Separate test scripts for TCP-only and combined TCP/UDP workloads
- **Latency decomposition** — Breaks per-request latency into application, syscall, TCP, and softirq components
- **Automated graphing** — Generates stacked bar charts, line graphs, and summary statistics from collected JSON data
- **Interrupt-safe event collection** — BPF perf buffer with a background polling thread; thread-safe event accumulation via lock

---

## Project Structure

```
├── ebpf_programs/
│   ├── ebpf_net.c        # TCP kprobe eBPF program (used with runner2)
│   ├── ebpf-probe.c      # Basic kernel event probe (used with runner1)
│   ├── ebpf_runner.py    # Runner for ebpf-probe.c
│   └── ebpf_runner2.py   # Runner for ebpf_net.c (TCP-focused)
├── data_collection/
│   ├── fast_server.py    # Minimal HTTP server
│   └── client.py         # HTTP client with latency logging
├── analysis/
│   ├── simple_test.py    # End-to-end TCP cross-layer test
│   ├── simple_test2.py   # TCP + UDP combined test
│   ├── graphing.py       # Stacked bar chart generator
│   └── summary.py        # Mean / P95 summary chart generator
└── docs/
    └── PROJECT.md
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| OS | Linux (Ubuntu VM) |
| Kernel instrumentation | eBPF (BCC / BPF kprobes) |
| eBPF programs | C (`ebpf_net.c`, `ebpf-probe.c`) |
| Userspace / orchestration | Python 3 (BCC bindings) |
| HTTP workload | Python `http.server`, `requests` |
| Data analysis & graphing | NumPy, pandas, matplotlib |

---

## Prerequisites

Linux only — eBPF requires kernel 4.9+ and root privileges.

```bash
# System dependencies
sudo apt install -y clang llvm libelf-dev libbpf-dev \
  bpfcc-tools linux-headers-$(uname -r) bpftool

# Python dependencies
pip install -r requirements.txt
```

> A pre-configured Ubuntu VM with all dependencies installed is available [here](https://drive.google.com/drive/folders/1RF5JRG1DJLXjseNQS9AUgnmlyvlN5KDK?usp=sharing).

---

## Quick Start

```bash
# TCP cross-layer test (10 requests, ~1MB payload)
cd analysis
sudo python3 simple_test.py

# TCP + UDP combined test
sudo python3 simple_test2.py

# Generate graphs from collected data
python3 graphing.py
python3 summary.py
```

Results are saved to `results/simple_cross_layer.json` (gitignored).

---

## How It Works

1. An HTTP server and client are spun up within the same process
2. eBPF kprobes are attached to kernel TCP functions, filtered by PID
3. The client sends 10 HTTP requests; kernel events are streamed via BPF perf buffer into a background thread
4. After all requests complete, events are correlated to requests by timing window
5. Per-request latency is decomposed into views: application, syscall, TCP, softirq
6. Results are serialized to JSON and passed to the graphing scripts

---

## Project Status

Active group project — Carleton University NET4000, 2025.

---

## License

For academic and portfolio purposes.
