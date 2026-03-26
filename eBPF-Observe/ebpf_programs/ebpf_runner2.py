#!/usr/bin/env python3
from bcc import BPF
import ctypes
import time

EVENT_NAMES = {
    1: "CONNECT",
    2: "SEND",
    3: "RECV",
    4: "CLOSE",
}

bpf = BPF(src_file="ebpf_net.c")

# Add PIDs you want to monitor
# (server + client)
import os
server_pid = int(os.environ.get("SERVER_PID", "0"))
client_pid = int(os.environ.get("CLIENT_PID", "0"))

if server_pid:
    bpf["target_pids"][ctypes.c_uint(server_pid)] = ctypes.c_ubyte(1)

if client_pid:
    bpf["target_pids"][ctypes.c_uint(client_pid)] = ctypes.c_ubyte(1)

class Event(ctypes.Structure):
    _fields_ = [
        ("ts_ns", ctypes.c_ulonglong),
        ("pid", ctypes.c_uint),
        ("ppid", ctypes.c_uint),
        ("bytes", ctypes.c_uint),
        ("event_type", ctypes.c_ubyte),
        ("comm", ctypes.c_char * 16),
    ]

def handle_event(cpu, data, size):
    e = ctypes.cast(data, ctypes.POINTER(Event)).contents
    print(
        f"{e.ts_ns} | "
        f"{EVENT_NAMES.get(e.event_type)} | "
        f"PID={e.pid} ({e.comm.decode()}) | "
        f"bytes={e.bytes}"
    )

bpf["events"].open_perf_buffer(handle_event)

print("Monitoring TCP activity (Ctrl-C to stop)...")

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break
