"""Micro-benchmarks for Reality Kernel overhead on a drone companion computer.
Run once without enforcement and once with it; compare the two JSON lines.
Numbers from CI VMs are noisy and are NOT real-hardware results."""
import json
import socket
import statistics
import subprocess
import sys
import threading
import time

LABEL = sys.argv[1] if len(sys.argv) > 1 else "unlabeled"
OUT = sys.argv[2] if len(sys.argv) > 2 else "bench-results.jsonl"
N = 500

def summarize(samples_us):
    s = sorted(samples_us)
    return {
        "n": len(s),
        "median_us": round(statistics.median(s), 1),
        "p95_us": round(s[int(len(s) * 0.95) - 1], 1),
        "p99_us": round(s[int(len(s) * 0.99) - 1], 1),
    }

def bench_exec():
    samples = []
    for _ in range(N):
        t = time.perf_counter()
        subprocess.run(["/bin/true"], check=True)
        samples.append((time.perf_counter() - t) * 1e6)
    return summarize(samples)

def bench_connect(port=7000):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(128)
    stop = False
    def accept_loop():
        while not stop:
            try:
                c, _ = srv.accept()
                c.close()
            except OSError:
                break
    threading.Thread(target=accept_loop, daemon=True).start()
    samples = []
    for _ in range(N):
        t = time.perf_counter()
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        samples.append((time.perf_counter() - t) * 1e6)
        s.close()
    stop = True
    srv.close()
    return summarize(samples)

result = {
    "label": LABEL,
    "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "exec_bin_true": bench_exec(),
    "connect_localhost": bench_connect(),
}
print(json.dumps(result))
with open(OUT, "a") as f:
    f.write(json.dumps(result) + "\n")
