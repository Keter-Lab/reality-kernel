# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

We take the security of Reality Kernel, its eBPF kernel probes, and symbolic execution engine extremely seriously. If you discover a vulnerability or execution bypass, please report it responsibly.

### Responsible Disclosure Process

1. **Do not open a public issue.** Please report vulnerabilities privately.
2. Email your findings directly to the Keter Labs security team at:
   **security@keterlabs.com** (or open a private GitHub Security Advisory).
3. Include the following details:
   - Type of vulnerability (e.g., eBPF probe bypass, symbolic execution evasion, fast-path escape).
   - Step-by-step reproduction instructions or proof-of-concept (PoC) script.
   - Affected components (`core/engine.py`, `rk-ebpf-probes`, `api`, etc.).
   - Potential impact on host isolation or agent execution.

### Response Timeline

- **Initial Response:** Within 48 hours of receipt.
- **Triage & Status Update:** Within 5 business days.
- **Remediation & Advisory Release:** Coordinated with the reporter prior to public release.

Thank you for helping keep the open-source autonomous agent ecosystem secure.
