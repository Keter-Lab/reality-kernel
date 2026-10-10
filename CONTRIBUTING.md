# Contributing to Reality Kernel

Thank you for your interest in contributing to Reality Kernel! We are excited to collaborate with the systems programming, eBPF, and AI security communities.

---

## Code of Conduct

We are committed to providing a friendly, safe, and welcoming environment for everyone, regardless of background or experience level. Be respectful and constructive.

---

## Development Setup

### 1. Prerequisites
- **Rust Toolchain:** Install latest stable Rust and nightly (required for compiling eBPF probes):
  ```bash
  rustup toolchain install stable
  rustup toolchain install nightly --component rust-src
  cargo install bpf-linker
  ```
- **Linux Environment:** Linux 5.15+ kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).
- **Python:** 3.10+ for SDK testing (`pip install -e sdk/`).

### 2. Building the Project
```bash
# Build user-space crates
cargo build --workspace

# Build kernel eBPF probes
cargo xtask build-ebpf

# Run tests
cargo test
```

---

## Pull Request Guidelines

1. **Keep PRs focused:** Submit small, focused pull requests addressing a single bug fix or feature.
2. **Include Tests:** Ensure all new verification logic or eBPF helpers include corresponding tests.
3. **Format & Lint:** Run `cargo fmt` and `cargo clippy` before submitting.
4. **Sign-off:** Contributions are licensed under the dual Apache-2.0 / MIT license.

---

## Reporting Vulnerabilities

If you discover a security vulnerability within Reality Kernel itself, please email **tabrez@realitykernel.dev** directly rather than opening a public issue. We will respond promptly and coordinate disclosure responsibly.
