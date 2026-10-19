# 0003. Kernel matrix with vmtest and pinned LVH kernels

Date: 2026-10-19 · Status: Accepted

## Context
Phase 0 requires verifier loads on a kernel matrix (5.15, 6.1, 6.6, 6.12, latest
stable) using little-vm-helper (LVH) or vmtest. BPF-LSM needs `bpf` in the boot
LSM list, which the LVH run action (v0.0.30) cannot pass on the kernel command
line.

## Decision
- Kernels: LVH kernel images (`quay.io/lvh-images/kernel-images`), built with
  `CONFIG_BPF_LSM` and BTF, pinned by digest.
- Runner: vmtest v0.18.0 in kernel mode, with
  `--kargs lsm=lockdown,capability,landlock,yama,bpf`. The guest uses the
  runner's rootfs read-only, so the static `rk-sensor` and `bpftool` run
  unchanged.
- Tools are downloaded at pinned versions and checked against SHA-256 sums.

## Consequences
- 6.18 stands in for "latest stable" until LVH publishes newer stable images.
- The LVH 5.15 image lacks `CONFIG_VIRTIO_CONSOLE` (needed by vmtest); CI rebuilds
  the same source from LVH's config plus that option, cached by digest.
- arm64 objects are not loaded into an arm64 kernel (no KVM on hosted arm64
  runners). Tracked in `docs/kernel-matrix.md`.
