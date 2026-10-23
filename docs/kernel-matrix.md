# Kernel support matrix

Every row is exercised by `.github/workflows/kernel.yml` (job `vm-matrix`) on
each push and pull request. A row may only be marked supported if that job passes
for it. The per-kernel selftest report is uploaded as the `selftest-<kernel>`
artifact.

| Kernel | Arch | BPF objects load (verifier) | Selftest | Notes |
|---|---|---|---|---|
| 5.15 LTS | x86_64 | CI | CI | Minimum supported kernel for enforcement. Built from source in CI (see below) |
| 6.1 LTS | x86_64 | CI | CI | |
| 6.6 LTS | x86_64 | CI | CI | |
| 6.12 LTS | x86_64 | CI | CI | |
| 6.18 | x86_64 | CI | CI | Latest stable in the LVH image set |
| any | arm64 | build + layout checks only | not yet | See "Known gaps" |

On any host, `rk doctor` checks the features the sensor needs and explains
what is missing (docs/install.md). It runs on every kernel below, in the VM
job's upgrade suite, and must report no failure.

## How the VM job works

1. `bpf-build` compiles `rk-bpf/` for x86 and arm64 with `-Wall -Werror` and
   checks that every object keeps its `.BTF` section.
2. `sensor` builds a static (musl) `rk-sensor` with the objects embedded and
   runs its tests with the real objects.
3. `vm-matrix` boots each kernel with [vmtest] (host rootfs shared read-only)
   with `lsm=lockdown,capability,landlock,yama,bpf` on the kernel command line,
   then runs `tests/vm/selftest.sh`:
   - `rk-sensor --selftest` must exit 0. It loads every embedded program through
     the verifier, checks that the LSM hook runs, that `cgroup/connect4` denies
     TEST-NET-1 with `EPERM` in a temporary cgroup, and that the records both
     programs emit through the production helpers decode with the production
     decoder and carry the expected values.
   - Negative control: `bpftool` must fail to load
     `rk-bpf/test/reject_infinite_loop.bpf.c`, with a verifier message.
   - Positive control: `bpftool` must load `rk_selftest.bpf.o`, so a broken
     bpftool can never make the negative control pass.

## Evidence for the Phase 0 acceptance criteria

- **A verifier-rejected program turns CI red.** On 2026-10-20 a throwaway branch
  added an unbounded loop (`rk_test_reject_proof`) to `rk_selftest.bpf.c`. clang
  compiled it and the build jobs passed. In every VM the selftest reported the
  program as not loaded, with the verifier's own message ("infinite loop detected
  at insn 6"), and exited 1. The bpftool positive control also failed, and the
  jobs went red:
  <https://github.com/Keter-Lab/reality-kernel/actions/runs/39379014299/job/118484170101>.
  The branch was then deleted.
- **A selftest report is uploaded per kernel**: the `selftest-<kernel>` artifacts
  of every `Kernel` workflow run.
- **No runtime override for the BPF object path**: `rk-sensor` refuses to compile
  in release without `embedded-bpf`, and `main::tests::no_object_path_flag`
  checks that no CLI flag accepts an object path.

## Kernel images

Kernels come from the [LVH] image set (`quay.io/lvh-images/kernel-images`),
built with `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF` and `CONFIG_CGROUP_BPF`.
They are pinned by digest in `kernel.yml`. To refresh:

```sh
curl -s "https://quay.io/api/v1/repository/lvh-images/kernel-images/tag/?specificTag=6.12-main" \
  | grep -o '"manifest_digest": "[^"]*"' | head -1
```

Update the digest in `kernel.yml` in its own pull request, so a behaviour change
can be traced to a kernel change.

## Kernel features reported by the selftest

`kernel_features` in the report lists the result of each probe in
`rk-bpf/src/rk_probes.bpf.c`. Measured in CI on 2026-10-20:

| Feature | 5.15 | 6.1 | 6.6 | 6.12 | 6.18 |
|---|---|---|---|---|---|
| `sockaddr_cgroup_id` (`bpf_get_current_cgroup_id` in `cgroup/connect4`) | yes | yes | yes | yes | yes |
| `sockaddr_pid_tgid` (`bpf_get_current_pid_tgid` in `cgroup/connect4`) | yes | yes | yes | yes | yes |

Phase 2 therefore identifies the governed cgroup directly in the network hooks
on every supported kernel.

## Known gaps

- **arm64 verifier runs.** GitHub-hosted arm64 runners have no KVM, so arm64
  objects are built and their Rust layout assertions run natively on arm64, but
  they are not loaded into an arm64 kernel. Planned: a nightly job under QEMU
  TCG emulation (slow, free).

[vmtest]: https://github.com/danobi/vmtest
[LVH]: https://github.com/cilium/little-vm-helper

## 5.15: built from source

The LVH 5.15 image is built without `CONFIG_VIRTIO_CONSOLE`, which vmtest needs
to talk to the guest. CI rebuilds the same source (`linux-5.15.222`, verified
against kernel.org's SHA-256) from LVH's own config with that one option added,
and caches the resulting `bzImage`. Everything that matters to Reality Kernel
(BPF, BTF, BPF-LSM, cgroup BPF) is identical to the LVH image.
