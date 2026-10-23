---
name: Bug report
about: Something does not work as documented
title: ''
labels: bug
assignees: ''
---

<!-- Security vulnerabilities: please do not open an issue. See SECURITY.md. -->

**What happened**
What you did, what you expected, and what happened instead.

**Component**
- [ ] Kernel programs (`rk-bpf`) or ABI (`rk-ebpf-common`)
- [ ] Sensor (`rk-sensor`), agent daemon (`rk-agentd`) or audit log (`rk-audit`)
- [ ] Policy (`rk-policy`)
- [ ] CLI (`rk`)
- [ ] Kubernetes: NRI plugin (`rk-nri`) or Helm chart
- [ ] Packages, systemd unit or container image
- [ ] Documentation or website

**To reproduce**
1. Policy (the smallest profile that shows the problem):
   ```toml
   ```
2. Command or workload:
3. Observed result (error, `rk audit tail` output, sensor log):
4. Expected result:

**Environment**
- Reality Kernel version (`rk --version`):
- Kernel and distribution (`uname -r`, `/etc/os-release`):
- Install method: deb / rpm / tarball / Helm
- `rk doctor` output:
  ```
  ```

**Anything else**
