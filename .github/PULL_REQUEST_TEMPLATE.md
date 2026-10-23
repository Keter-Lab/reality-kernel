## What and why

<!-- What this changes, and the problem it solves. Link the issue or design note. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change (policy format, agentd protocol, audit format, pin layout)
- [ ] Documentation
- [ ] CI, build or release

## Areas

- [ ] Kernel programs or ABI (`rk-bpf/`, `rk-ebpf-common/`): two-person review, see GOVERNANCE.md
- [ ] Sensor, agentd, audit (`rk-sensor/`, `rk-agentd/`, `rk-audit/`)
- [ ] Policy (`rk-policy/`)
- [ ] CLI (`rk-cli/`)
- [ ] Kubernetes (`rk-nri/`, `deploy/helm/`)
- [ ] Packaging and release (`deploy/`, `.github/`)
- [ ] Website (`public/`)

## Testing

<!-- The tests that cover this change, and which acceptance criteria they belong to. -->

## Checklist

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md)
- [ ] Behaviour changes come with tests; `tests/traceability.toml` is updated if a criterion's tests changed
- [ ] Docs updated; any new README claim links to its evidence
- [ ] CHANGELOG.md updated under "Unreleased" for user-visible changes
