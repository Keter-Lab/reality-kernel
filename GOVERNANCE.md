# Governance

How decisions about Reality Kernel are made, and by whom.

## Maintainers

| Name | GitHub | Areas |
|---|---|---|
| Mohd Tabrez | [HunterX461](https://github.com/HunterX461) | everything (lead maintainer) |

Ownership of paths is recorded in [.github/CODEOWNERS](.github/CODEOWNERS).

Maintainers review and merge changes, cut releases, triage security reports
([SECURITY.md](SECURITY.md)) and uphold the
[Code of Conduct](CODE_OF_CONDUCT.md).

## How changes land

- Every change reaches `main` through a pull request. Direct pushes,
  force pushes and branch deletion are blocked on `main`.
- Every commit is signed off under the
  [Developer Certificate of Origin](https://developercertificate.org/);
  a CI check enforces it ([CONTRIBUTING.md](CONTRIBUTING.md#sign-off)).
- Required checks must pass: lint, unit tests on x86_64 and arm64, Python
  and Go tests, and, for any change that can affect the kernel side, the
  full kernel matrix and the traceability check. A change that removes a
  criterion's evidence cannot merge ([docs/testing.md](docs/testing.md)).
- **Kernel code** (`rk-bpf/`, the ABI in `rk-ebpf-common/`, the loader and
  pin handling in `rk-sensor/`) follows a two-person rule: two maintainers
  have read and approved it, so a maintainer's own change needs another
  maintainer's approval and an outside contribution needs two. This rule
  takes effect as soon as the project has two maintainers; until then, the
  full kernel matrix is the reviewer of record and the lead maintainer
  approves.
- Other changes need one maintainer's approval.

## Design decisions

Significant changes start with a design note in
[docs/design/](docs/design/) that states the problem, the options, the
recommendation and acceptance criteria with named tests. The note is
reviewed and marked ACCEPTED before implementation. Lasting decisions are
recorded as ADRs in [docs/decisions/](docs/decisions/README.md); an ADR is
superseded by a newer one, never edited to say something else.

Decisions are made by consensus among maintainers. Where consensus cannot
be reached, the lead maintainer decides and records the reasoning in the
design note or ADR.

## Becoming a maintainer

Contributors who have made sustained, high-quality contributions (code,
review, documentation or triage) over several months can be nominated by a
maintainer. A new maintainer is added by consensus of the existing
maintainers and recorded in this file and in CODEOWNERS in a pull request.

A maintainer who is inactive for six months, or who asks to step down,
moves to emeritus status. Their access is removed and they are thanked in
this file.

## Releases

Release policy, versioning and the support window:
[docs/releases.md](docs/releases.md).

## Changes to this document

Changes to governance are made by pull request and need the approval of
every active maintainer.
