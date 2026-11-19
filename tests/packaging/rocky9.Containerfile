# Rocky Linux 9 with systemd as PID 1, for the rpm package test
# (docs/design/phase-10.md §7). Run privileged with a private cgroup
# namespace, the way kind runs its nodes.
FROM docker.io/rockylinux/rockylinux:9.9@sha256:bb5755f96bec05ff26165e779ec843d7167544be9e50770508f307019a6d05c4
RUN dnf -y install systemd procps-ng iproute jq bash util-linux && dnf clean all
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
