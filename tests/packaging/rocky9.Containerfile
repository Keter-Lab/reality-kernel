# Rocky Linux 9 with systemd as PID 1, for the rpm package test
# (docs/design/phase-10.md §7). Run privileged with a private cgroup
# namespace, the way kind runs its nodes.
FROM docker.io/rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe
RUN dnf -y install systemd procps-ng iproute jq bash util-linux && dnf clean all
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
