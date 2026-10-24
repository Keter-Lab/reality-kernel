# Rocky Linux 9 with systemd as PID 1, for the rpm package test
# (docs/design/phase-10.md §7). Run privileged with a private cgroup
# namespace, the way kind runs its nodes.
FROM docker.io/rockylinux/rockylinux:9.8@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f
RUN dnf -y install systemd procps-ng iproute jq bash util-linux && dnf clean all
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
