# Rocky Linux 9 with systemd as PID 1, for the rpm package test
# (docs/design/phase-10.md §7). Run privileged with a private cgroup
# namespace, the way kind runs its nodes.
FROM docker.io/rockylinux/rockylinux:10.2@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834
RUN dnf -y install systemd procps-ng iproute jq bash util-linux && dnf clean all
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/sbin/init"]
