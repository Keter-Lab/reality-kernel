# RK Production Deployment Guide

> **Installing the sensor** (packages, systemd, Kubernetes, upgrades,
> `rk doctor`): see [docs/install.md](docs/install.md). This guide covers the
> hosted API service (`rk-api`).

## 1) Prerequisites

- Linux kernel **>= 5.8**
- Run `rk doctor` **before anything else**
- Rust toolchain (stable)
- Root/sudo access on sensor host (for eBPF capabilities)

### Required environment variables

- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `RK_SECRET_KEY`
- `ALLOWED_ORIGINS` (comma-separated strict CORS allow-list)
- `SERVER_SECRET`
- `DISCORD_NOTIFY_BLOCK` (`true` / `false`)
- `PORT` (optional, defaults to `8000`)

---

## 2) Build

```bash
make -C rk-bpf
cargo build --release -p rk-api
cargo build --release -p rk-sensor --features embedded-bpf
cargo build --release -p rk-cli
```

---

## 3) Deploy `rk-api` (Fly.io / VPS)

### Dockerfile (Debian slim)

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY rk-api /app/rk-api

ENV PORT=8000
EXPOSE 8000

CMD ["/app/rk-api"]
```

### Runtime env vars

Set these in Fly/VPS environment:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `RK_SECRET_KEY`
- `ALLOWED_ORIGINS`
- `SERVER_SECRET`
- `DISCORD_NOTIFY_BLOCK`
- `PORT` (if different from 8000)

### Port configuration

- Default bind port: `8000`
- Ensure your reverse proxy / platform health checks point to `/healthz`

---

## 4) Deploy `rk-sensor` (customer host)

### Install artifacts

- Copy binary to e.g. `/usr/local/bin/rk-sensor`
- The BPF objects are embedded in the `rk-sensor` binary; there is nothing else to copy
- Create env file at: **`/etc/rk/env`**

### systemd unit (`/etc/systemd/system/rk-sensor.service`)

```ini
[Unit]
Description=Reality Kernel Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/rk/env
ExecStart=/usr/local/bin/rk-sensor
Restart=always
RestartSec=3
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

### Enable/start

```bash
sudo systemctl daemon-reload
sudo systemctl enable rk-sensor
sudo systemctl start rk-sensor
sudo systemctl status rk-sensor
```

---

## 5) Verify end-to-end

1. Run preflight:
   ```bash
   rk doctor
   ```
2. Run parity gate:
   ```bash
   cargo test -p parity
   ```
3. Probe API:
   ```bash
   curl -s http://127.0.0.1:8000/healthz
   ```
4. Send test check request:
   ```bash
   curl -s -X POST http://127.0.0.1:8000/v1/check \
     -H "Authorization: Bearer <API_KEY>" \
     -H "Content-Type: application/json" \
     -d '{"command":"echo hello","prime_intent":"print a greeting"}'
   ```
