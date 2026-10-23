"""The repository holds only the open-source project (ADR-0016, phase 12)."""

import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]

RETIRED = [
    "api", "core", "sdk", "rk-api", "rk-supabase", "rk-signing", "rk-session",
    "rk-types", "rk-engine-core", "tests/parity", "requirements.txt",
    "package.json", "package-lock.json", "tailwind.config.js",
]

WORKSPACE = {
    "rk-ebpf-common", "rk-sensor", "rk-audit", "rk-policy", "rk-agentd", "rk-cli",
    "xtask", "tests/integration",
}


def test_retired_product_is_gone():
    present = [p for p in RETIRED if (ROOT / p).exists()]
    assert present == []
    with open(ROOT / "Cargo.toml", "rb") as f:
        members = set(tomllib.load(f)["workspace"]["members"])
    assert members == WORKSPACE
