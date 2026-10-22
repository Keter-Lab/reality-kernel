"""The Grafana dashboard only queries metrics the sensor exports
(docs/design/phase-9.md §3.9, §5)."""

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "deploy" / "grafana" / "reality-kernel.json"
EXPORTER = ROOT / "rk-sensor" / "src" / "metrics.rs"

# PromQL functions and keywords that look like metric names.
PROMQL = {"sum", "by", "rate", "increase", "topk", "min", "max", "on", "group_left", "without"}


def exported_metrics():
    text = EXPORTER.read_text()
    return set(re.findall(r'"(rk_[a-z_]+)"', text)) | set(re.findall(r"family\(&mut out, \"(rk_[a-z_]+)\"", text))


def queried_metrics():
    dash = json.loads(DASHBOARD.read_text())
    names = set()
    for panel in dash["panels"]:
        for target in panel.get("targets", []):
            expr = re.sub(r"\{[^}]*\}", "", target["expr"])
            expr = re.sub(r"\[[^\]]*\]", "", expr)
            names |= {n for n in re.findall(r"[a-z_][a-z0-9_]*", expr) if n not in PROMQL and not n.isdigit()}
    return names


def test_dashboard_metrics_exist():
    exported = exported_metrics()
    assert "rk_decisions_total" in exported
    missing = queried_metrics() - exported - {"instance", "rule_id", "profile", "verdict", "hook", "stage", "kind"}
    assert not missing, f"dashboard queries metrics the sensor does not export: {sorted(missing)}"


def test_dashboard_is_valid_grafana_json():
    dash = json.loads(DASHBOARD.read_text())
    ids = [p["id"] for p in dash["panels"]]
    assert len(ids) == len(set(ids))
    assert dash["uid"] == "reality-kernel"
