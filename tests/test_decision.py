"""Testes do motor de decisão (sem root e sem rede)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.metrics import MetricsRecorder
from detection.alert import Alert
from response.decision import DecisionEngine


class FakeEnforcer:
    def __init__(self):
        self.calls = []

    def block_ip(self, ip, direction="inbound"):
        self.calls.append((ip, direction))
        return "blocked"


def make_alert(**kw):
    base = dict(src_ip="10.0.0.5", rule_name="port_scan", description="x", severity="medium")
    base.update(kw)
    return Alert(**base)


def test_detection_mode_never_blocks():
    enforcer = FakeEnforcer()
    engine = DecisionEngine("detection", enforcer)
    engine.handle(make_alert())
    assert enforcer.calls == []


def test_prevention_mode_blocks_target_ip():
    enforcer = FakeEnforcer()
    engine = DecisionEngine("prevention", enforcer)
    engine.handle(make_alert())
    assert enforcer.calls == [("10.0.0.5", "inbound")]


def test_prevention_mode_uses_outbound_for_exfiltration():
    enforcer = FakeEnforcer()
    engine = DecisionEngine("prevention", enforcer)
    engine.handle(make_alert(rule_name="exfiltration", target_ip="203.0.113.9", direction="outbound"))
    assert enforcer.calls == [("203.0.113.9", "outbound")]


def test_cooldown_suppresses_repeated_alerts():
    enforcer = FakeEnforcer()
    engine = DecisionEngine("prevention", enforcer, cooldown_seconds=60)
    for _ in range(5):
        engine.handle(make_alert())
    assert len(enforcer.calls) == 1


def test_cooldown_is_per_ip_and_rule():
    enforcer = FakeEnforcer()
    engine = DecisionEngine("prevention", enforcer, cooldown_seconds=60)
    engine.handle(make_alert())
    engine.handle(make_alert(rule_name="flood"))
    engine.handle(make_alert(src_ip="10.0.0.6"))
    assert len(enforcer.calls) == 3


def test_prevention_without_enforcer_is_rejected():
    with pytest.raises(ValueError):
        DecisionEngine("prevention", None)


def test_metrics_are_recorded(tmp_path):
    path = tmp_path / "events.jsonl"
    engine = DecisionEngine("detection", None, MetricsRecorder(str(path)))
    engine.handle(make_alert())
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2  # alert + action
    assert '"type": "alert"' in lines[0] and '"alert_only"' in lines[1]
