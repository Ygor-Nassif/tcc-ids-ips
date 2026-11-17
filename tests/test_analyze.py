"""Testes do cálculo de métricas (evaluation/analyze.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from evaluation.analyze import build_intervals, evaluate, summarize

ATK, USER = "10.0.0.20", "10.0.0.30"


def truth(scenario, kind, ip, start, end):
    return [
        {"ts": start, "event": "begin", "scenario": scenario, "kind": kind, "src_ip": ip},
        {"ts": end, "event": "end", "scenario": scenario},
    ]


def test_detection_rate_ttd_and_false_positives():
    events = [
        {"ts": 0, "type": "session_start", "mode": "prevention"},
        {"ts": 103, "type": "alert", "src_ip": ATK, "rule": "port_scan", "mode": "prevention"},
        {"ts": 103.1, "type": "action", "src_ip": ATK, "rule": "port_scan", "action": "blocked"},
        {"ts": 215, "type": "alert", "src_ip": USER, "rule": "flood", "mode": "prevention"},
        {"ts": 215.1, "type": "action", "src_ip": USER, "rule": "flood", "action": "blocked"},
    ]
    gt = (truth("port_scan", "malicious", ATK, 100, 110)
          + truth("brute_force", "malicious", ATK, 150, 160)   # sem alerta -> não detectado
          + truth("web_normal", "legit", USER, 210, 220)       # alerta -> falso positivo
          + truth("ssh_normal", "legit", USER, 300, 310))      # limpo
    intervals, unfinished = build_intervals(gt)
    rows = evaluate(events, intervals, grace=15)
    s = summarize(rows)["prevention"]

    assert unfinished == []
    assert s["malicious_runs"] == 2 and s["detected"] == 1
    assert s["detection_rate"] == 0.5
    assert s["blocked"] == 1
    assert s["ttd_mean_s"] == 3.0
    assert s["legit_runs"] == 2 and s["false_positive_runs"] == 1
    assert s["legit_blocked_runs"] == 1


def test_unfinished_scenarios_are_reported():
    gt = [{"ts": 1, "event": "begin", "scenario": "x", "kind": "malicious", "src_ip": ATK}]
    intervals, unfinished = build_intervals(gt)
    assert intervals == [] and unfinished == ["x"]


def test_mode_is_taken_from_session_start():
    events = [
        {"ts": 0, "type": "session_start", "mode": "detection"},
        {"ts": 500, "type": "session_start", "mode": "prevention"},
    ]
    gt = truth("a", "malicious", ATK, 10, 20) + truth("b", "malicious", ATK, 510, 520)
    intervals, _ = build_intervals(gt)
    rows = {r["scenario"]: r["mode"] for r in evaluate(events, intervals)}
    assert rows == {"a": "detection", "b": "prevention"}
