"""
Testes unitários básicos das regras de detecção, usando dicionários
packet_info simulados (não precisam de captura real de rede nem de root).

Rodar com: pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.rules import PortScanRule, FloodRule, BruteForceRule


def make_tcp_packet(src_ip="10.0.0.5", dst_port=80, syn=False):
    return {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "proto": "TCP",
        "dst_port": dst_port,
        "src_port": 54321,
        "syn_flag": syn,
        "packet_len": 60,
    }


def test_port_scan_rule_triggers_after_threshold():
    rule = PortScanRule(window_seconds=10, port_threshold=5)
    alert = None
    for port in range(1, 10):
        alert = rule.inspect(make_tcp_packet(dst_port=port))
        if alert:
            break
    assert alert is not None
    assert alert.rule_name == "port_scan"


def test_port_scan_rule_does_not_trigger_below_threshold():
    rule = PortScanRule(window_seconds=10, port_threshold=20)
    alert = None
    for port in range(1, 5):
        alert = rule.inspect(make_tcp_packet(dst_port=port))
    assert alert is None


def test_flood_rule_triggers_on_high_rate():
    rule = FloodRule(threshold_pps=5)
    alert = None
    for _ in range(10):
        alert = rule.inspect(make_tcp_packet())
        if alert:
            break
    assert alert is not None
    assert alert.rule_name == "flood"


def test_brute_force_rule_triggers_on_repeated_syn_to_sensitive_port():
    rule = BruteForceRule(window_seconds=10, attempt_threshold=5)
    alert = None
    for _ in range(10):
        alert = rule.inspect(make_tcp_packet(dst_port=22, syn=True))
        if alert:
            break
    assert alert is not None
    assert alert.rule_name == "brute_force"


def test_brute_force_rule_ignores_non_sensitive_ports():
    rule = BruteForceRule(window_seconds=10, attempt_threshold=5)
    alert = None
    for _ in range(10):
        alert = rule.inspect(make_tcp_packet(dst_port=8080, syn=True))
    assert alert is None


# ---------- novas regras e correções ----------
from detection.rules import SignatureRule, ExfiltrationRule


def test_flood_description_reports_real_count():
    rule = FloodRule(threshold_pps=5)
    alert = None
    for _ in range(10):
        alert = rule.inspect(make_tcp_packet())
        if alert:
            break
    assert alert is not None
    assert "5" in alert.description and not alert.description.startswith("0")


def test_signature_rule_detects_known_tool_user_agent():
    rule = SignatureRule()
    packet = make_tcp_packet(dst_port=80)
    packet["payload"] = b"GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2\r\n\r\n"
    alert = rule.inspect(packet)
    assert alert is not None
    assert alert.rule_name == "offensive_tool_signature"


def test_signature_rule_ignores_normal_traffic():
    rule = SignatureRule()
    packet = make_tcp_packet(dst_port=80)
    packet["payload"] = b"GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    assert rule.inspect(packet) is None


def test_exfiltration_rule_triggers_on_large_outbound_volume():
    rule = ExfiltrationRule(["10.0.0.1"], window_seconds=30, threshold_bytes=10_000)
    alert = None
    for _ in range(20):
        pkt = {"src_ip": "10.0.0.1", "dst_ip": "203.0.113.9", "proto": "TCP",
               "dst_port": 9000, "packet_len": 1500, "syn_flag": False}
        alert = rule.inspect(pkt)
        if alert:
            break
    assert alert is not None
    assert alert.direction == "outbound"
    assert alert.target_ip == "203.0.113.9"


def test_exfiltration_rule_ignores_inbound_and_other_hosts():
    rule = ExfiltrationRule(["10.0.0.1"], window_seconds=30, threshold_bytes=1000)
    for _ in range(50):
        pkt = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "proto": "TCP",
               "dst_port": 80, "packet_len": 1500, "syn_flag": False}
        assert rule.inspect(pkt) is None
