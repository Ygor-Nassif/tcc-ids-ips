"""
Teste de integração sem root/rede: pacotes sintéticos do Scapy passam
pelo parser do sniffer, pelo motor de regras e pelo motor de decisão.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import IP, TCP, Raw

import main
from capture.sniffer import _extract_packet_info
from core.config_loader import Config, load_config
from response.decision import DecisionEngine


class FakeEnforcer:
    def __init__(self):
        self.calls = []

    def block_ip(self, ip, direction="inbound"):
        self.calls.append((ip, direction))
        return "blocked"


def run_packets(packets, mode):
    config = Config(port_scan_threshold=10, brute_force_attempt_threshold=5, flood_threshold_pps=10_000)
    enforcer = FakeEnforcer()
    decision = DecisionEngine(mode, enforcer if mode == "prevention" else None)
    engine = main.build_rule_engine(config)
    for pkt in packets:
        info = _extract_packet_info(pkt)
        for alert in engine.evaluate(info):
            decision.handle(alert)
    return enforcer.calls


def syn(src, dport, flags="S"):
    return IP(src=src, dst="192.168.56.10") / TCP(sport=40000, dport=dport, flags=flags)


def test_parser_extracts_fields_and_pure_syn():
    info = _extract_packet_info(syn("10.0.0.20", 22))
    assert info["src_ip"] == "10.0.0.20" and info["dst_port"] == 22
    assert info["syn_flag"] is True
    syn_ack = _extract_packet_info(syn("10.0.0.20", 22, flags="SA"))
    assert syn_ack["syn_flag"] is False


def test_parser_keeps_payload():
    pkt = IP(src="10.0.0.20", dst="192.168.56.10") / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\nUser-Agent: Nikto\r\n")
    assert b"Nikto" in _extract_packet_info(pkt)["payload"]


def test_port_scan_blocked_only_in_prevention_mode():
    scan = [syn("10.0.0.20", port) for port in range(1, 40)]
    assert run_packets(scan, "detection") == []
    assert ("10.0.0.20", "inbound") in run_packets(scan, "prevention")


def test_legitimate_traffic_raises_no_alert():
    normal = [syn("10.0.0.30", 80, flags="PA") for _ in range(30)]
    assert run_packets(normal, "prevention") == []


def test_default_config_file_loads():
    cfg = load_config(str(Path(__file__).resolve().parent.parent / "config.yaml"))
    assert cfg.mode in {"detection", "prevention"}
