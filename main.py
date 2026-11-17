"""
Ponto de entrada do IDS/IPS.

    captura (sniffer) -> detecção (RuleEngine) -> decisão (DecisionEngine)
                                                        |
                                              (se modo prevention)
                                                        v
                                              resposta (IptablesEnforcer)

Uso (na VM Linux, com root):
    sudo venv/bin/python3 main.py [caminho_do_config.yaml]
"""

import signal
import sys

from capture.sniffer import start_sniffing
from core.config_loader import load_config
from core.event_logger import setup_logger
from core.metrics import MetricsRecorder
from detection.rules import (
    BruteForceRule, ExfiltrationRule, FloodRule, PortScanRule,
    RuleEngine, SignatureRule,
)
from response.decision import DecisionEngine
from response.enforcer import IptablesEnforcer


def build_rule_engine(config) -> RuleEngine:
    rules = [
        PortScanRule(config.detection_window_seconds, config.port_scan_threshold),
        FloodRule(config.flood_threshold_pps),
        BruteForceRule(config.detection_window_seconds, config.brute_force_attempt_threshold),
        SignatureRule(),
    ]
    if config.protected_ips:
        rules.append(
            ExfiltrationRule(
                config.protected_ips,
                config.exfil_window_seconds,
                config.exfil_threshold_bytes,
            )
        )
    return RuleEngine(rules)


def build_enforcer(config):
    if not config.is_prevention_mode():
        return None
    return IptablesEnforcer(config.block_duration_seconds, config.whitelist_ips)


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    config = load_config(config_path)
    logger = setup_logger(config.log_file)
    metrics = MetricsRecorder(config.metrics_file)

    enforcer = build_enforcer(config)
    decision = DecisionEngine(
        config.mode, enforcer, metrics, config.alert_cooldown_seconds
    )
    rule_engine = build_rule_engine(config)

    metrics.record(
        "session_start",
        mode=config.mode,
        interface=config.interface,
        thresholds={
            "port_scan": config.port_scan_threshold,
            "brute_force": config.brute_force_attempt_threshold,
            "flood_pps": config.flood_threshold_pps,
            "exfil_bytes": config.exfil_threshold_bytes,
        },
    )
    logger.info(f"Iniciando IDS/IPS em modo '{config.mode}' na interface '{config.interface}'")
    if config.is_prevention_mode():
        logger.warning(
            "Modo PREVENTION ativo: IPs suspeitos serão bloqueados via iptables. "
            "Confirme a whitelist_ips no config.yaml."
        )

    def shutdown(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, shutdown)

    def on_packet(packet_info: dict):
        for alert in rule_engine.evaluate(packet_info):
            decision.handle(alert)

    try:
        start_sniffing(config.interface, on_packet)
    except KeyboardInterrupt:
        logger.info("Encerrado (Ctrl+C / SIGTERM).")
    except PermissionError:
        logger.error("Permissão negada ao capturar pacotes. Rode com sudo/root.")
    finally:
        if enforcer is not None:
            enforcer.cleanup()
            logger.info("Bloqueios removidos do iptables.")
        metrics.record("session_end", mode=config.mode)


if __name__ == "__main__":
    main()
