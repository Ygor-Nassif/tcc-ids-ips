"""
Motor de decisão.

Recebe os Alerts e decide, conforme o modo do config.yaml:
- "detection"  -> registra o alerta (IDS).
- "prevention" -> registra E aciona o enforcer para bloquear (IPS).

Também aplica um cooldown por (IP, regra) para não inundar o log com o
mesmo alerta — importante porque o sniffer continua vendo pacotes de um IP
já bloqueado. Todo alerta e toda ação vão para as métricas (events.jsonl).
"""

import time

from core.event_logger import setup_logger
from core.metrics import NullRecorder
from detection.alert import Alert


class DecisionEngine:
    def __init__(self, mode: str, enforcer, metrics=None, cooldown_seconds: int = 30):
        self.mode = mode.lower()
        self.enforcer = enforcer
        self.metrics = metrics or NullRecorder()
        self.cooldown_seconds = cooldown_seconds
        self.logger = setup_logger()
        self._last_alert: dict[tuple, float] = {}

        if self.mode == "prevention" and enforcer is None:
            raise ValueError("Modo 'prevention' requer um IptablesEnforcer configurado.")

    def handle(self, alert: Alert) -> None:
        now = time.time()
        key = (alert.src_ip, alert.rule_name)
        last = self._last_alert.get(key)
        if last is not None and now - last < self.cooldown_seconds:
            return  # alerta repetido dentro do cooldown
        self._last_alert[key] = now

        self.logger.warning(str(alert))
        self.metrics.record(
            "alert",
            mode=self.mode,
            src_ip=alert.src_ip,
            rule=alert.rule_name,
            severity=alert.severity,
            description=alert.description,
        )

        if self.mode == "prevention":
            started = time.time()
            outcome = self.enforcer.block_ip(alert.target_ip, alert.direction)
            self.metrics.record(
                "action",
                mode=self.mode,
                src_ip=alert.src_ip,
                target_ip=alert.target_ip,
                direction=alert.direction,
                rule=alert.rule_name,
                action=outcome,
                response_ms=round((time.time() - started) * 1000, 2),
            )
        else:
            self.metrics.record(
                "action",
                mode=self.mode,
                src_ip=alert.src_ip,
                rule=alert.rule_name,
                action="alert_only",
            )
