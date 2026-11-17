"""
Representa um alerta gerado pelo motor de detecção.

Cada regra (ver rules.py) produz um Alert ao identificar um padrão
suspeito. O Alert trafega do motor de detecção para o motor de decisão.

- src_ip:     IP associado à origem do evento.
- target_ip:  IP que seria bloqueado em modo prevenção (padrão: src_ip).
- direction:  "inbound" bloqueia tráfego vindo de target_ip (chain INPUT);
              "outbound" bloqueia tráfego indo para target_ip (chain OUTPUT),
              usado quando o infrator é o próprio host protegido (exfiltração).
"""

from dataclasses import dataclass, field
from datetime import datetime
from time import time


@dataclass
class Alert:
    src_ip: str
    rule_name: str
    description: str
    severity: str  # "low", "medium", "high"
    target_ip: str = None
    direction: str = "inbound"
    created_at: float = field(default_factory=time)
    timestamp: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        if self.target_ip is None:
            self.target_ip = self.src_ip

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.rule_name} "
            f"| origem={self.src_ip} | {self.description}"
        )
