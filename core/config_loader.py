"""Carrega e valida o config.yaml."""

from dataclasses import dataclass, field, fields
from pathlib import Path

import yaml

VALID_MODES = {"detection", "prevention"}


@dataclass
class Config:
    mode: str = "detection"
    interface: str = "eth0"
    protected_ips: list = field(default_factory=list)
    whitelist_ips: list = field(default_factory=list)
    block_duration_seconds: int = 600
    alert_cooldown_seconds: int = 30
    detection_window_seconds: int = 10
    port_scan_threshold: int = 15
    brute_force_attempt_threshold: int = 10
    flood_threshold_pps: int = 100
    exfil_threshold_bytes: int = 5_000_000
    exfil_window_seconds: int = 30
    log_file: str = "logs/ids_ips.log"
    metrics_file: str = "logs/events.jsonl"

    def is_prevention_mode(self) -> bool:
        return self.mode == "prevention"


def load_config(path: str = "config.yaml") -> Config:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(
            f"Arquivo de configuração não encontrado: {config_path.resolve()}"
        )

    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    known = {f.name for f in fields(Config)}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"Chaves desconhecidas no config.yaml: {sorted(unknown)}")

    config = Config(**raw)
    config.mode = str(config.mode).lower()
    if config.mode not in VALID_MODES:
        raise ValueError(f"mode deve ser um de {sorted(VALID_MODES)}, recebido: {config.mode!r}")
    return config
