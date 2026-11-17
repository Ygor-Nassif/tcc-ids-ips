"""
Logger centralizado de eventos do IDS/IPS.

Registra tanto no console quanto em arquivo, para que os logs
possam ser usados depois na avaliação de métricas do TCC
(taxa de detecção, falsos positivos, tempo de resposta etc.).
"""

import logging
from pathlib import Path


def setup_logger(log_file: str = "logs/ids_ips.log") -> logging.Logger:
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("ids_ips")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        # Evita handlers duplicados se setup_logger for chamado mais de uma vez.
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
