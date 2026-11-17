"""
Registro estruturado de eventos (JSON Lines) para a avaliação do TCC.

Cada linha de logs/events.jsonl é um evento (alerta, ação, início de
sessão). O script evaluation/analyze.py cruza esses eventos com o gabarito
dos cenários (evaluation/mark.py) para calcular detecção, tempo de detecção
e falsos positivos em cada modo.
"""

import json
import threading
import time
from pathlib import Path


class MetricsRecorder:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event_type: str, **fields) -> None:
        entry = {"ts": time.time(), "type": event_type, **fields}
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


class NullRecorder:
    """Usada em testes ou quando as métricas estão desligadas."""

    def record(self, event_type: str, **fields) -> None:
        pass
