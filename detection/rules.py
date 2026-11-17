"""
Motor de regras de detecção (assinaturas e heurísticas por janela de tempo).

Cada regra mantém seu próprio estado (contadores por IP dentro de uma
janela deslizante) e decide, a cada pacote, se gera um Alert. Os limiares
vêm do config.yaml, então os experimentos do TCC podem variar os valores
sem alterar código.

Regras implementadas:
- PortScanRule      varredura de portas
- FloodRule         volume anormal de pacotes por segundo
- BruteForceRule    tentativas repetidas de conexão a serviços sensíveis
- SignatureRule     assinaturas de ferramentas ofensivas conhecidas (payload)
- ExfiltrationRule  volume de saída anormal do host protegido para um destino

Limitação conhecida (discutir no capítulo de resultados): as regras usam
limiares fixos, então o ajuste deles controla diretamente o equilíbrio entre
detecção e falsos positivos.
"""

from collections import defaultdict, deque
from time import time

from detection.alert import Alert


class BaseRule:
    """Interface que toda regra de detecção deve implementar."""

    name = "base_rule"

    def inspect(self, packet_info: dict) -> Alert | None:
        raise NotImplementedError


class PortScanRule(BaseRule):
    name = "port_scan"

    def __init__(self, window_seconds: int, port_threshold: int):
        self.window_seconds = window_seconds
        self.port_threshold = port_threshold
        self._history: dict[str, deque] = defaultdict(deque)

    def inspect(self, packet_info: dict) -> Alert | None:
        if packet_info.get("proto") != "TCP":
            return None

        src_ip = packet_info["src_ip"]
        now = time()
        history = self._history[src_ip]
        history.append((now, packet_info["dst_port"]))

        while history and now - history[0][0] > self.window_seconds:
            history.popleft()

        distinct_ports = {port for _, port in history}
        if len(distinct_ports) >= self.port_threshold:
            count = len(distinct_ports)
            history.clear()
            return Alert(
                src_ip=src_ip,
                rule_name=self.name,
                description=(
                    f"{count} portas distintas em {self.window_seconds}s "
                    f"(possível port scan)"
                ),
                severity="medium",
            )
        return None


class FloodRule(BaseRule):
    name = "flood"

    def __init__(self, threshold_pps: int):
        self.threshold_pps = threshold_pps
        self._history: dict[str, deque] = defaultdict(deque)

    def inspect(self, packet_info: dict) -> Alert | None:
        src_ip = packet_info["src_ip"]
        now = time()
        history = self._history[src_ip]
        history.append(now)

        while history and now - history[0] > 1.0:
            history.popleft()

        if len(history) >= self.threshold_pps:
            count = len(history)  # calcular ANTES de limpar o histórico
            history.clear()
            return Alert(
                src_ip=src_ip,
                rule_name=self.name,
                description=f"{count} pacotes/segundo (possível flood/DoS)",
                severity="high",
            )
        return None


class BruteForceRule(BaseRule):
    name = "brute_force"
    SENSITIVE_PORTS = {21, 22, 23, 3389}

    def __init__(self, window_seconds: int, attempt_threshold: int = 10):
        self.window_seconds = window_seconds
        self.attempt_threshold = attempt_threshold
        self._history: dict[tuple, deque] = defaultdict(deque)

    def inspect(self, packet_info: dict) -> Alert | None:
        if packet_info.get("proto") != "TCP":
            return None
        dst_port = packet_info["dst_port"]
        if dst_port not in self.SENSITIVE_PORTS:
            return None
        if not packet_info.get("syn_flag"):
            return None  # só tentativas de nova conexão (SYN)

        src_ip = packet_info["src_ip"]
        now = time()
        history = self._history[(src_ip, dst_port)]
        history.append(now)
        while history and now - history[0] > self.window_seconds:
            history.popleft()

        if len(history) >= self.attempt_threshold:
            history.clear()
            return Alert(
                src_ip=src_ip,
                rule_name=self.name,
                description=(
                    f"{self.attempt_threshold}+ tentativas de conexão à porta "
                    f"{dst_port} em {self.window_seconds}s (possível força bruta)"
                ),
                severity="high",
            )
        return None


class SignatureRule(BaseRule):
    """
    Detecta, no payload de pacotes TCP, assinaturas textuais de ferramentas
    ofensivas conhecidas (ex.: User-Agent padrão de scanners). É uma detecção
    por assinatura simples: trivial de evadir, mas serve para demonstrar o
    método e comparar com as heurísticas comportamentais acima.
    """

    name = "offensive_tool_signature"

    # (padrão em bytes, descrição). Comparação sem diferenciar maiúsculas.
    DEFAULT_SIGNATURES = [
        (b"nmap scripting engine", "User-Agent do Nmap Scripting Engine"),
        (b"sqlmap", "User-Agent do sqlmap"),
        (b"nikto", "User-Agent do Nikto"),
        (b"(hydra)", "User-Agent do Hydra"),
    ]

    def __init__(self, signatures=None):
        self.signatures = signatures or self.DEFAULT_SIGNATURES

    def inspect(self, packet_info: dict) -> Alert | None:
        payload = packet_info.get("payload")
        if not payload:
            return None
        lowered = payload.lower()
        for pattern, description in self.signatures:
            if pattern in lowered:
                return Alert(
                    src_ip=packet_info["src_ip"],
                    rule_name=self.name,
                    description=f"assinatura detectada: {description}",
                    severity="medium",
                )
        return None


class ExfiltrationRule(BaseRule):
    """
    Detecta volume de dados de SAÍDA do host protegido para um mesmo destino
    acima de um limite, dentro de uma janela de tempo. Em modo prevenção o
    bloqueio é no sentido de saída (OUTPUT), pois o infrator é o próprio host.
    """

    name = "exfiltration"

    def __init__(self, protected_ips: list[str], window_seconds: int, threshold_bytes: int):
        self.protected_ips = set(protected_ips)
        self.window_seconds = window_seconds
        self.threshold_bytes = threshold_bytes
        self._history: dict[str, deque] = defaultdict(deque)  # dst_ip -> (ts, bytes)

    def inspect(self, packet_info: dict) -> Alert | None:
        if packet_info["src_ip"] not in self.protected_ips:
            return None

        dst_ip = packet_info["dst_ip"]
        now = time()
        history = self._history[dst_ip]
        history.append((now, packet_info.get("packet_len", 0)))
        while history and now - history[0][0] > self.window_seconds:
            history.popleft()

        total = sum(size for _, size in history)
        if total >= self.threshold_bytes:
            history.clear()
            return Alert(
                src_ip=packet_info["src_ip"],
                rule_name=self.name,
                description=(
                    f"{total / 1_000_000:.1f} MB enviados para {dst_ip} em "
                    f"{self.window_seconds}s (possível exfiltração)"
                ),
                severity="high",
                target_ip=dst_ip,
                direction="outbound",
            )
        return None


class RuleEngine:
    """Executa cada pacote contra todas as regras ativas."""

    def __init__(self, rules: list[BaseRule]):
        self.rules = rules

    def evaluate(self, packet_info: dict) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            alert = rule.inspect(packet_info)
            if alert is not None:
                alerts.append(alert)
        return alerts
