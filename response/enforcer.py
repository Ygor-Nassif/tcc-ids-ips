"""
Módulo de resposta: aplica e remove bloqueios via iptables (Linux, root).

- inbound  -> descarta pacotes vindos do IP (chain INPUT, -s)
- outbound -> descarta pacotes enviados ao IP (chain OUTPUT, -d)

As regras são inseridas no TOPO da chain (-I ... 1) para ter precedência
sobre regras ACCEPT já existentes. Todo bloqueio é temporário e o método
cleanup() remove tudo ao encerrar, para não deixar o laboratório bloqueado.

Só age em modo "prevention": o DecisionEngine nunca o chama em "detection".
"""

import ipaddress
import subprocess
import threading

from core.event_logger import setup_logger

CHAINS = {"inbound": ("INPUT", "-s"), "outbound": ("OUTPUT", "-d")}


class IptablesEnforcer:
    def __init__(self, block_duration_seconds: int, whitelist_ips: list[str]):
        self.block_duration_seconds = block_duration_seconds
        self.whitelist_ips = set(whitelist_ips)
        self._blocked: set[tuple[str, str]] = set()  # (ip, direction)
        self._timers: dict[tuple[str, str], threading.Timer] = {}
        self._lock = threading.Lock()
        self.logger = setup_logger()

    # ---------- utilitários ----------
    @staticmethod
    def _rule(ip: str, direction: str) -> list[str]:
        chain, flag = CHAINS[direction]
        return [chain, flag, ip, "-j", "DROP"]

    def is_blocked(self, ip: str, direction: str = "inbound") -> bool:
        return (ip, direction) in self._blocked

    # ---------- API ----------
    def block_ip(self, ip: str, direction: str = "inbound") -> str:
        """
        Retorna o resultado: "blocked", "already_blocked", "whitelisted",
        "invalid" ou "error". O resultado vai para as métricas.
        """
        try:
            ipaddress.ip_address(ip)  # evita passar valor estranho ao subprocess
        except ValueError:
            self.logger.error(f"IP inválido, bloqueio ignorado: {ip!r}")
            return "invalid"
        if direction not in CHAINS:
            self.logger.error(f"Direção inválida: {direction!r}")
            return "invalid"

        if ip in self.whitelist_ips:
            self.logger.info(f"IP {ip} está na whitelist — bloqueio ignorado.")
            return "whitelisted"

        key = (ip, direction)
        with self._lock:
            if key in self._blocked:
                return "already_blocked"
            rule = self._rule(ip, direction)
            try:
                exists = subprocess.run(
                    ["iptables", "-C", *rule], capture_output=True
                ).returncode == 0
                if not exists:
                    chain, *rest = rule
                    subprocess.run(["iptables", "-I", chain, "1", *rest], check=True)
            except FileNotFoundError:
                self.logger.error(
                    "Comando 'iptables' não encontrado (requer Linux + root)."
                )
                return "error"
            except subprocess.CalledProcessError as exc:
                self.logger.error(f"Falha ao bloquear {ip} ({direction}): {exc}")
                return "error"

            self._blocked.add(key)
            timer = threading.Timer(
                self.block_duration_seconds, self.unblock_ip, args=[ip, direction]
            )
            timer.daemon = True
            timer.start()
            self._timers[key] = timer

        self.logger.warning(f"BLOQUEADO: {ip} ({direction}) via iptables")
        return "blocked"

    def unblock_ip(self, ip: str, direction: str = "inbound") -> None:
        key = (ip, direction)
        with self._lock:
            if key not in self._blocked:
                return
            try:
                subprocess.run(["iptables", "-D", *self._rule(ip, direction)], check=True)
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                self.logger.error(f"Falha ao desbloquear {ip} ({direction}): {exc}")
                return
            self._blocked.discard(key)
            timer = self._timers.pop(key, None)
            if timer:
                timer.cancel()
        self.logger.info(f"DESBLOQUEADO: {ip} ({direction})")

    def cleanup(self) -> None:
        """Remove todos os bloqueios ativos (chamar ao encerrar o programa)."""
        for ip, direction in list(self._blocked):
            self.unblock_ip(ip, direction)
