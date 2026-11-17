"""Testes do enforcer com subprocess simulado (não toca no iptables real)."""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from response import enforcer as enforcer_module
from response.enforcer import IptablesEnforcer


class Recorder:
    def __init__(self, check_exists=False):
        self.commands = []
        self.check_exists = check_exists

    def __call__(self, cmd, **kwargs):
        self.commands.append(cmd)
        if "-C" in cmd:
            return subprocess.CompletedProcess(cmd, 0 if self.check_exists else 1)
        return subprocess.CompletedProcess(cmd, 0)


def test_block_inserts_rule_at_top_of_input(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, [])
    assert enf.block_ip("10.0.0.5") == "blocked"
    assert ["iptables", "-I", "INPUT", "1", "-s", "10.0.0.5", "-j", "DROP"] in rec.commands
    enf.cleanup()


def test_outbound_block_uses_output_chain(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, [])
    enf.block_ip("203.0.113.9", "outbound")
    assert ["iptables", "-I", "OUTPUT", "1", "-d", "203.0.113.9", "-j", "DROP"] in rec.commands
    enf.cleanup()


def test_whitelist_is_never_blocked(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, ["10.0.0.9"])
    assert enf.block_ip("10.0.0.9") == "whitelisted"
    assert rec.commands == []


def test_invalid_ip_is_rejected_without_running_commands(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, [])
    assert enf.block_ip("10.0.0.5; rm -rf /") == "invalid"
    assert rec.commands == []


def test_duplicate_block_is_reported(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, [])
    enf.block_ip("10.0.0.5")
    assert enf.block_ip("10.0.0.5") == "already_blocked"
    enf.cleanup()


def test_cleanup_removes_all_rules(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(enforcer_module.subprocess, "run", rec)
    enf = IptablesEnforcer(600, [])
    enf.block_ip("10.0.0.5")
    enf.cleanup()
    assert ["iptables", "-D", "INPUT", "-s", "10.0.0.5", "-j", "DROP"] in rec.commands
    assert not enf.is_blocked("10.0.0.5")
