"""
Marca o início e o fim de cada cenário de teste (gabarito da avaliação).

Rode NA VM DO SENSOR (a mesma que grava events.jsonl), para que os
timestamps usem o mesmo relógio. Fluxo típico por execução:

    python3 evaluation/mark.py begin port_scan malicious 192.168.56.20
    #   ... na VM atacante, execute o ataque ...
    python3 evaluation/mark.py end port_scan

kind: "malicious" (ataque, esperado detectar) ou "legit" (tráfego normal,
esperado NÃO gerar alerta). src_ip é o IP de origem do tráfego do cenário.
"""

import argparse
import json
import sys
import time
from pathlib import Path

DEFAULT_FILE = "evaluation/ground_truth.jsonl"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="event", required=True)

    begin = sub.add_parser("begin")
    begin.add_argument("scenario")
    begin.add_argument("kind", choices=["malicious", "legit"])
    begin.add_argument("src_ip")

    end = sub.add_parser("end")
    end.add_argument("scenario")

    parser.add_argument("--file", default=DEFAULT_FILE)
    args = parser.parse_args(argv)

    entry = {"ts": time.time(), "event": args.event, "scenario": args.scenario}
    if args.event == "begin":
        entry.update(kind=args.kind, src_ip=args.src_ip)

    path = Path(args.file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[mark] {args.event} {args.scenario}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
