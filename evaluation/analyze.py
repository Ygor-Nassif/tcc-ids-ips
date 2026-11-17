"""
Cruza logs/events.jsonl (o que o sistema fez) com o gabarito dos cenários
(evaluation/ground_truth.jsonl, gerado por mark.py) e calcula as métricas
do TCC, separadas por modo de operação (detection vs prevention):

- taxa de detecção:        execuções maliciosas com >= 1 alerta
- tempo até a detecção:    início do cenário -> primeiro alerta
- taxa de bloqueio:        execuções maliciosas em que houve bloqueio (IPS)
- falsos positivos:        execuções de tráfego legítimo que geraram alerta
- tráfego legítimo bloqueado: execuções legítimas em que o IP foi bloqueado

Uso:
    python3 evaluation/analyze.py [--events logs/events.jsonl]
        [--truth evaluation/ground_truth.jsonl] [--grace 15]
        [--csv evaluation/resultados.csv]
"""

import argparse
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path


def load_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def build_intervals(truth):
    """Pareia cada 'begin' com o próximo 'end' do mesmo cenário."""
    open_runs = {}
    intervals = []
    for entry in sorted(truth, key=lambda e: e["ts"]):
        name = entry["scenario"]
        if entry["event"] == "begin":
            open_runs[name] = entry
        elif entry["event"] == "end" and name in open_runs:
            b = open_runs.pop(name)
            intervals.append({
                "scenario": name, "kind": b["kind"], "src_ip": b["src_ip"],
                "start": b["ts"], "end": entry["ts"],
            })
    return intervals, list(open_runs)


def mode_at(sessions, ts):
    mode = None
    for s in sessions:
        if s["ts"] <= ts:
            mode = s["mode"]
    return mode


def evaluate(events, intervals, grace=15.0):
    sessions = sorted((e for e in events if e["type"] == "session_start"), key=lambda e: e["ts"])
    alerts = [e for e in events if e["type"] == "alert"]
    actions = [e for e in events if e["type"] == "action"]

    rows = []
    for iv in intervals:
        lo, hi = iv["start"], iv["end"] + grace
        in_alerts = [a for a in alerts if a["src_ip"] == iv["src_ip"] and lo <= a["ts"] <= hi]
        in_actions = [a for a in actions if a["src_ip"] == iv["src_ip"] and lo <= a["ts"] <= hi]
        blocked = any(a["action"] == "blocked" for a in in_actions)
        first = min((a["ts"] for a in in_alerts), default=None)
        rows.append({
            "scenario": iv["scenario"],
            "kind": iv["kind"],
            "mode": mode_at(sessions, iv["start"]) or "desconhecido",
            "alerts": len(in_alerts),
            "rules": ",".join(sorted({a["rule"] for a in in_alerts})),
            "detected": bool(in_alerts),
            "time_to_detect_s": round(first - iv["start"], 2) if first is not None else "",
            "blocked": blocked,
        })
    return rows


def summarize(rows):
    by_mode = defaultdict(list)
    for r in rows:
        by_mode[r["mode"]].append(r)

    summary = {}
    for mode, rs in by_mode.items():
        mal = [r for r in rs if r["kind"] == "malicious"]
        leg = [r for r in rs if r["kind"] == "legit"]
        ttds = [r["time_to_detect_s"] for r in mal if r["time_to_detect_s"] != ""]
        summary[mode] = {
            "malicious_runs": len(mal),
            "detected": sum(r["detected"] for r in mal),
            "detection_rate": (sum(r["detected"] for r in mal) / len(mal)) if mal else None,
            "blocked": sum(r["blocked"] for r in mal),
            "ttd_mean_s": round(statistics.mean(ttds), 2) if ttds else None,
            "ttd_median_s": round(statistics.median(ttds), 2) if ttds else None,
            "legit_runs": len(leg),
            "false_positive_runs": sum(r["detected"] for r in leg),
            "legit_blocked_runs": sum(r["blocked"] for r in leg),
        }
    return summary


def _pct(x):
    return "n/d" if x is None else f"{x * 100:.1f}%"


def print_report(rows, summary, unfinished):
    print("\n=== Execuções ===")
    print(f"{'cenário':<18}{'tipo':<11}{'modo':<12}{'alertas':<9}{'detectou':<10}{'ttd(s)':<9}{'bloqueou':<9}")
    for r in rows:
        print(f"{r['scenario']:<18}{r['kind']:<11}{r['mode']:<12}{r['alerts']:<9}"
              f"{str(r['detected']):<10}{str(r['time_to_detect_s']):<9}{str(r['blocked']):<9}")

    print("\n=== Resumo por modo ===")
    for mode, s in summary.items():
        print(f"\n[{mode}]")
        print(f"  ataques: {s['malicious_runs']} | detectados: {s['detected']} "
              f"({_pct(s['detection_rate'])}) | bloqueados: {s['blocked']}")
        print(f"  tempo até detecção: média {s['ttd_mean_s']}s, mediana {s['ttd_median_s']}s")
        fp_rate = (s['false_positive_runs'] / s['legit_runs']) if s['legit_runs'] else None
        print(f"  tráfego legítimo: {s['legit_runs']} execuções | com alerta (falso positivo): "
              f"{s['false_positive_runs']} ({_pct(fp_rate)}) | com bloqueio: {s['legit_blocked_runs']}")

    if unfinished:
        print(f"\n[aviso] cenários com 'begin' sem 'end' (ignorados): {', '.join(unfinished)}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--events", default="logs/events.jsonl")
    ap.add_argument("--truth", default="evaluation/ground_truth.jsonl")
    ap.add_argument("--grace", type=float, default=15.0,
                    help="segundos após o fim do cenário em que alertas ainda contam")
    ap.add_argument("--csv", default="evaluation/resultados.csv")
    args = ap.parse_args(argv)

    events = load_jsonl(args.events)
    truth = load_jsonl(args.truth)
    if not events or not truth:
        print("Sem dados: confira se há eventos em", args.events, "e gabarito em", args.truth)
        return 1

    intervals, unfinished = build_intervals(truth)
    rows = evaluate(events, intervals, args.grace)
    summary = summarize(rows)
    print_report(rows, summary, unfinished)

    with open(args.csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["scenario"])
        w.writeheader()
        w.writerows(rows)
    print(f"\nResultados por execução salvos em {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
