# IDS/IPS de Rede com Resposta Configurável (TCC)

Sistema em Python que captura tráfego (Scapy), detecta comportamentos
suspeitos por regras e responde de forma configurável:

- `mode: detection`  -> só alerta (IDS)
- `mode: prevention` -> alerta e bloqueia via iptables (IPS)

## Estrutura

```
main.py                   ponto de entrada
config.yaml               modo, limiares, whitelist, arquivos de saída
core/                     config_loader, event_logger, metrics (events.jsonl)
capture/sniffer.py        captura e parsing de pacotes
detection/                alert.py, rules.py (5 regras)
response/                 decision.py (modo + cooldown), enforcer.py (iptables)
evaluation/               mark.py (gabarito), analyze.py (métricas)
lab/ROTEIRO_EXPERIMENTOS.md   cenários e procedimento dos testes
tests/                    31 testes (rodam sem root nem rede)
```

## Regras de detecção

| Regra | O que detecta | Limiares (config.yaml) |
|-------|---------------|------------------------|
| `port_scan` | muitas portas distintas por IP | `port_scan_threshold`, `detection_window_seconds` |
| `brute_force` | SYNs repetidos a portas 21/22/23/3389 | `brute_force_attempt_threshold` |
| `flood` | pacotes/segundo de um mesmo IP | `flood_threshold_pps` |
| `offensive_tool_signature` | User-Agent de nmap NSE, sqlmap, Nikto, Hydra | (lista no código) |
| `exfiltration` | bytes de saída do host protegido para um destino | `exfil_threshold_bytes`, `exfil_window_seconds`, `protected_ips` |

## Como rodar (VM Linux, com root)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# edite config.yaml: interface, protected_ips, whitelist_ips
sudo venv/bin/python3 main.py
```

No Windows (PowerShell) use `venv\Scripts\Activate.ps1` apenas para
editar/testar o código; a captura e o bloqueio exigem Linux (iptables).

## Testes

```bash
pip install -r requirements.txt
python3 -m pytest tests -q
```

## Decisões de projeto que valem citar no TCC

- **Separação detecção/decisão/resposta:** o modo é lido só pelo
  `DecisionEngine`; trocar de modo não altera o motor de detecção.
- **Bloqueio inline seguro:** regras entram no topo da chain (`-I ... 1`),
  são temporárias (`block_duration_seconds`), respeitam a whitelist, validam
  o IP antes de chamar o iptables e são removidas ao encerrar.
- **Bloqueio bidirecional:** infrator externo -> chain INPUT; host protegido
  exfiltrando -> chain OUTPUT para o destino.
- **Cooldown de alertas:** evita que um IP já bloqueado (que o sniffer ainda
  vê) gere alertas repetidos e distorça as métricas.
- **Métricas estruturadas:** `logs/events.jsonl` + gabarito dos cenários
  alimentam a análise quantitativa (detecção, tempo, falsos positivos).

## Limitações (para a seção de trabalhos futuros)

- Limiares fixos: o ajuste define o equilíbrio detecção × falso positivo.
- Assinaturas textuais são fáceis de evadir (ex.: trocar o User-Agent).
- Tráfego cifrado: o payload não é inspecionável (vale para a regra de
  assinatura); as regras comportamentais continuam funcionando.
- Sensor no próprio host (HIDS/HIPS); não é um dispositivo inline entre
  atacante e alvo.
- Sem detecção por anomalias/ML (discutir Sommer e Paxson, 2010).
