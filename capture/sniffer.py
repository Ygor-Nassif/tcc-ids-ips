"""
Captura de tráfego com Scapy.

Extrai apenas os campos úteis ao motor de detecção e os entrega em um
dicionário simples (packet_info), desacoplando a detecção da biblioteca de
captura. Requer root.
"""

from typing import Callable

from scapy.all import sniff, IP, TCP, UDP, Raw

PAYLOAD_BYTES = 512  # quanto do payload guardar para as assinaturas


def _extract_packet_info(packet) -> dict | None:
    if not packet.haslayer(IP):
        return None

    ip_layer = packet[IP]
    info = {
        "ts": float(packet.time),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "proto": "OTHER",
        "src_port": None,
        "dst_port": None,
        "syn_flag": False,
        "packet_len": len(packet),
        "payload": b"",
    }

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info["proto"] = "TCP"
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        # Só SYN puro (sem ACK) conta como tentativa de nova conexão.
        info["syn_flag"] = bool(tcp.flags & 0x02) and not (tcp.flags & 0x10)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info["proto"] = "UDP"
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport

    if packet.haslayer(Raw):
        info["payload"] = bytes(packet[Raw].load)[:PAYLOAD_BYTES]

    return info


def start_sniffing(interface: str, on_packet: Callable[[dict], None]) -> None:
    def _handle(packet):
        info = _extract_packet_info(packet)
        if info is not None:
            on_packet(info)

    print(f"[captura] Sniffing em '{interface}' (Ctrl+C para parar)")
    sniff(iface=interface, prn=_handle, store=False)
