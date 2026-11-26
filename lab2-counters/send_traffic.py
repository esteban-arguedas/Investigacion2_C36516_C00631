#!/usr/bin/env python3
"""
Lab 2 - Generador de trafico controlado con Scapy.

Envia desde un host de Mininet una cantidad EXACTA de paquetes TCP, UDP,
ICMP y 'otros' (protocolo IP 253, reservado para experimentacion) y guarda
lo enviado en un JSON para compararlo con los contadores del switch.

Ejemplo (desde la CLI de Mininet):
  h1 python3 send_traffic.py --dst 10.0.2.2 --tcp 100 --udp 200 --icmp 50 --other 30
"""
import argparse
import json
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, sendp, get_if_addr, get_if_hwaddr


def main():
    ap = argparse.ArgumentParser(description="Generador de trafico del Lab 2")
    ap.add_argument("--dst", required=True, help="IP destino")
    ap.add_argument("--tcp", type=int, default=0, help="paquetes TCP")
    ap.add_argument("--udp", type=int, default=0, help="paquetes UDP")
    ap.add_argument("--icmp", type=int, default=0, help="paquetes ICMP")
    ap.add_argument("--other", type=int, default=0, help="paquetes de protocolo 253")
    ap.add_argument("--size", type=int, default=100, help="bytes de payload por paquete")
    ap.add_argument("--inter", type=float, default=0.005, help="segundos entre paquetes")
    ap.add_argument("--iface", default="eth0")
    ap.add_argument("--out", default="expected.json", help="archivo con lo enviado")
    args = ap.parse_args()

    src_ip = get_if_addr(args.iface)
    src_mac = get_if_hwaddr(args.iface)
    # MAC del gateway segun topology.json: 08:00:00:00:<subred>:00
    gw_mac = f"08:00:00:00:{int(src_ip.split('.')[2]):02x}:00"

    eth = Ether(src=src_mac, dst=gw_mac)
    payload = Raw(b"x" * args.size)
    packets = {
        "TCP":   (args.tcp,   eth / IP(src=src_ip, dst=args.dst) / TCP(sport=40000, dport=5001, flags="A") / payload),
        "UDP":   (args.udp,   eth / IP(src=src_ip, dst=args.dst) / UDP(sport=40000, dport=5001) / payload),
        "ICMP":  (args.icmp,  eth / IP(src=src_ip, dst=args.dst) / ICMP() / payload),
        "Otros": (args.other, eth / IP(src=src_ip, dst=args.dst, proto=253) / payload),
    }

    expected = {"src": src_ip, "dst": args.dst, "protocols": {}}
    print(f"Enviando de {src_ip} a {args.dst}:")
    for name, (count, pkt) in packets.items():
        size = len(pkt)
        if count > 0:
            sendp(pkt, iface=args.iface, count=count, inter=args.inter, verbose=False)
        expected["protocols"][name] = [count, count * size]
        print(f"  {name:<6} {count:>6} paquetes x {size:>4} bytes = {count * size:>8} bytes")

    with open(args.out, "w") as f:
        json.dump(expected, f, indent=2)
    print(f"Guardado en {args.out}")


if __name__ == "__main__":
    main()
