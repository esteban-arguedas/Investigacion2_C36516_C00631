#!/usr/bin/env python3
"""
Lab 2 - Verificacion de exactitud de los contadores.

Compara lo enviado por send_traffic.py (expected.json) con lo que contaron
el contador por protocolo, el contador directo del flujo y el registro
flow_bytes del switch. Debe usarse con los contadores recien reiniciados
(controller.py --reset) y sin otro trafico en la red.
"""
import argparse
import json
import sys
from controller import load_flows, read_stats, PROTOS, reg


def main():
    ap = argparse.ArgumentParser(description="Verifica contadores contra expected.json")
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--expected", default="expected.json")
    ap.add_argument("--runtime", default="topo/s1-runtime.json")
    args = ap.parse_args()

    exp = json.load(open(args.expected))
    flows = load_flows(args.runtime)
    fid = next(f for f, (s, d) in flows.items() if s == exp["src"] and d == exp["dst"])
    try:
        proto, flow, regs = read_stats(args.port, flows)
    except RuntimeError as e:
        sys.exit(f"[ERROR] {e}")

    rows = []
    for i, name in enumerate(PROTOS):
        e_p, e_b = exp["protocols"][name]
        g_p, g_b = proto.get(i, (0, 0))
        rows.append((f"Protocolo {name}", e_p, g_p, e_b, g_b))

    tot_p = sum(v[0] for v in exp["protocols"].values())
    tot_b = sum(v[1] for v in exp["protocols"].values())
    g_p, g_b = flow.get(fid, (0, 0))
    rows.append((f"Flujo {fid} (direct counter)", tot_p, g_p, tot_b, g_b))
    rows.append((f"Flujo {fid} (registro bytes)", "-", "-", tot_b, reg(regs, "flow_bytes", fid)))

    print(f"\nVerificacion: {exp['src']} -> {exp['dst']}\n")
    print(f"{'Medicion':<30}{'Pkts env.':>10}{'Pkts cont.':>11}{'Bytes env.':>12}{'Bytes cont.':>12}  Resultado")
    print("-" * 87)
    all_ok = True
    for label, e_p, g_p, e_b, g_b in rows:
        ok = e_p == g_p and e_b == g_b
        all_ok &= ok
        print(f"{label:<30}{e_p:>10}{g_p:>11}{e_b:>12}{g_b:>12}  {'OK' if ok else 'FALLA'}")
    print("-" * 87)
    print("TODOS LOS CONTADORES COINCIDEN" if all_ok else "HAY DIFERENCIAS")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
