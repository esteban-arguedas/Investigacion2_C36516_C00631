#!/usr/bin/env python3
"""
Lab 2 - Controlador de estadisticas de trafico.

Lee periodicamente, via Thrift (simple_switch_CLI), los contadores y
registros del programa counters.p4 y los imprime en consola:
  - Contadores globales por protocolo (TCP, UDP, ICMP, otros)
  - Contadores directos por flujo (IP origen + IP destino)
  - Tamano de paquetes por flujo (min / promedio / max / ultimo)
  - Flujos elefante (marcados por el plano de datos al superar el umbral)

Uso:
  python3 controller.py [--port 9090] [--interval 5] [--threshold 1000000]
                        [--reset] [--all] [--no-clear]
"""
import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime

PROTOS = ["TCP", "UDP", "ICMP", "Otros"]          # indices 0..3 de proto_counter
REGISTERS = ["last_pkt_size", "min_pkt_size", "max_pkt_size",
             "flow_bytes", "elephant_flag"]

COUNTER_RE = re.compile(r"(MyIngress\.\w+)\[(\d+)\]=\s*\((\d+) bytes, (\d+) packets\)")
REGISTER_RE = re.compile(r"(MyIngress\.\w+)= ([\d, ]+)")


def run_cli(port, commands):
    """Ejecuta una lista de comandos en simple_switch_CLI y devuelve la salida."""
    try:
        res = subprocess.run(["simple_switch_CLI", "--thrift-port", str(port)],
                             input="\n".join(commands) + "\n",
                             capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise RuntimeError("simple_switch_CLI no respondio a tiempo")
    out = res.stdout + res.stderr
    if "Could not connect" in out or "Error" in out and "RuntimeCmd" not in out:
        raise RuntimeError(f"No se pudo conectar al switch en el puerto {port}. "
                           "Esta corriendo 'make run'?")
    return out


def load_flows(path):
    """Lee el mapeo flow_id -> (ip_origen, ip_destino) del archivo de runtime."""
    with open(path) as f:
        data = json.load(f)
    flows = {}
    for e in data["table_entries"]:
        if e.get("table") == "MyIngress.flow_stats":
            m = e["match"]
            flows[e["action_params"]["flow_id"]] = (m["hdr.ipv4.srcAddr"],
                                                    m["hdr.ipv4.dstAddr"])
    return dict(sorted(flows.items()))


def read_stats(port, flows):
    """Lee contadores y registros en una sola llamada al switch."""
    cmds = [f"counter_read MyIngress.proto_counter {i}" for i in range(len(PROTOS))]
    # En BMv2 el handle de cada entrada de flow_stats coincide con su flow_id
    # porque las entradas se insertan en orden (ver gen_runtime.py).
    cmds += [f"counter_read MyIngress.flow_counter {fid}" for fid in flows]
    cmds += [f"register_read MyIngress.{r}" for r in REGISTERS]
    out = run_cli(port, cmds)

    proto, flow = {}, {}
    for name, idx, nbytes, npkts in COUNTER_RE.findall(out):
        target = proto if name.endswith("proto_counter") else flow
        target[int(idx)] = (int(npkts), int(nbytes))

    regs = {}
    for name, values in REGISTER_RE.findall(out):
        regs[name.split(".")[-1]] = [int(v) for v in values.replace(" ", "").split(",") if v]
    return proto, flow, regs


def human(n):
    """Formatea bytes en B / KB / MB / GB."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def reg(regs, name, idx):
    values = regs.get(name, [])
    return values[idx] if idx < len(values) else 0


def rate(prev, kind, idx, current, dt):
    if not prev or dt <= 0:
        return 0.0
    return max(0, current - prev[kind].get(idx, 0)) / dt


def show(args, flows, proto, flow, regs, prev, dt, alerts):
    if not args.no_clear:
        print("\033[2J\033[H", end="")          # limpia la pantalla
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 96)
    print(f" LAB 2 - Estadisticas de trafico | switch thrift:{args.port} | {now} | cada {args.interval:g} s")
    print(f" Umbral de flujo elefante: {args.threshold} bytes ({human(args.threshold)})")
    print("=" * 96)

    print("\n POR PROTOCOLO")
    print(f" {'Protocolo':<10}{'Paquetes':>12}{'Bytes':>14}{'Pkt/s':>10}")
    print(" " + "-" * 46)
    tot_p = tot_b = 0
    for i, name in enumerate(PROTOS):
        p, b = proto.get(i, (0, 0))
        tot_p, tot_b = tot_p + p, tot_b + b
        print(f" {name:<10}{p:>12}{human(b):>14}{rate(prev, 'proto', i, p, dt):>10.1f}")
    print(" " + "-" * 46)
    print(f" {'TOTAL':<10}{tot_p:>12}{human(tot_b):>14}")

    print("\n POR FLUJO (IP origen -> IP destino)")
    print(f" {'ID':>3}  {'Flujo':<23}{'Paquetes':>10}{'Bytes':>12}{'Pkt/s':>9}"
          f"{'Min':>7}{'Prom':>7}{'Max':>7}{'Ult':>7}  Estado")
    print(" " + "-" * 94)
    shown = 0
    for fid, (src, dst) in flows.items():
        p, b = flow.get(fid, (0, 0))
        if p == 0 and not args.all:
            continue
        shown += 1
        avg = b // p if p else 0
        state = "** ELEFANTE **" if reg(regs, "elephant_flag", fid) else ""
        print(f" {fid:>3}  {src + ' -> ' + dst:<23}{p:>10}{human(b):>12}"
              f"{rate(prev, 'flow', fid, p, dt):>9.1f}"
              f"{reg(regs, 'min_pkt_size', fid):>7}{avg:>7}"
              f"{reg(regs, 'max_pkt_size', fid):>7}{reg(regs, 'last_pkt_size', fid):>7}  {state}")
    if shown == 0:
        print("   (sin trafico todavia)")
    print("\n Tamanos en bytes. Ctrl+C para salir.")

    if alerts:
        print("\n FLUJOS ELEFANTE DETECTADOS (tambien en elephants.log)")
        for msg in alerts:
            print(f"   [ALERTA] {msg}")


def main():
    ap = argparse.ArgumentParser(description="Controlador de estadisticas del Lab 2")
    ap.add_argument("--port", type=int, default=9090, help="puerto Thrift del switch")
    ap.add_argument("--interval", type=float, default=5, help="segundos entre lecturas")
    ap.add_argument("--threshold", type=int, default=1_000_000,
                    help="umbral de flujo elefante en bytes")
    ap.add_argument("--runtime", default="topo/s1-runtime.json",
                    help="archivo de runtime con el mapeo de flujos")
    ap.add_argument("--reset", action="store_true",
                    help="poner contadores y registros en cero al iniciar")
    ap.add_argument("--all", action="store_true", help="mostrar tambien flujos sin trafico")
    ap.add_argument("--no-clear", action="store_true", help="no limpiar la pantalla")
    args = ap.parse_args()

    flows = load_flows(args.runtime)

    # Configuracion inicial en el plano de datos
    setup = [f"register_write MyIngress.elephant_threshold 0 {args.threshold}"]
    if args.reset:
        setup += ["counter_reset MyIngress.proto_counter",
                  "counter_reset MyIngress.flow_counter"]
        setup += [f"register_reset MyIngress.{r}" for r in REGISTERS]
    try:
        run_cli(args.port, setup)
    except RuntimeError as e:
        sys.exit(f"[ERROR] {e}")

    prev, prev_t, known_elephants = None, None, set()
    alert_history = []
    try:
        while True:
            t = time.time()
            try:
                proto, flow, regs = read_stats(args.port, flows)
            except RuntimeError as e:
                print(f"[ERROR] {e}")
                time.sleep(args.interval)
                continue

            # Detectar flujos elefante nuevos y registrarlos en elephants.log
            alerts = []
            for fid, (src, dst) in flows.items():
                if reg(regs, "elephant_flag", fid) and fid not in known_elephants:
                    known_elephants.add(fid)
                    msg = (f"{datetime.now():%Y-%m-%d %H:%M:%S} flujo {fid} "
                           f"{src} -> {dst} es ELEFANTE "
                           f"({human(reg(regs, 'flow_bytes', fid))} > {human(args.threshold)})")
                    alert_history.append(msg)
                    with open("elephants.log", "a") as log:
                        log.write(msg + "\n")

            show(args, flows, proto, flow, regs, prev, t - prev_t if prev_t else 0, alert_history)
            prev = {"proto": {i: v[0] for i, v in proto.items()},
                    "flow": {i: v[0] for i, v in flow.items()}}
            prev_t = t
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nControlador detenido.")


if __name__ == "__main__":
    main()
