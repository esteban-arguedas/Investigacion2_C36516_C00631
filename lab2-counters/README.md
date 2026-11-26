# Lab 2 — Contadores y estadísticas de tráfico en P4

Sistema de monitoreo de tráfico en el plano de datos de un switch BMv2 (v1model).

## Funcionalidades
- **Contadores directos por flujo** (`flow_counter`): tabla `flow_stats` con match exacto por IP origen + IP destino; un contador de paquetes y bytes por cada uno de los 12 flujos entre los 4 hosts.
- **Contadores globales por protocolo** (`proto_counter`): índice 0 = TCP, 1 = UDP, 2 = ICMP, 3 = otros.
- **Tamaño de paquetes por flujo** (registros): `last_pkt_size`, `min_pkt_size`, `max_pkt_size`, `flow_bytes`.
- **Detección de flujos elefante**: el umbral se escribe desde el plano de control en `elephant_threshold`; si `flow_bytes` lo supera, el switch marca el flujo en `elephant_flag`.
- **Controlador Python** (`controller.py`): lee todo vía Thrift cada 5 s, lo imprime en tablas y registra alertas en `elephants.log`.

## Archivos
| Archivo | Descripción |
| --- | --- |
| `counters.p4` | Programa P4 (parser, contadores, registros, reenvío IPv4) |
| `topo/topology.json` | Topología: 1 switch (s1), 4 hosts en subredes 10.0.1.0/24 a 10.0.4.0/24 |
| `topo/s1-runtime.json` | Reglas instaladas por P4Runtime al arrancar (generado por `gen_runtime.py`) |
| `gen_runtime.py` | Genera las reglas de reenvío y los 12 flujos con su `flow_id` |
| `controller.py` | Controlador: lectura periódica e impresión de estadísticas |
| `send_traffic.py` | Generador de tráfico exacto con Scapy (TCP, UDP, ICMP, protocolo 253) |
| `check_counters.py` | Verificación: compara lo enviado con lo contado por el switch |
| `demo_traffic.txt` | Comandos de Mininet para tráfico mixto simultáneo (iperf TCP/UDP, ping, Scapy) |

## Requisitos
VM oficial de P4 (p4lang/tutorials, Ubuntu 24.04) con p4c, BMv2 (`simple_switch_grpc`), Mininet, Scapy e iperf.

## Ejecución
El `Makefile` usa los scripts de `p4lang/tutorials`, por eso la carpeta debe copiarse dentro de `tutorials/exercises/`:
```bash
cp -r lab2-counters ~/tutorials/exercises/
cd ~/tutorials/exercises/lab2-counters
make run
```
`make run` compila el programa, levanta Mininet y carga las reglas por P4Runtime.

En otra terminal (misma carpeta):
```bash
python3 controller.py --reset --threshold 1048576
```
Opciones: `--interval` (segundos, por defecto 5), `--threshold` (bytes), `--reset` (contadores a cero), `--all` (mostrar flujos sin tráfico).

## Prueba de exactitud
En la CLI de Mininet:
```
h2 iptables -A INPUT -s 10.0.1.1 -j DROP
h1 python3 send_traffic.py --dst 10.0.2.2 --tcp 100 --udp 200 --icmp 50 --other 30
```
En otra terminal: `python3 check_counters.py`. Resultado obtenido:

| Medición | Enviado (pkts / bytes) | Contado (pkts / bytes) |
| --- | --- | --- |
| TCP | 100 / 15400 | 100 / 15400 |
| UDP | 200 / 28400 | 200 / 28400 |
| ICMP | 50 / 7100 | 50 / 7100 |
| Otros (proto 253) | 30 / 4020 | 30 / 4020 |
| Flujo h1→h2 (direct counter) | 380 / 54920 | 380 / 54920 |

Al terminar: `h2 iptables -D INPUT -s 10.0.1.1 -j DROP`.

La regla de iptables evita que h2 responda (RST / ICMP unreachable), para que solo se cuente el tráfico inyectado.

## Tráfico mixto y flujos elefante
En Mininet: `source demo_traffic.txt`. El controlador muestra los cuatro protocolos subiendo y marca como **ELEFANTE** los flujos h1→h2 (TCP) y h4→h3 (UDP) al superar 1 MB.

## Detener
```
exit
```
Luego, en la terminal: `make stop` y `make clean`.
