"""Captura los puertos del primer salto y el trayecto hasta h4."""
from pathlib import Path
from threading import Event
from time import sleep

from scapy.all import AsyncSniffer, Ether, ICMP, IP, raw, wrpcap
from scapy.utils import checksum


def probe(net, label, dst, initial_ttl, expected, options=False):
    # Observa la petición ICMP antes y después de cada router.
    interfaces = ['r1-p1', 'r1-p2', 'r2-p3', 'r3-p3']
    ready = Event()
    capture = AsyncSniffer(iface=interfaces, store=True, started_callback=ready.set,
                           filter=f'icmp and src host 10.0.1.10 and dst host {dst}')
    capture.start()
    if not ready.wait(4):
        raise RuntimeError('No inició la captura. Revise libpcap y permisos.')
    try:
        option_flag = '-R' if options else ''
        net['h1'].cmd(f'ping -n -c 1 -W 1 {option_flag} -t {initial_ttl} {dst}')
        sleep(.25)
    finally:
        packets = capture.stop()
    packets = [p for p in packets if ICMP in p and p[ICMP].type == 8]
    if packets:
        wrpcap(str(Path('build') / f'{label}.pcap'), packets)
    observed = {}
    for p in packets:
        if options and (p[IP].ihl <= 5 or checksum(raw(p[IP])[:p[IP].ihl * 4]) != 0):
            raise RuntimeError(f'{label}: opciones o checksum IPv4 incorrectos')
        observed.setdefault(p.sniffed_on, set()).add(p[IP].ttl)
        print(label, p.sniffed_on, 'TTL', p[IP].ttl, p[Ether].src, '->', p[Ether].dst)
    wanted = {port: {ttl} for port, ttl in zip(interfaces, expected)}
    # La ausencia en los demás puertos también comprueba el descarte.
    if observed != wanted:
        raise RuntimeError(f'{label}: esperado {wanted}, observado {observed}')


def verify(net):
    # Prueba conectividad, decremento de TTL y descartes.
    hosts = [net[f'h{i}'] for i in range(1, 5)]
    if net.ping(hosts=hosts, timeout='1') != 0:
        raise RuntimeError('Falló la conectividad entre hosts')
    probe(net, 'tres-saltos', '10.0.4.10', 64, [64, 63, 62, 61])
    probe(net, 'opciones-ipv4', '10.0.4.10', 64, [64, 63, 62, 61], options=True)
    probe(net, 'sin-ruta', '192.0.2.10', 64, [64])
    probe(net, 'ttl-agotado', '10.0.4.10', 1, [1])
    for ttl, source in [(1, '10.0.1.1'), (2, '10.255.2.1'), (3, '10.255.3.1')]:
        output = net['h1'].cmd(f'LC_ALL=C ping -n -c 1 -W 2 -t {ttl} 10.0.4.10')
        if f'From {source}' not in output or 'Time to live exceeded' not in output:
            raise RuntimeError(f'No llegó ICMP Time Exceeded del salto {ttl}:\n{output}')
        print(f'ICMP Time Exceeded recibido desde {source} (salto {ttl})')
    print('Verificación completada.')
