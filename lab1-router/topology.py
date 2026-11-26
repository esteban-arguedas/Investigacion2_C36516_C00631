"""Ejecutar desde lab1-router como root en la VM de P4."""
import argparse
from pathlib import Path
import socket
import subprocess
import time

from mininet.cli import CLI
from mininet.net import Mininet

# (vecino, puerto local, puerto remoto). Para los hosts, el puerto remoto es 0.
LINKS = {
    1: [('h1', 1, 0), ('r2', 2, 1)],
    2: [('h2', 2, 0), ('r3', 3, 1)],
    3: [('h3', 2, 0), ('h4', 3, 0)],
}
# Puerto de salida para los prefijos de h1, h2, h3 y h4 respectivamente.
PORTS = {1: [1, 2, 2, 2], 2: [1, 2, 3, 3], 3: [1, 1, 2, 3]}


def mac(node, port):
    # Asigna una MAC estable a cada extremo del enlace.
    family = 1 if node.startswith('r') else 2
    return f'02:00:00:{family:02x}:{int(node[1:]):02x}:{port:02x}'


def configure(router, neighbors):
    # Espera al switch y carga sus rutas mediante Thrift.
    thrift = 9090 + router
    for attempt in range(50):
        try:
            with socket.create_connection(('127.0.0.1', thrift), timeout=.2):
                break
        except OSError:
            time.sleep(.1)
    commands = []
    for subnet, port in enumerate(PORTS[router], 1):
        peer, remote = neighbors[port]
        router_ip = (f'10.0.{int(peer[1:])}.1' if peer.startswith('h')
                     else f'10.255.{router}.{port}')
        commands.append(f'table_add RouterIngress.routes RouterIngress.forward 10.0.{subnet}.0/24 => '
                        f'{mac(f"r{router}", port)} {mac(peer, remote)} {port} {router_ip}')
    result = subprocess.run(['simple_switch_CLI', '--thrift-port', str(thrift)],
                            input='\n'.join(commands)+'\n', text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
    if result.stdout.count('Entry has been added') != len(commands):
        raise RuntimeError(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', action='store_true')
    args = parser.parse_args()
    Path('build').mkdir(exist_ok=True)
    subprocess.run(['p4c-bm2-ss', '--p4v', '16', '-o', 'build/router.json', 'router.p4'], check=True)
    net = Mininet(controller=None, build=False)
    processes = []
    peers = {i: {} for i in LINKS}
    try:
        # Los routers comparten el espacio de nombres de la máquina anfitriona.
        for i in LINKS:
            net.addHost(f'r{i}', inNamespace=False, ip=None)
        for i in range(1, 5):
            net.addHost(f'h{i}', ip=f'10.0.{i}.10/24', mac=mac(f'h{i}', 0))
        for i, edges in LINKS.items():
            for peer, port, remote in edges:
                name = f'r{i}'
                net.addLink(name, peer, port1=port, port2=remote,
                            intfName1=f'{name}-p{port}', intfName2=f'{peer}-p{remote}')
                peers[i][port] = (peer, remote)
                if peer.startswith('r'):
                    peers[int(peer[1:])][remote] = (name, port)
        net.start()
        for i, neighbors in peers.items():
            name = f'r{i}'
            cmd = ['simple_switch', '--device-id', str(i), '--thrift-port', str(9090+i)]
            for port, (peer, remote) in neighbors.items():
                intf = f'{name}-p{port}'
                net[name].cmd(f'ip link set {intf} up')
                cmd.extend(['-i', f'{port}@{intf}'])
                if peer.startswith('h'):
                    # Evita depender de ARP, que el programa P4 no implementa.
                    gateway = f'10.0.{int(peer[1:])}.1'
                    net[peer].cmd(f'ip neigh replace {gateway} lladdr {mac(name,port)} '
                                  f'nud permanent dev {peer}-p0')
                    net[peer].cmd(f'ip route replace default via {gateway}')
            with open(f'build/{name}.log', 'w') as log:
                proc = subprocess.Popen(cmd + ['build/router.json'], stdout=log, stderr=log)
            processes.append(proc)
            configure(i, neighbors)
            if proc.poll() is not None:
                raise RuntimeError(f'Revise build/{name}.log')
        if args.test:
            from verify import verify
            verify(net)
        else:
            CLI(net)
    finally:
        # Libera los procesos y enlaces incluso si falla una prueba.
        for proc in processes:
            proc.terminate()
        for proc in processes:
            proc.wait()
        net.stop()


if __name__ == '__main__':
    main()
