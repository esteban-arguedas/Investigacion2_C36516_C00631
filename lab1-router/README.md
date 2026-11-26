# Lab 1: router IPv4 estático

La topología conecta tres routers P4 en línea y cuatro hosts, cada uno en una subred distinta. Las rutas y las entradas de vecinos se configuran estáticamente; el router no implementa ARP.

## Requisitos

Una VM o entorno Linux con P4₁₆ (`p4c-bm2-ss`), BMv2 (`simple_switch` y `simple_switch_CLI`), Mininet, Python 3, Scapy, libpcap y `ping`. Se requieren privilegios de administrador para crear la topología y capturar paquetes.

Desde esta carpeta, ejecute:

```bash
sudo python3 topology.py --test
```

El script compila `router.p4`, crea la topología, carga las rutas y comprueba conectividad entre todos los hosts, TTL, descarte sin ruta y descarte por TTL agotado. Las capturas con paquetes observados y los logs se guardan en `build/`. Para explorar la topología manualmente, ejecute `sudo python3 topology.py` y use la consola de Mininet; salga con `exit`.

El parser admite cabeceras IPv4 con y sin opciones. Cuando se agota el TTL, el router genera una respuesta ICMP Time Exceeded y la envía por la ruta hacia el origen. Las interfaces entre routers usan direcciones 10.255.<router>.<puerto> como origen de estas respuestas.


