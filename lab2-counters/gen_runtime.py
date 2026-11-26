#!/usr/bin/env python3
"""Genera topo/s1-runtime.json: reglas de reenvio + un flow_id por cada par de hosts."""
import json

HOSTS = {  # puerto: (ip, mac)
    1: ("10.0.1.1", "08:00:00:00:01:11"),
    2: ("10.0.2.2", "08:00:00:00:02:22"),
    3: ("10.0.3.3", "08:00:00:00:03:33"),
    4: ("10.0.4.4", "08:00:00:00:04:44"),
}

entries = [{
    "table": "MyIngress.ipv4_lpm", "default_action": True,
    "action_name": "MyIngress.drop", "action_params": {}
}]

for port, (ip, mac) in HOSTS.items():
    entries.append({
        "table": "MyIngress.ipv4_lpm",
        "match": {"hdr.ipv4.dstAddr": [ip, 32]},
        "action_name": "MyIngress.ipv4_forward",
        "action_params": {"dstAddr": mac, "port": port}
    })

flow_id = 0
for s, (src, _) in HOSTS.items():
    for d, (dst, _) in HOSTS.items():
        if s == d:
            continue
        entries.append({
            "table": "MyIngress.flow_stats",
            "match": {"hdr.ipv4.srcAddr": src, "hdr.ipv4.dstAddr": dst},
            "action_name": "MyIngress.count_flow",
            "action_params": {"flow_id": flow_id}
        })
        print(f"flow_id {flow_id:2d}: {src} -> {dst}")
        flow_id += 1

with open("topo/s1-runtime.json", "w") as f:
    json.dump({
        "target": "bmv2",
        "p4info": "build/counters.p4.p4info.txtpb",
        "bmv2_json": "build/counters.json",
        "table_entries": entries
    }, f, indent=2)
print("topo/s1-runtime.json generado")
