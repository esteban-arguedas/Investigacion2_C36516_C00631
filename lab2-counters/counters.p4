/* -*- P4_16 -*- */
/* Lab 2: Contadores y estadisticas de trafico en el plano de datos */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  PROTO_TCP  = 6;
const bit<8>  PROTO_UDP  = 17;

#define MAX_FLOWS 64

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************** CABECERAS ***************************/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<32> flow_id;     /* indice del flujo asignado por el control plane */
    bit<1>  flow_known;  /* 1 si el flujo esta en la tabla flow_stats */
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

/*************************** PARSER ***************************/
parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************** INGRESS ***************************/
control MyIngress(inout headers hdr, inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* Contador directo: un contador por entrada de flow_stats */
    direct_counter(CounterType.packets_and_bytes) flow_counter;

    /* Contador global por protocolo: 0=TCP 1=UDP 2=ICMP 3=otros */
    counter(4, CounterType.packets_and_bytes) proto_counter;

    /* Registros de tamano de paquete por flujo (bytes) */
    register<bit<32>>(MAX_FLOWS) last_pkt_size;
    register<bit<32>>(MAX_FLOWS) min_pkt_size;
    register<bit<32>>(MAX_FLOWS) max_pkt_size;
    register<bit<64>>(MAX_FLOWS) flow_bytes;

    /* Deteccion de flujos elefante */
    register<bit<64>>(1)         elephant_threshold; /* lo escribe el control plane */
    register<bit<8>>(MAX_FLOWS)  elephant_flag;      /* 1 = flujo elefante */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    action count_flow(bit<32> flow_id) {
        flow_counter.count();
        meta.flow_id = flow_id;
        meta.flow_known = 1;
    }

    action unknown_flow() {
        meta.flow_known = 0;
    }

    table flow_stats {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = { count_flow; unknown_flow; }
        counters = flow_counter;
        size = MAX_FLOWS;
        default_action = unknown_flow();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            /* 1. Contador por flujo (directo) */
            flow_stats.apply();

            /* 2. Contador global por protocolo */
            if (hdr.ipv4.protocol == PROTO_TCP) {
                proto_counter.count(0);
            } else if (hdr.ipv4.protocol == PROTO_UDP) {
                proto_counter.count(1);
            } else if (hdr.ipv4.protocol == PROTO_ICMP) {
                proto_counter.count(2);
            } else {
                proto_counter.count(3);
            }

            /* 3. Tamano de paquetes y flujos elefante */
            if (meta.flow_known == 1) {
                bit<32> pkt_len = standard_metadata.packet_length;
                bit<32> v;

                last_pkt_size.write(meta.flow_id, pkt_len);

                max_pkt_size.read(v, meta.flow_id);
                if (pkt_len > v) {
                    max_pkt_size.write(meta.flow_id, pkt_len);
                }

                min_pkt_size.read(v, meta.flow_id);
                if (v == 0 || pkt_len < v) {
                    min_pkt_size.write(meta.flow_id, pkt_len);
                }

                bit<64> total;
                flow_bytes.read(total, meta.flow_id);
                total = total + (bit<64>)pkt_len;
                flow_bytes.write(meta.flow_id, total);

                bit<64> thr;
                elephant_threshold.read(thr, 0);
                if (thr != 0 && total > thr) {
                    elephant_flag.write(meta.flow_id, 1);
                }
            }

            /* 4. Reenvio IPv4 */
            ipv4_lpm.apply();
        }
    }
}

/*************************** EGRESS ***************************/
control MyEgress(inout headers hdr, inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
