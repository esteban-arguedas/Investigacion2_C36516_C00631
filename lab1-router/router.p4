#include <core.p4>
#include <v1model.p4>

header ethernet_t { bit<48> dst; bit<48> src; bit<16> kind; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len;
    bit<16> id; bit<3> flags; bit<13> offset; bit<8> ttl;
    bit<8> proto; bit<16> checksum; bit<32> src; bit<32> dst;
    varbit<320> options;
}
header ipv4_prefix_t { bit<4> version; bit<4> ihl; }
header outer_ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> tos; bit<16> len;
    bit<16> id; bit<3> flags; bit<13> offset; bit<8> ttl;
    bit<8> proto; bit<16> checksum; bit<32> src; bit<32> dst;
}
header icmp_error_t { bit<8> type; bit<8> code; bit<16> checksum; bit<32> unused; }
header quoted_data_t { bit<64> data; }
struct headers { ethernet_t eth; outer_ipv4_t outer; icmp_error_t icmp; ipv4_t ip; quoted_data_t quoted; }
struct metadata { bit<1> time_exceeded; bit<32> route_dst; }
parser Decode(packet_in p, out headers h, inout metadata m, inout standard_metadata_t sm) {
    // Solo se procesan tramas Ethernet que contienen IPv4.
    state start {
        p.extract(h.eth);
        transition select(h.eth.kind) { 0x0800: ipv4; default: accept; }
    }
    state ipv4 {
        // IHL indica la longitud total de la cabecera en palabras de 4 bytes.
        verify(p.lookahead<ipv4_prefix_t>().ihl >= 5, error.PacketTooShort);
        p.extract(h.ip, (bit<32>) (((bit<9>) p.lookahead<ipv4_prefix_t>().ihl - 5) * 32));
        transition select(h.ip.ttl, h.ip.len >= ((bit<16>) h.ip.ihl * 4 + 8), h.ip.offset) {
            (0, true, 0): quote;
            (1, true, 0): quote;
            default: accept;
        }
    }
    state quote { p.extract(h.quoted); transition accept; }
}
control Verify(inout headers h, inout metadata m) {
    // Incluye las opciones en el checksum cuando están presentes.
    apply {
        verify_checksum(h.ip.isValid(),
            {h.ip.version,h.ip.ihl,h.ip.tos,h.ip.len,h.ip.id,h.ip.flags,h.ip.offset,
             h.ip.ttl,h.ip.proto,h.ip.src,h.ip.dst,h.ip.options}, h.ip.checksum, HashAlgorithm.csum16);
    }
}
control RouterIngress(inout headers h, inout metadata m, inout standard_metadata_t sm) {
    action drop() { mark_to_drop(sm); }
    action forward(bit<48> srcMac, bit<48> dstMac, bit<9> port, bit<32> routerIp) {
        // Prepara la trama para el siguiente salto.
        h.eth.src = srcMac;
        h.eth.dst = dstMac;
        if (m.time_exceeded == 1) { h.outer.src = routerIp; }
        else { h.ip.ttl = h.ip.ttl - 1; }
        sm.egress_spec = port;
    }
    table routes {
        // Se elige el prefijo más específico; si no hay ruta, se descarta.
        key = { m.route_dst: lpm; }
        actions = { forward; drop; }
        size = 64;
        const default_action = drop();
    }
    apply {
        // Comprobar antes de restar evita que un TTL de cero pase a 255.
        if (sm.parser_error != error.NoError || !h.ip.isValid()) { drop(); }
        else if (h.ip.version != 4 || sm.checksum_error == 1) { drop(); }
        else if (h.ip.ttl <= 1) {
            // Solo se responde si hay suficientes bytes y no es un fragmento posterior.
            if (!h.quoted.isValid() || h.ip.src == 0 || h.ip.dst[31:28] == 0xe ||
                h.ip.dst == 0xffffffff || (h.ip.proto == 1 &&
                (h.quoted.data[63:56] == 3 || h.quoted.data[63:56] == 4 ||
                 h.quoted.data[63:56] == 5 || h.quoted.data[63:56] == 11 ||
                 h.quoted.data[63:56] == 12))) { drop(); }
            else {
                m.time_exceeded = 1;
                m.route_dst = h.ip.src;
                h.outer.setValid();
                h.outer.version = 4; h.outer.ihl = 5; h.outer.tos = 0;
                h.outer.len = 36 + (bit<16>) h.ip.ihl * 4;
                h.outer.id = 0; h.outer.flags = 0; h.outer.offset = 0;
                h.outer.ttl = 64; h.outer.proto = 1; h.outer.checksum = 0;
                h.outer.dst = h.ip.src;
                h.icmp.setValid(); h.icmp.type = 11; h.icmp.code = 0;
                h.icmp.checksum = 0; h.icmp.unused = 0;
                truncate((bit<32>) h.outer.len + 14);
                routes.apply();
            }
        }
        else { m.route_dst = h.ip.dst; routes.apply(); }
    }
}
control RouterEgress(inout headers h, inout metadata m, inout standard_metadata_t sm) { apply {} }
control Update(inout headers h, inout metadata m) {
    // El cambio de TTL requiere recalcular el checksum.
    apply {
        update_checksum(h.ip.isValid() && !h.outer.isValid(),
            {h.ip.version,h.ip.ihl,h.ip.tos,h.ip.len,h.ip.id,h.ip.flags,h.ip.offset,
             h.ip.ttl,h.ip.proto,h.ip.src,h.ip.dst,h.ip.options}, h.ip.checksum, HashAlgorithm.csum16);
        update_checksum(h.outer.isValid(),
            {h.outer.version,h.outer.ihl,h.outer.tos,h.outer.len,h.outer.id,h.outer.flags,
             h.outer.offset,h.outer.ttl,h.outer.proto,h.outer.src,h.outer.dst},
             h.outer.checksum, HashAlgorithm.csum16);
        update_checksum(h.icmp.isValid(),
            {h.icmp.type,h.icmp.code,h.icmp.unused,h.ip.version,h.ip.ihl,h.ip.tos,h.ip.len,
             h.ip.id,h.ip.flags,h.ip.offset,h.ip.ttl,h.ip.proto,h.ip.checksum,h.ip.src,h.ip.dst,
             h.ip.options,h.quoted.data}, h.icmp.checksum, HashAlgorithm.csum16);
    }
}
control Emit(packet_out p, in headers h) { apply { p.emit(h.eth); p.emit(h.outer); p.emit(h.icmp); p.emit(h.ip); p.emit(h.quoted); } }
V1Switch(Decode(), Verify(), RouterIngress(), RouterEgress(), Update(), Emit()) main;
