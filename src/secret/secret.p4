#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "parser.p4"


/* ===================================================== Ingress ===================================================== */


control SwitchIngress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_t                     ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t         ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t     ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t           ig_tm_md)
{
    /* Forward */
    action hit(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action miss(bit<3> drop) {
        ig_dprsr_md.drop_ctl = drop;
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
            @defaultonly miss;
        }

        const default_action = miss(0x1);
        size = 1024;
    }

    // registradores para guardar o secret (4 bytes cada um)
    Register<bit<32>, bit<1>> (1) secret_v1;
    Register<bit<32>, bit<1>> (1) secret_v2;
    Register<bit<32>, bit<1>> (1) secret_v3;
    Register<bit<32>, bit<1>> (1) secret_v4;

    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v1) write_v1 = { void apply(inout bit<32> value) { value = hdr.secret.token[127:96]; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v2) write_v2 = { void apply(inout bit<32> value) { value = hdr.secret.token[95:64]; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v3) write_v3 = { void apply(inout bit<32> value) { value = hdr.secret.token[63:32]; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v4) write_v4 = { void apply(inout bit<32> value) { value = hdr.secret.token[31:0]; } };

    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v1) read_v1 = { void apply(inout bit<32> value, out bit<32> rv) { rv = value; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v2) read_v2 = { void apply(inout bit<32> value, out bit<32> rv) { rv = value; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v3) read_v3 = { void apply(inout bit<32> value, out bit<32> rv) { rv = value; } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v4) read_v4 = { void apply(inout bit<32> value, out bit<32> rv) { rv = value; } };

    apply {
        if (hdr.secret.isValid()) {
            if (hdr.secret.op == 1) { 
                write_v1.execute(0); write_v2.execute(0); write_v3.execute(0); write_v4.execute(0);
                ig_dprsr_md.drop_ctl = 1; 
            } else if (hdr.secret.op == 2) {
                meta.aux1 = read_v1.execute(0);
                meta.aux2 = read_v2.execute(0);
                meta.aux3 = read_v3.execute(0);
                meta.aux4 = read_v4.execute(0);
                
                // os IFs aninhados para não exceder limites do PHV do hardware Tofino: é um problema que eu tive
                if (meta.aux1 == hdr.secret.token[127:96]) { // verifica se secret é o mesmo do armazenado
                    if (meta.aux2 == hdr.secret.token[95:64]) {
                        if (meta.aux3 == hdr.secret.token[63:32]) {
                            if (meta.aux4 == hdr.secret.token[31:0]) {
                                forward.apply();
                            } else { ig_dprsr_md.drop_ctl = 1; }
                        } else { ig_dprsr_md.drop_ctl = 1; }
                    } else { ig_dprsr_md.drop_ctl = 1; }
                } else { ig_dprsr_md.drop_ctl = 1; }
            } else {
                ig_dprsr_md.drop_ctl = 1;
            }
        } else {
            ig_dprsr_md.drop_ctl = 1;
        }
    }
}


/* ===================================================== Egress ===================================================== */

control SwitchEgress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in egress_intrinsic_metadata_t                      eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t          eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t      eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t   eg_oport_md)
{
    apply {}
}


/* ===================================================== Final Pipeline ===================================================== */
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
