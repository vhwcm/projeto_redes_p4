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

    RegisterAction<bit<32>, bit<1>, void>(secret_v1) write_v1 = { void apply(inout bit<32> value) { value = hdr.secret.token1; } };
    RegisterAction<bit<32>, bit<1>, void>(secret_v2) write_v2 = { void apply(inout bit<32> value) { value = hdr.secret.token2; } };
    RegisterAction<bit<32>, bit<1>, void>(secret_v3) write_v3 = { void apply(inout bit<32> value) { value = hdr.secret.token3; } };
    RegisterAction<bit<32>, bit<1>, void>(secret_v4) write_v4 = { void apply(inout bit<32> value) { value = hdr.secret.token4; } };

    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v1) check_v1 = { void apply(inout bit<32> value, out bit<32> rv) { if (value == hdr.secret.token1) { rv = 1; } else { rv = 0; } } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v2) check_v2 = { void apply(inout bit<32> value, out bit<32> rv) { if (value == hdr.secret.token2) { rv = 1; } else { rv = 0; } } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v3) check_v3 = { void apply(inout bit<32> value, out bit<32> rv) { if (value == hdr.secret.token3) { rv = 1; } else { rv = 0; } } };
    RegisterAction<bit<32>, bit<1>, bit<32>>(secret_v4) check_v4 = { void apply(inout bit<32> value, out bit<32> rv) { if (value == hdr.secret.token4) { rv = 1; } else { rv = 0; } } };

    apply {
        if (hdr.secret.isValid()) {
            if (hdr.secret.op == 1) { 
                write_v1.execute(0); write_v2.execute(0); write_v3.execute(0); write_v4.execute(0);
                ig_dprsr_md.drop_ctl = 1; 
            } else if (hdr.secret.op == 2) {
                meta.aux1 = check_v1.execute(0);
                meta.aux2 = check_v2.execute(0);
                meta.aux3 = check_v3.execute(0);
                meta.aux4 = check_v4.execute(0);
                
                if (meta.aux1 == 1) { 
                    if (meta.aux2 == 1) {
                        if (meta.aux3 == 1) {
                            if (meta.aux4 == 1) {
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
