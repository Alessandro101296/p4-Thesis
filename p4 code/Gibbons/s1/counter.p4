/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define INDEX 0
const bit<16> L2_LEARN_ETHER_TYPE = 0x1234;
const bit<8> CLONE  = 0;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


struct metadata {
    bit<6> pos;
    bit<6> rank;
    bit<2> index;
    bit<3> index_ultimo_lv;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;

}
/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control stage_1(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata){
        
    bit<1> pack_matchato=0;
    bit<3> right_level=1;
    bit<32> indice_registri=0;

    /* registri per la gestione delle informazioni di ogni livello*/
    register<bit<2>>(1) current_index_lv_1;
    register<bit<6>>(2) pos_lv_1;
    register<bit<6>>(2) rank_lv_1;
    register<bit<48>>(2) timestamp_lv_1;
    register<bit<2>>(1) current_index_lv_2;
    register<bit<6>>(2) pos_lv_2;
    register<bit<6>>(2) rank_lv_2;
    register<bit<48>>(2) timestamp_lv_2;
    register<bit<2>>(1) current_index_lv_3;
    register<bit<6>>(2) pos_lv_3;
    register<bit<6>>(2) rank_lv_3;
    register<bit<48>>(2) timestamp_lv_3;
    register<bit<2>>(1) current_index_lv_4;
    register<bit<6>>(2) pos_lv_4;
    register<bit<6>>(2) rank_lv_4;
    register<bit<48>>(2) timestamp_lv_4;
    register<bit<3>>(1) current_index_lv_5;
    register<bit<6>>(4) pos_lv_5;
    register<bit<6>>(4) rank_lv_5;
    register<bit<48>>(4) timestamp_lv_5;

    /* registri per salvare posizione e rank corrente*/
    register<bit<6>>(1) curr_pos;
    register<bit<6>>(1) curr_rank;

    /*logica di inoltro*/
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_out_port(bit<9> out_port){
        standard_metadata.egress_spec=out_port;
    }

    table ipv4_exact{
        key={
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_out_port;
            drop;
        }
        size = 1024;
        default_action = drop;        
    }

    /* action per la gestione del counter della posizione*/
    action increment_pos(){
        curr_pos.read(meta.pos,INDEX);
        meta.pos=meta.pos+1;
        meta.pos=meta.pos & 63;
        curr_pos.write(INDEX,meta.pos);
    }

    /*action per la gestione del counter del rank*/
    action increment_rank(){
        curr_rank.read(meta.rank,INDEX);
        meta.rank=meta.rank+1;
        meta.rank=meta.rank & 63;
        curr_rank.write(INDEX,meta.rank);
    }

    /* tabella per il match sul flusso*/
    action set_var(){
        pack_matchato=1;
    }

    table match_flow{
        key={
            hdr.ipv4.srcAddr :exact;
            hdr.ipv4.dstAddr :exact;
        }
        actions = {
            set_var;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    /* capire il livello in cui salvare tali cose */
    action select_level(bit<6> pack_rank){
        if(pack_rank & 1==0){
            right_level=2;
        }
        if(pack_rank & 3==0){
            right_level=3;
        }
        if(pack_rank & 7==0){
            right_level=4;
        }
        if(pack_rank & 15==0){
            right_level=5;
        }
    }

    /*action per la scrittura sui registri*/
    action write_lv_1(){
        current_index_lv_1.read(meta.index,INDEX);
        indice_registri=(bit<32>)meta.index;
        pos_lv_1.write(indice_registri,meta.pos);
        rank_lv_1.write(indice_registri,meta.rank);
        timestamp_lv_1.write(indice_registri,standard_metadata.ingress_global_timestamp);
        meta.index=meta.index+1;
        meta.index=meta.index & 1;
        current_index_lv_1.write(INDEX, meta.index);
    }
    action write_lv_2(){
        current_index_lv_2.read(meta.index,INDEX);
        indice_registri=(bit<32>)meta.index;
        pos_lv_2.write(indice_registri,meta.pos);
        rank_lv_2.write(indice_registri,meta.rank);
        timestamp_lv_2.write(indice_registri,standard_metadata.ingress_global_timestamp);
        meta.index=meta.index+1;
        meta.index=meta.index & 1;
        current_index_lv_2.write(INDEX, meta.index);
    }
    action write_lv_3(){
        current_index_lv_3.read(meta.index,INDEX);
        indice_registri=(bit<32>)meta.index;
        pos_lv_3.write(indice_registri,meta.pos);
        rank_lv_3.write(indice_registri,meta.rank);
        timestamp_lv_3.write(indice_registri,standard_metadata.ingress_global_timestamp);
        meta.index=meta.index+1;
        meta.index=meta.index & 1;
        current_index_lv_3.write(INDEX, meta.index);
    }
    action write_lv_4(){
        current_index_lv_4.read(meta.index,INDEX);
        indice_registri=(bit<32>)meta.index;
        pos_lv_4.write(indice_registri,meta.pos);
        rank_lv_4.write(indice_registri,meta.rank);
        timestamp_lv_4.write(indice_registri,standard_metadata.ingress_global_timestamp);
        meta.index=meta.index+1;
        meta.index=meta.index & 1;
        current_index_lv_4.write(INDEX, meta.index);
    }
    action write_lv_5(){
        current_index_lv_5.read(meta.index_ultimo_lv,INDEX);
        indice_registri=(bit<32>)meta.index_ultimo_lv;
        pos_lv_5.write(indice_registri,meta.pos);
        rank_lv_5.write(indice_registri,meta.rank);
        timestamp_lv_5.write(indice_registri,standard_metadata.ingress_global_timestamp);
        meta.index_ultimo_lv=meta.index_ultimo_lv+1;
        meta.index_ultimo_lv=meta.index_ultimo_lv & 1;
        current_index_lv_5.write(INDEX, meta.index_ultimo_lv);
    }
    
    /*blocco apply*/
    apply{
        if(hdr.ipv4.isValid()){
            increment_pos();
            match_flow.apply();
            if(pack_matchato==1){
                increment_rank();
                select_level(meta.rank);
                if(right_level==1){
                    write_lv_1();
                }
                if(right_level==2){
                    write_lv_2();
                }
                if(right_level==3){
                    write_lv_3();
                }
                if(right_level==4){
                    write_lv_4();
                }
                if(right_level==5){
                    write_lv_5();
                }
            }
            ipv4_exact.apply();
        }
    }
    


}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}      


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);


    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
stage_1(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

