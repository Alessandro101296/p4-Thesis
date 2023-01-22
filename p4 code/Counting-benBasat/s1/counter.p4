/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define INDEX 0


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
    bit<5> counter_value;
    bit<1> over_threshold;
    bit<1> flag;
    bit<5> current_offset;
    bit<32> indice_corrente;
    bit<32> target_srcAddr;
    bit<16> target_srcPort;
    bit<32> target_dstAddr;
    bit<16> target_dstPort;
    bit<8> target_protocol;
    bit<4> support_B;
    bit<1> support_b;
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<32>>(1) srcAddr;
    register<bit<16>>(1) srcPort;
    register<bit<32>>(1) dstAddr;
    register<bit<16>>(1) dstPort;
    register<bit<8>>(1) protocol;
    register<bit<32>>(1) tmpsrc;
    register<bit<32>>(1) tmpdst;

    register<bit<5>>(1) y;
    register<bit<5>>(1) m;
    register<bit<1>>(8) b;
    register<bit<4>>(1) B;
    register<bit<16>>(1) i;
    register<bit<32>>(1) current_index;

    bit<16> indice;

    action drop() {
        mark_to_drop(standard_metadata);
    }   

    action flag(){
    tmpsrc.write(INDEX,hdr.ipv4.srcAddr);
    tmpdst.write(INDEX,hdr.ipv4.dstAddr);
    srcAddr.read(meta.target_srcAddr,INDEX);
    srcPort.read(meta.target_srcPort,INDEX);
    dstAddr.read(meta.target_dstAddr,INDEX);
    dstPort.read(meta.target_dstPort,INDEX);
    protocol.read(meta.target_protocol,INDEX);
    if((hdr.ipv4.srcAddr==meta.target_srcAddr && hdr.ipv4.dstAddr==meta.target_dstAddr && hdr.tcp.srcPort==meta.target_srcPort && hdr.tcp.dstPort==meta.target_dstPort && hdr.ipv4.protocol==meta.target_protocol)){
            meta.flag=1;
        }
    else{meta.flag=0;}
    }

    action offset_read(){
        m.read(meta.current_offset,INDEX);
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


    action set_current_index(bit<32> index){
        current_index.write(INDEX,index);
    }

    table match_index{
        key={
            indice: ternary;
        }
        actions ={
            set_current_index;
        }
    }

    action write_on_array(){
        y.read(meta.counter_value,INDEX);
        B.read(meta.support_B,INDEX);
        if(meta.flag==1){
            meta.counter_value=meta.counter_value+1;
        }
        if(meta.counter_value>=20){
            meta.counter_value=meta.counter_value-20;
            meta.over_threshold=1;
            meta.support_B=meta.support_B+1;
        }
        else{ meta.over_threshold=0;}        
        current_index.read(meta.indice_corrente,INDEX);
        b.read(meta.support_b,meta.indice_corrente);
        if(meta.support_b==1){
            meta.support_B=meta.support_B-1;
        }
        B.write(INDEX,meta.support_B);
        b.write(meta.indice_corrente,meta.over_threshold);
        y.write(INDEX,meta.counter_value);
        m.write(INDEX,0);
        i.read(indice,INDEX);
        indice=indice+1;
        i.write(INDEX,indice);
    }

    action counter_up(){
        y.read(meta.counter_value,INDEX);
        if(meta.flag==1){
            meta.counter_value=meta.counter_value+1;
        }
        y.write(INDEX,meta.counter_value);
        m.read(meta.current_offset,INDEX);
        meta.current_offset=meta.current_offset+1;
        m.write(INDEX,meta.current_offset);
    }

    apply{
        if(hdr.ipv4.isValid()){
            if(hdr.tcp.isValid()){
                flag();
                offset_read();
                if(meta.current_offset==19){
                    write_on_array();
                    match_index.apply();                    
                }
                else{
                    counter_up();
                }
                ipv4_exact.apply();
            }
        }


    }

}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
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
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;