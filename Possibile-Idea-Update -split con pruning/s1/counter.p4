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
header cpu_t {
    bit<8> curr_cammino;
}

struct metadata {
    bit<3> livello_split;
    bit<16> contatore_valore;
    bit<48> tmp_timestamp_low;
    bit<48> tmp_timestamp_up;
    bit<48> swap_timestamp_low;
    bit<48> swap_timestamp_up;
    bit<1> blocco_valido;
    bit<1> prosegui;
    bit<4> grana_corrente;
    bit<16> soglia_corrente;
    bit<48> soglia_up;
    bit<48> soglia_down;
    bit<4> blocco_da_controllare;
    bit<4> cammino_saved;
    bit<1> soglia_attivata;
    bit<3> auxiliary_level;
}

struct headers {
    ethernet_t   ethernet;
    cpu_t cpu;
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

/*registri  variabili per la gestione della grana e della soglia corrente*/
    bit<2> up_down=0;
    bit<4> contatore_step=0;
    bit<32> index;
    bit<4> address_bit;
    bit<4> bit_curr_path;
    register <bit<3>>(1) split_level;
    register <bit<4>>(1) blocco_da_controllare;
    register <bit<4>>(1) grana;
    register <bit<16>>(1) soglia;
    register <bit<4>>(1) curr_path;
/*registri per gestire le info dei blocchi*/
    register <bit<16>>(7) contatore;
    register <bit<48>>(7) timestamp_low_contatore;
    register <bit<48>>(7) timestamp_low_blocco1;
    register <bit<48>>(7) timestamp_up_blocco1;
    register <bit<1>>(7) valido_blocco1;
    register <bit<48>>(7) timestamp_low_blocco2;
    register <bit<48>>(7) timestamp_up_blocco2;
    register <bit<1>>(7) valido_blocco2;
    register <bit<48>>(7) timestamp_low_blocco3;
    register <bit<48>>(7) timestamp_up_blocco3;
    register <bit<1>>(7) valido_blocco3;
    register <bit<48>>(7) timestamp_low_blocco4;
    register <bit<48>>(7) timestamp_up_blocco4;
    register <bit<1>>(7) valido_blocco4;
    register <bit<48>>(7) timestamp_low_blocco5;
    register <bit<48>>(7) timestamp_up_blocco5;
    register <bit<1>>(7) valido_blocco5;

/* registri per salvare le soglie per l'attivazione degli allarmi */
    register <bit<48>>(1) soglia_blocco_up;
    register <bit<48>>(1) soglia_blocco_down;

/*match della barra 28*/
    action nada(){
    }
    table match_flow{
        key={
            hdr.ipv4.dstAddr: lpm;
        }
        actions={
            nada;
        }
    }

/* gestione indice registri*/
    action read_data(){
        split_level.read(meta.livello_split,INDEX);
        split_level.read(meta.auxiliary_level,INDEX);
        bit<3> num_bit=4-meta.livello_split;
        address_bit=(bit<4>)hdr.ipv4.dstAddr[3:0]>>num_bit;
        num_bit=num_bit+1;
        bit_curr_path=(bit<4>)hdr.ipv4.dstAddr[3:0]>>num_bit;
    }
    action read_cammino(){
        curr_path.read(meta.cammino_saved,INDEX);
    }

    action set_index(bit<32> indice){
        index=indice;
    }   

    table get_index{
        key={
            meta.livello_split: exact;
            address_bit:exact;
        }
        actions={
            set_index;
        }
    }
/* blocco logico per la gestione dei contatori ausiliari*/
    action set_alternative_counter(){        
        meta.cammino_saved=meta.cammino_saved>>1;
        bit_curr_path=bit_curr_path>>1;
        meta.auxiliary_level=meta.auxiliary_level-1;
        if(meta.cammino_saved==bit_curr_path){
            if(meta.auxiliary_level>1){
                index=(bit<32>)meta.auxiliary_level+2;
            }
            else{
                index=3;
            }
        }
        else{
            meta.cammino_saved=meta.cammino_saved>>1;
            bit_curr_path=bit_curr_path>>1;
            meta.auxiliary_level=meta.auxiliary_level-1;
            if(meta.cammino_saved==bit_curr_path){
                if(meta.auxiliary_level>1){
                    index=(bit<32>)meta.auxiliary_level+2;
                }
                else{
                    index=3;
                }
            }
            else{
                meta.cammino_saved=meta.cammino_saved>>1;
                bit_curr_path=bit_curr_path>>1;
                meta.auxiliary_level=meta.auxiliary_level-1;
                if(meta.cammino_saved==bit_curr_path){
                    if(meta.auxiliary_level>1){
                        index=(bit<32>)meta.auxiliary_level+2;
                    }
                    else{
                        index=3;
                    }
                }
                else{
                    meta.cammino_saved=meta.cammino_saved>>1;
                    bit_curr_path=bit_curr_path>>1;
                    meta.auxiliary_level=meta.auxiliary_level-1;
                    if(meta.cammino_saved==bit_curr_path){
                        if(meta.auxiliary_level>1){
                            index=(bit<32>)meta.auxiliary_level+2;
                        }
                        else{
                            index=3;
                        }
                    }
                }
            }
            
        }
    }
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
/*fine logica inoltro*/

    action incrementa_step(){
        contatore_step=contatore_step+1;
    }

    action read_grana(){
        grana.read(meta.grana_corrente,INDEX);
    }

/* contatore pacchetti*/    
    action incrementa_contatore(){
        contatore_step=0;        
        contatore.read(meta.contatore_valore,index);
        timestamp_low_contatore.read(meta.tmp_timestamp_low,index);
        meta.contatore_valore=meta.contatore_valore+1;
        soglia.read(meta.soglia_corrente,INDEX);
        if(meta.contatore_valore==meta.soglia_corrente){
            meta.prosegui=1;
            meta.contatore_valore=0;
            meta.tmp_timestamp_up=hdr.ethernet.dstAddr;
        }
        if(meta.contatore_valore==1){
            meta.tmp_timestamp_low=hdr.ethernet.dstAddr;
        }
        contatore.write(index,meta.contatore_valore);
        timestamp_low_contatore.write(index,meta.tmp_timestamp_low);
    }

/*logica dei blocchi*/
    action swap_timestamp(bit<1> valido){
        if(valido==1){
            meta.prosegui=1;
        }
        else{
            meta.prosegui=0;
        }
    }

    action merge(){
        if(meta.blocco_valido==1){
            meta.prosegui=1;
            if(contatore_step & (meta.grana_corrente-1)==0){
                meta.blocco_valido=0;
                meta.tmp_timestamp_up=meta.swap_timestamp_up;
            }   
            else{
                meta.blocco_valido=1;
            }    
        }
        else{
            meta.prosegui=0;
            meta.blocco_valido=1;
        }
    }

/* action di controllo soglie*/
    action leggi_soglie(){
        soglia_blocco_up.read(meta.soglia_up,INDEX);
        soglia_blocco_down.read(meta.soglia_down,INDEX);
        blocco_da_controllare.read(meta.blocco_da_controllare,INDEX);
    }

    action soglia_tmp(){
        if(meta.tmp_timestamp_up-meta.tmp_timestamp_low<meta.soglia_up){
            meta.livello_split=meta.livello_split+1;
            meta.cammino_saved=address_bit;
        }      
    }    

    action send_alarm(){
        if(meta.blocco_da_controllare==contatore_step){
            soglia_tmp();
        }
        split_level.write(INDEX,meta.livello_split);
        curr_path.write(INDEX,meta.cammino_saved);
    }

/*letture e scritture per ogni blocco*/    
    action blocco_1(){
        incrementa_step();
        valido_blocco1.read(meta.blocco_valido,index);
        timestamp_low_blocco1.read(meta.swap_timestamp_low,index);
        timestamp_up_blocco1.read(meta.swap_timestamp_up,index);
        swap_timestamp(meta.blocco_valido);
        timestamp_low_blocco1.write(index,meta.tmp_timestamp_low);
        timestamp_up_blocco1.write(index,meta.tmp_timestamp_up);
        valido_blocco1.write(index,1);
        send_alarm();
    }
    action blocco_2(){
        incrementa_step();
        valido_blocco2.read(meta.blocco_valido,index);
        timestamp_low_blocco2.read(meta.tmp_timestamp_low,index);
        timestamp_up_blocco2.read(meta.tmp_timestamp_up,index);
        merge();
        timestamp_low_blocco2.write(index,meta.swap_timestamp_low);
        timestamp_up_blocco2.write(index,meta.swap_timestamp_up);
        valido_blocco2.write(index,meta.blocco_valido);
    }
    action blocco_3(){
        incrementa_step();       
        valido_blocco3.read(meta.blocco_valido,index);
        timestamp_low_blocco3.read(meta.swap_timestamp_low,index);
        timestamp_up_blocco3.read(meta.swap_timestamp_up,index);
        swap_timestamp(meta.blocco_valido);
        timestamp_low_blocco3.write(index,meta.tmp_timestamp_low);
        timestamp_up_blocco3.write(index,meta.tmp_timestamp_up);
        valido_blocco3.write(index,1);
        send_alarm();
    }    
    action blocco_4(){
        incrementa_step();
        valido_blocco4.read(meta.blocco_valido,index);
        timestamp_low_blocco4.read(meta.tmp_timestamp_low,index);
        timestamp_up_blocco4.read(meta.tmp_timestamp_up,index);        
        merge();
        timestamp_low_blocco4.write(index,meta.swap_timestamp_low);
        timestamp_up_blocco4.write(index,meta.swap_timestamp_up);
        valido_blocco4.write(index,meta.blocco_valido);
    }
    action blocco_5(){
        incrementa_step();
        timestamp_low_blocco5.write(index,meta.tmp_timestamp_low);
        timestamp_up_blocco5.write(index,meta.tmp_timestamp_up);
        valido_blocco5.write(index,1);
        send_alarm();
    }
   
/* modifica grana corrente*/
    apply{
        if(hdr.ipv4.isValid()){
            if(hdr.tcp.isValid()){
                /* se il prefisso è valido allora controlla i bit*/
                if(match_flow.apply().hit){
                    /*leggi i bit dell' address del pack che ti interessano*/
                    read_data();
                    /* leggi il path sull' albero che sto seguendo per ora*/
                    read_cammino();
                    /*se cammino e bit letti corrispondono allora incrementa uno dei due counter del path*/
                    if(meta.cammino_saved==bit_curr_path){                   
                        if(get_index.apply().hit){                    
                            incrementa_contatore();
                        }
                    }
                    /*altrimenti incrementa il giusto contatore ausiliario*/
                    else{
                        set_alternative_counter();
                        incrementa_contatore();
                    }
                }
               
            }
        }
        ipv4_exact.apply();        
        if(meta.prosegui==1){
            leggi_soglie();
            read_grana();
            blocco_1();
        }
        if(meta.prosegui==1){            
            blocco_2();
        }
        if(meta.prosegui==1){
            blocco_3();         
        }
        if(meta.prosegui==1){
            blocco_4();
        }
        if(meta.prosegui==1){
            blocco_5();
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
        if(standard_metadata.instance_type == 0x01) {
            hdr.cpu.setValid();
            hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
            truncate((bit<32>)15);
        }
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
        packet.emit(hdr.cpu);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);


    }
}
/*************************************************************************
***********************  S W I T C H  ******************************* s
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

