from scapy.all import *

def write(pkt):
    wrpcap('filtered2.pcap', pkt, append=True)
i=0
for packet in PcapReader(('trace_5000-7-12-modified.pcap')):
    if(i==0):
        newDst="00:00:00:00:00:00"
        packet[Ether].dst=newDst
        write(packet)
        i=i+1
    else:        
        if(packet[IP].len>len(packet)):
            i=i+1
            continue
        time=str(packet.time).replace(".","")  
        print(time)      
        newDst="00"
        for x in range(len(time)):
            if(x%2==0):
                newDst=newDst+":"+time[x]
            else:
                newDst=newDst+time[x]
        newDst=":".join(map(lambda x:"%02x" % int(x), newDst.split(":")))
        packet[Ether].dst=newDst
        write(packet)

    
# devo cancellare i pack trucated
