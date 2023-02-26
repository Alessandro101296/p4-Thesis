from scapy.all import *
import sys, socket, random

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface
def send_random_traffic(dst_ip,num_pack,pkts):
    iface = get_if()
    dst_addr = socket.gethostbyname(dst_ip)
    start=open("startnumber.txt","r+",encoding="UTF-8")
    x=int(start.read())
    print(x)
    for i in range (x,len(pkts)):
        if(i<int(num_pack)+x):
            pkts[i][IP].dst=dst_addr
            pkts[i][Ether].src=get_if_hwaddr(iface)      
            del pkts[i][IP].chksum     
            sendp(pkts[i], iface = iface)
            i=i+1           
        else:
            start.seek(0)
            start.write(str(int(num_pack)+x))
            break

def input_to_send():
    pkts=rdpcap("filtered.pcap")
    while True:
        print("inserisci Indirizzo :")
        dst_name = input()
        print("inserisci numero pacchetti :")
        num_packets = input()
        test=dst_name.replace(".","")
        if (test.isdigit() and num_packets.isdigit()):
            send_random_traffic(dst_name, num_packets, pkts)
        else:
            print ("qualcosa sbagliato")



if __name__ == '__main__':
    input_to_send()
