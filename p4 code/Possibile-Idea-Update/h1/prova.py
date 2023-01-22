from scapy.all import *
import sys, socket, random

pkts=rdpcap("filtered.pcap")
start=open("startnumber.txt","r+",encoding="UTF-8")
x=int(start.read())
print(len(pkts))
a=0
for i in range (x,len(pkts)):
    print(pkts[i][IP].dst)
    a=a+1
start.seek(0)
start.write(str(a))
print(a)