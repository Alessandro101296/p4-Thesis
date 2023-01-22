import shlex
import subprocess
import threading 
from scapy.all import sniff, Packet, BitField
from scapy.layers.l2 import Ether

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('up_down', 0, 8)]


class L2Controller(object):
    def recv_msg_cpu(self, packet):  
        if packet.type == 0x1234:
            cpu_header = CpuHeader(bytes(packet.payload))      
            up_down=cpu_header.up_down
            print(up_down)
            print("giusto")
            grana=0      
            indice=0    
            p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read grana 0"\'')).decode("UTF-8")
            p=p.replace("\n"," ")
            p=p.split(" ")
            for elem in p:
                if(elem.isnumeric()):
                    grana=grana+int(elem)
                    if(up_down==1 and grana != 8):
                        print("salgo")
                        grana=grana*2 
                    elif(up_down==2 and grana != 2):
                        print("scendo")
                        grana=int(grana/2)
            proc = subprocess.Popen(
                shlex.split('bash -c \'simple_switch_CLI <<< "register_write grana 0 %s"\'' %grana),
                stdout=subprocess.DEVNULL
            )
            proc.wait()
            proc.terminate()

    def run_cpu_port_loop(self):
        sniff(iface="cpu", prn=self.recv_msg_cpu)


if __name__ == "__main__":
    L2Controller().run_cpu_port_loop()     