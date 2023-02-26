import shlex
import subprocess
import threading 
from scapy.all import sniff, Packet, BitField
from scapy.layers.l2 import Ether

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField('path',0,8)]


class L2Controller(object):
    def recv_msg_cpu(self, packet):  
        if packet.type == 0x1234:
            cpu_header = CpuHeader(bytes(packet.payload))      
            print("giusto")
            livello_split=0      
            p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read split_level 0"\'')).decode("UTF-8")
            p=p.replace("\n"," ")
            p=p.split(" ")
            for elem in p:
                if(elem.isnumeric()):
                    livello_split+=int(elem)+1
                    
            proc = subprocess.Popen(
                shlex.split('bash -c \'simple_switch_CLI <<< "register_write split_level 0 %s"\'' %livello_split),
                stdout=subprocess.DEVNULL
            )
            proc.wait()
            proc.terminate()
            proc = subprocess.Popen(
                shlex.split('bash -c \'simple_switch_CLI <<< "register_write curr_path 0 %s"\'' %cpu_header.path),
                stdout=subprocess.DEVNULL
            )
            proc.wait()
            proc.terminate()


    def run_cpu_port_loop(self):
        sniff(iface="cpu", prn=self.recv_msg_cpu)


if __name__ == "__main__":
    L2Controller().run_cpu_port_loop()     