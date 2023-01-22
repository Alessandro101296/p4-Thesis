import shlex
import subprocess
import sys

def totalQuery():
    blocchi_a_1=0
    y=0
    i=0
    bi=0
    m=0
    p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read B 0"\'')).decode("UTF-8")
    p=p.replace("\n"," ")
    p=p.split(" ")
    for elem in p:
        if(elem.isnumeric()):
            blocchi_a_1=blocchi_a_1+int(elem)
    p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read y 0"\'')).decode("UTF-8")
    p=p.replace("\n"," ")
    p=p.split(" ")
    for elem in p:
        if(elem.isnumeric()):
            y=y+int(elem)
    p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read current_index 0"\'')).decode("UTF-8")
    p=p.replace("\n"," ")
    p=p.split(" ")
    for elem in p:
        if(elem.isnumeric()):
            i=i+int(elem)
    p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read b i"\'')).decode("UTF-8")
    p=p.replace("\n"," ")
    p=p.split(" ")
    for elem in p:
        if(elem.isnumeric()):
            bi=bi+int(elem)
    p = subprocess.check_output(shlex.split('bash -c \'simple_switch_CLI <<< "register_read m 0"\'')).decode("UTF-8")
    p=p.replace("\n"," ")
    p=p.split(" ")
    for elem in p:
        if(elem.isnumeric()):
            m=m+int(elem)
    
    print(20*blocchi_a_1+y-10-m*bi)

if __name__ == "__main__":
    totalQuery()