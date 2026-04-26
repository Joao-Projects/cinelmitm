from scapy.layers.inet import *
from scapy.all import *
from ldap_parser import *
from hashlib import sha256

ORANGE = '\033[0;38;5;214m'
BLUE = '\033[0;38;5;12m'
RED = '\033[1;31m'
RESET = '\033[0m'
packets = []
packets_hashes = set()
extract = True


def pkt_buffer(pkt, cli_ip, srv_ip, sniff_op):

    # sniff default. Guarda tudo.
    if sniff_op == 'def':
        if (pkt.haslayer(IP) and
            ((pkt[IP].src == cli_ip and pkt[IP].dst == srv_ip) or
             (pkt[IP].src == srv_ip and pkt[IP].dst == cli_ip))):
            packets.append(pkt)

    elif sniff_op == 'ldap':
        if pkt.haslayer(TCP) and pkt[TCP].dport == 389:
            raw_data = bytes(pkt[TCP].payload)
            pkt_hash = sha256(raw_data).hexdigest()
            if pkt_hash not in packets_hashes:
                # TODO: controlo desta opção nos argumentos de entrada
                if extract:  # extrator de credenciais LDAP (simple binding)
                    ldap_bind_req = False
                    for i in range(len(raw_data)):
                        if hex(raw_data[i]) == '0x30':  # Identifica que se trata de uma sequência em ASN.1
                            for x in range(i + 1, len(raw_data)):
                                if hex(raw_data[x]) == '0x60':  # 0x60 identifica que se trata de um pedido LDAP do tipo Bind Req
                                    ldap_bind_req = True
                                    break
                            if ldap_bind_req:
                                break
                    if ldap_bind_req:
                        packets_hashes.add(pkt_hash)
                        ldap_parser(raw_data)
                        packets.append(pkt)
                else:
                    packets.append(pkt)

    elif sniff_op == 'dns':
        if pkt.haslayer(UDP) and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
            print(f"{ORANGE}[*]{RESET} Pacotes interceptados!: {pkt.summary()}")
            # TODO: para futura análise e extração de informação DNS
            # raw_data = bytes(pkt[UDP].payload)
            # dns_parser(raw_data)
            packets.append(pkt)

    elif sniff_op == 'http':
        if pkt.haslayer(TCP) and ((pkt[TCP].dport == 80) or (pkt[TCP].sport == 80)):
            print(f"{ORANGE}[*]{RESET} Pacotes interceptados!: {pkt.summary()}")
            # TODO: para futura análise e extração de informação HTTP
            # raw_data = bytes(pkt[TCP].payload)
            # http_parser(raw_data)
            packets.append(pkt)


def sniff_packets(cli_ip, srv_ip, sniff_op, stop_event):
    while not stop_event.is_set():
        interface = get_working_if()
        filtro = f"host {cli_ip} and host {srv_ip}"

        if sniff_op == 'ldap':
            proto = 'tcp'
            port = '389'
            filtro += f" and {proto} port {port}"
        elif sniff_op == 'dns':
            proto = 'udp'
            port = '53'
            filtro += f" and {proto} port {port}"
        elif sniff_op == 'http':
            proto = 'tcp'
            port = '80'
            filtro += f" and {proto} port {port}"

        # Função wrapper/helper para passagem de múltiplos argumentos
        def pkt_buffer_wrapper(pkt):
            pkt_buffer(pkt, cli_ip, srv_ip, sniff_op)

        # faz o sniff baseado nos filtros escolhidos
        sniff(filter=filtro, iface=interface, prn=pkt_buffer_wrapper, store=0)


def log(delay, stop_event):

    global packets
    current_directory = os.getcwd()
    file_path = os.path.join(current_directory, 'sniff.pcap')
    print(f"{ORANGE}[*]{BLUE} A gravar pacotes em: {file_path} ")
    while not stop_event.is_set():
        try:
            # grava os pacotes em formato compativel com wireshark
            wrpcap(file_path, packets, linktype=1)  # linktype = 1 (ethernet)
            packets.clear()  # limpa a memoria após gravar os pacotes
            print(f"{ORANGE}[*]{BLUE} A gravar...")
        except Exception as e:
            print(f"{ORANGE}[*]{RED} Erro ao gravar: {e}")
        time.sleep(int(delay))
