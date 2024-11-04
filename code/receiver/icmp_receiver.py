from scapy.all import *

def handle_packet(packet):
    if packet.haslayer(ICMP):
        packet.show() 


sniff(filter="icmp", prn=handle_packet)
