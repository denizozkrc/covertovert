from scapy.all import *


icmp_packet = IP(dst="172.18.255.255", ttl=1) / ICMP()
send(icmp_packet)
