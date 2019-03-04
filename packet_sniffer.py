#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
     scapy.sniff(iface=interface, store=False, prn=process_packet, filter="tcp")

#process the packet received by scapy.sniff called by prn
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet)

sniff("wlp3s0")
