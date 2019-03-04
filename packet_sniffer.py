#!/usr/bin/env python

import scapy.all as scapy

def sniff(interface):
     scapy.sniff(iface=interface, store=False, prn=process_packet)

#process the packet received by scapy.sniff called by prn
def process_packet(packet):
    print(packet)

sniff("wlp3s0")
