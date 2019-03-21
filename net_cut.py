#!/usr/bin/env python3
import netfilterqueue

def process_packet(packet):
    print(packet)
    packet.drop()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

#Remember to delte iptables wih iptables --flush
