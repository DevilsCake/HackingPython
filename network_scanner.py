#!/usr/bin/env python

import scapy.all as scapy
import argparse

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_req
    ans = scapy.srp(arp_req_broad,timeout=13, verbose=False)[0]
    clients = get_clients_list(ans)
    return clients

def get_clients_list(packets):
    client_list =[]
    for packet in packets:
        dict ={"ip": packet[1].psrc, "mac":packet[1].hwsrc}
        client_list.append(dict)

    return client_list

def print_clients(list):
    print("IP\t\t\t""MAC\n................................")
    for client in list:
        print(client["ip"] + "\t" + client["mac"] )

#prepare parser
def prep_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target",help="Target network to scan")
    return parser

def get_target(parser):
    options = parser.parse_args() #returns only the OptionParser
    target_net = options.target
    return target_net

parser = prep_parser()          #prepares parser
target_net = get_target(parser) #takes the target network
scan_res = scan(target_net)     #scan target network
print_clients(scan_res)
