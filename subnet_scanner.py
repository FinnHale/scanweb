# subnet_scanner.py
import socket
import struct
import threading
from scapy.all import ARP, Ether, srp

class SubnetScanner:
    def __init__(self, print_output):
        self.print_output = print_output

    def scan_subnet(self, subnet):
        self.print_output(f"Scanning subnet: {subnet}")
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=2, verbose=0)[0]

        devices = []
        for sent, received in result:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})

        for device in devices:
            self.print_output(f"IP: {device['ip']}, MAC: {device['mac']}")