# packet_sniffer.py
from scapy.all import sniff

class PacketSniffer:
    def __init__(self, print_output):
        self.print_output = print_output

    def sniff_packets(self, filter=""):
        self.print_output(f"Sniffing packets with filter: {filter}")
        sniff(filter=filter, prn=lambda x: self.print_output(x.summary()), store=0)