import socket
import struct
import random

class PortScanner:
    def __init__(self, target, port_range, scan_type, print_output):
        self.target = self.resolve_hostname(target)  # Resolve hostname to IP here
        self.port_range = self.parse_port_range(port_range)
        self.scan_type = scan_type
        self.print_output = print_output

    def resolve_hostname(self, hostname):
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            self.print_output(f"Invalid hostname: {hostname}")
            return None

    def parse_port_range(self, port_range):
        start, end = map(int, port_range.split('-'))
        return range(start, end + 1)

    def scan(self):
        if self.target is None:  # Check if hostname resolution failed
            return

        self.print_output(f"Starting {self.scan_type} scan on {self.target} for ports {self.port_range.start}-{self.port_range.stop - 1}")
        if self.scan_type == "tcp":
            self.tcp_connect_scan()
        elif self.scan_type == "udp":
            self.udp_scan()
        elif self.scan_type == "syn":
            self.syn_scan()
        else:
            self.print_output("Invalid scan type selected.")

    def tcp_connect_scan(self):
        for port in self.port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((self.target, port))
                    self.print_output(f"Port {port} is open")
                    self.banner_grab(port)
                except (socket.timeout, ConnectionRefusedError):
                    self.print_output(f"Port {port} is closed")

    def udp_scan(self):
        for port in self.port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                try:
                    sock.sendto(b'test', (self.target, port))
                    data, _ = sock.recvfrom(1024)
                    self.print_output(f"Port {port} is open")
                except socket.timeout:
                    self.print_output(f"Port {port} is closed")

    def syn_scan(self):
        for port in self.port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sock:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                source_port = random.randint(1024, 65535)
                packet = self.create_syn_packet(source_port, port)
                sock.sendto(packet, (self.target, 0))
                sock.settimeout(1)
                try:
                    response = sock.recv(1024)
                    if self.is_syn_ack(response, source_port):
                        self.print_output(f"Port {port} is open")
                        self.banner_grab(port)
                    else:
                        self.print_output(f"Port {port} is closed")
                except socket.timeout:
                    self.print_output(f"Port {port} is closed")

    def create_syn_packet(self, source_port, dest_port):
        # IP header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # kernel will fill this
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0  # kernel will fill this
        ip_saddr = socket.inet_aton("0.0.0.0")  # Spoofed source IP
        ip_daddr = socket.inet_aton(self.target)

        # TCP header
        tcp_source = source_port
        tcp_dest = dest_port
        tcp_seq = random.randint(1, 4294967295)
        tcp_ack_seq = 0
        tcp_offset_res = (5 << 4) + 0  # Data offset, reserved
        tcp_flags = 2  # SYN flag
        tcp_window = socket.htons(5840)  # Max window size
        tcp_check = 0  # kernel will fill this
        tcp_urg_ptr = 0

        # Pack IP header
        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl << 4 | ip_ver, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr,
                                ip_daddr)

        # Pack TCP header
        tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window, tcp_check,
                                 tcp_urg_ptr)

        # Calculate TCP checksum (pseudo header included)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        psh = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, placeholder, protocol,
                          tcp_length)
        psh = psh + tcp_header
        tcp_check = self.checksum(psh)

        # Repack TCP header with checksum
        tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window, tcp_check,
                                 tcp_urg_ptr)

        # Concatenate headers
        packet = ip_header + tcp_header
        return packet

    def checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = msg[i] << 8 | msg[i + 1]
            s = s + w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s
    
    def is_syn_ack(self, response, source_port):
        # Check if the response is a TCP packet
        if response[9] != socket.IPPROTO_TCP:
            return False

        # Get the source and destination ports from the response
        resp_source_port = struct.unpack("!H", response[34:36])[0]
        # Check if the source port in the response matches the source port used in the request
        if resp_source_port != source_port:
            return False

        # Get TCP flags from the response
        flags = struct.unpack("!H", response[46:48])[0]
        # Check for SYN-ACK flags (0x12)
        if flags & 0x12 != 0x12:
            return False

        return True

    def banner_grab(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                sock.connect((self.target, port))
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode().strip()
                self.print_output(f"Banner on port {port}: {banner}")
        except:
            self.print_output(f"Could not grab banner on port {port}")