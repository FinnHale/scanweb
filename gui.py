# gui.py
import customtkinter as ctk
from port_scanner import PortScanner
from packet_sniffer import PacketSniffer
from subnet_scanner import SubnetScanner
import threading

class NetworkTool:
    def __init__(self, master):
        self.master = master
        master.title("Network Tool")

        self.target = ctk.StringVar(master)
        self.port_range = ctk.StringVar(master, value="1-65535")
        self.scan_type = ctk.StringVar(master, value="tcp")
        self.output_file = ctk.StringVar(master)
        self.subnet = ctk.StringVar(master)

        self.notebook = ctk.CTkTabview(master)
        self.notebook.pack(expand=True, fill="both")

        self.port_scan_tab = self.notebook.add("Port Scanner")
        self.subnet_scan_tab = self.notebook.add("Subnet Scanner")
        self.packet_sniffer_tab = self.notebook.add("Packet Sniffer")

        self.create_port_scan_widgets()
        self.create_subnet_scan_widgets()
        self.create_packet_sniffer_widgets()

        self.text_output = ctk.CTkTextbox(master, wrap="word", state="disabled")
        self.text_output.pack(expand=True, fill="both")

    def create_port_scan_widgets(self):
        # Target
        ctk.CTkLabel(self.port_scan_tab, text="Enter URL or IP:").grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkEntry(self.port_scan_tab, textvariable=self.target).grid(row=0, column=1, padx=5, pady=5)

        # Port Range
        ctk.CTkLabel(self.port_scan_tab, text="Enter Port Range (e.g., 1-65535):").grid(row=1, column=0, padx=5, pady=5)
        ctk.CTkEntry(self.port_scan_tab, textvariable=self.port_range).grid(row=1, column=1, padx=5, pady=5)

        # Scan Type
        ctk.CTkLabel(self.port_scan_tab, text="Select Scan Type:").grid(row=2, column=0, padx=5, pady=5)
        scan_types = ['tcp', 'udp', 'syn']
        ctk.CTkOptionMenu(self.port_scan_tab, variable=self.scan_type, values=scan_types).grid(row=2, column=1, padx=5, pady=5)

        # Output File
        ctk.CTkLabel(self.port_scan_tab, text="Save Results to File:").grid(row=3, column=0, padx=5, pady=5)
        ctk.CTkEntry(self.port_scan_tab, textvariable=self.output_file).grid(row=3, column=1, padx=5, pady=5)

        # Buttons
        ctk.CTkButton(self.port_scan_tab, text="Start Scan", command=self.start_scan).grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def create_subnet_scan_widgets(self):
        # Subnet
        ctk.CTkLabel(self.subnet_scan_tab, text="Enter Subnet (e.g., 192.168.1.0/24):").grid(row=0, column=0, padx=5, pady=5)
        ctk.CTkEntry(self.subnet_scan_tab, textvariable=self.subnet).grid(row=0, column=1, padx=5, pady=5)

        # Button
        ctk.CTkButton(self.subnet_scan_tab, text="Scan Subnet", command=self.start_subnet_scan).grid(row=1, column=0, columnspan=2, padx=5, pady=5)

    def create_packet_sniffer_widgets(self):
        # Filter
        ctk.CTkLabel(self.packet_sniffer_tab, text="Enter Filter (optional):").grid(row=0, column=0, padx=5, pady=5)
        self.filter_entry = ctk.CTkEntry(self.packet_sniffer_tab)
        self.filter_entry.grid(row=0, column=1, padx=5, pady=5)

        # Buttons
        ctk.CTkButton(self.packet_sniffer_tab, text="Start Sniffing", command=self.start_sniffing).grid(row=1, column=0, padx=5, pady=5)
        ctk.CTkButton(self.packet_sniffer_tab, text="Start HTTP Sniffing", command=self.start_http_sniffing).grid(row=1, column=1, padx=5, pady=5)

    def print_output(self, message):
        self.text_output.configure(state="normal")
        self.text_output.insert("end", message + "\n")
        self.text_output.configure(state="disabled")
        self.text_output.see("end")

    def start_scan(self):
        threading.Thread(target=self._scan).start()

    def _scan(self):
        scanner = PortScanner(self.target.get(), self.port_range.get(), self.scan_type.get(), self.print_output)
        scanner.scan()
        self.save_results()

    def save_results(self):
        try:
            with open(self.output_file.get(), 'w') as f:
                f.write(self.text_output.get("1.0", "end"))
            self.print_output(f"Results saved to: {self.output_file.get()}")
        except Exception as e:
            self.print_output(f"Error saving to file: {e}")

    def start_sniffing(self):
        filter_text = self.filter_entry.get()
        threading.Thread(target=self._start_sniffing, args=(filter_text,)).start()

    def _start_sniffing(self, filter_text=""):
        sniffer = PacketSniffer(self.print_output)
        sniffer.sniff_packets(filter=filter_text)

    def start_subnet_scan(self):
        threading.Thread(target=self._start_subnet_scan).start()

    def _start_subnet_scan(self):
        scanner = SubnetScanner(self.print_output)
        scanner.scan_subnet(self.subnet.get())

    def start_http_sniffing(self):
        threading.Thread(target=self._start_http_sniffing).start()

    def _start_http_sniffing(self):
        sniffer = PacketSniffer(self.print_output)
        sniffer.sniff_packets(filter="tcp port 80")