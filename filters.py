'''
@ASSESSME.USERID: nk3899
@ASSESSME.AUTHOR: 
@ASSESSME.DESCRIPTION: Pqcket sniffer filters and statistics GUI component for a network analysis tool.
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import TCP, UDP, ICMP, ARP, IP


class Filters:
    def __init__(self, parent):
        self.parent = parent
        self.apply_callback = None
        self.make_gui()

    def make_gui(self):
        filter_box = tk.LabelFrame(self.parent, text="Filters", font=("Arial", 10, "bold"))
        filter_box.pack(fill=tk.X, padx=10, pady=10)

        tk.Label(filter_box, text="Protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol = tk.StringVar(value="All")
        tk.OptionMenu(filter_box, self.protocol, "All", "TCP", "UDP", "ICMP", "ARP").pack(side=tk.LEFT)

        tk.Label(filter_box, text="Source IP:").pack(side=tk.LEFT, padx=5)
        self.ip = tk.Entry(filter_box, width=15)
        self.ip.pack(side=tk.LEFT)

        stats_box = tk.LabelFrame(self.parent, text="Statistics", font=("Arial", 10, "bold"))
        stats_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.stats = scrolledtext.ScrolledText(stats_box, width=30, height=30)
        self.stats.pack(fill=tk.BOTH, expand=True)

    def filter_packets(self, all_packets):
        proto = self.protocol.get()
        ip_filter = self.ip.get().strip()
        result = []
        for pkt in all_packets:
            if proto != "All":
                if proto == "TCP" and not pkt.haslayer(TCP):
                    continue
                elif proto == "UDP" and not pkt.haslayer(UDP):
                    continue
                elif proto == "ICMP" and not pkt.haslayer(ICMP):
                    continue
                elif proto == "ARP" and not pkt.haslayer(ARP):
                    continue
            if ip_filter:
                if pkt.haslayer(IP):
                    if ip_filter not in pkt[IP].src and ip_filter not in pkt[IP].dst:
                        continue
                else:
                    continue
            result.append(pkt)
        return result

    def show_stats(self, packets):
        self.stats.delete(1.0, tk.END)

        total = len(packets)
        self.stats.insert(tk.END, f"Total Packets: {total}\n\n")

        if total == 0:
            return
        tcp = sum(1 for p in packets if p.haslayer(TCP))
        udp = sum(1 for p in packets if p.haslayer(UDP))
        icmp = sum(1 for p in packets if p.haslayer(ICMP))
        arp = sum(1 for p in packets if p.haslayer(ARP))
        other = total - tcp - udp - icmp - arp
        '''copied from copilot so i dont have to write everything out'''
        self.stats.insert(tk.END, "Protocol Count:\n")
        self.stats.insert(tk.END, f"TCP: {tcp}\n")
        self.stats.insert(tk.END, f"UDP: {udp}\n")
        self.stats.insert(tk.END, f"ICMP: {icmp}\n")
        self.stats.insert(tk.END, f"ARP: {arp}\n")
        self.stats.insert(tk.END, f"Other: {other}\n")

    def reset(self):
        self.protocol.set("All")
        self.ip.delete(0, tk.END)
        if self.apply_callback:
            self.apply_callback()

    def set_apply_callback(self, callback):
        self.apply_callback = callback:
