'''
@ASSESSME.USERID:ls3385
@ASSESSME.AUTHOR: Lovro Sekelj
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from scapy.all import sniff, wrpcap, rdpcap, IP, TCP,UDP, ICMP, ARP
import threading

class Capture:
    def __init__(self):
        self.packets = []
        self.capturing = False

    def start(self, callback):
        self.capturing = True
        self.callback = callback
        thread = threading.Thread(target = self._capture, daemon = True)
        thread.start()

    def _capture(self):
        sniff(prn = self._got_packet, store = 0, stop_filter = lambda x: not self.capturing)

    def _got_packet(self, pkt):
        self.packets.append(pkt)
        num = len(self.packets)
        src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"

        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        elif pkt.haslayer(ARP):
            proto = "ARP"
        else:
            proto = "Other"

        self.callback(pkt, num, src, dst, proto)
    
    def stop(self):
        self.capturing = False
        return len(self.packets)
    
    def get_packet(self, index):
        if index < len(self.packets):
            return self.packets[index]
        return None
    
    def save(self, filename):
        wrpcap(filename, self.packets)

    def load( self, filename):
        self.packets = rdpcap(filename)
        return self.packets