import tkinter as tk
from tkinter import messagebox, filedialog
from capture import Capture
from display import Display
from filters import Filters
from scapy.all import IP, TCP, UDP

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1200x700")
        
        # Create instances from the 3 files
        self.capture = Capture()  # Person 1's code
        
        # Setup GUI
        self.setup_gui()
    
    def setup_gui(self):
        # Top buttons
        top = tk.Frame(self.root, bg="lightgray", pady=10)
        top.pack(fill=tk.X)
        
        self.start_btn = tk.Button(top, text="▶ Start", command=self.start, bg="green", fg="white", padx=20)
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.stop_btn = tk.Button(top, text="⏹ Stop", command=self.stop, bg="red", fg="white", padx=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        
        tk.Button(top, text="Load", command=self.load).pack(side=tk.LEFT, padx=5)
        tk.Button(top, text="Save", command=self.save).pack(side=tk.LEFT, padx=5)
        tk.Button(top, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=5)
        
        # Main area
        main = tk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Left: Display (Person 2's code)
        left = tk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.display = Display(left)
        self.display.set_click_callback(self.on_packet_click)
        
        # Right: Filters (Person 3's code)
        right = tk.Frame(main)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5)
        self.filters = Filters(right)
        self.filters.set_apply_callback(self.on_filter_apply)
        
        # Status bar
        self.status = tk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status.pack(fill=tk.X)
    
    def start(self):
        # Start capture (Person 1)
        self.capture.start(callback=self.on_new_packet)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="Capturing...")
    
    def stop(self):
        # Stop capture (Person 1)
        count = self.capture.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text=f"Stopped. {count} packets")
        self.filters.show_stats(self.capture.packets)
    
    def on_new_packet(self, pkt, num, src, dst, proto):
        # When Person 1 captures a packet, show it in Person 2's display
        self.display.add_packet(num, src, dst, proto)
        self.filters.show_stats(self.capture.packets)
    
    def on_packet_click(self, index):
        # When Person 2's display is clicked, get packet from Person 1 and show details in Person 2
        pkt = self.capture.get_packet(index)
        if pkt:
            self.display.show_details(pkt)
    
    def on_filter_apply(self):
        # When Person 3 applies filter, use Person 1's packets, filter with Person 3, display in Person 2
        filtered = self.filters.filter_packets(self.capture.packets)
        self.display.clear_table()
        
        for i, pkt in enumerate(filtered, 1):
            src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "Other"
            self.display.add_packet(i, src, dst, proto)
        
        self.filters.show_stats(filtered)
        self.status.config(text=f"{len(filtered)} of {len(self.capture.packets)} packets")
    
    def load(self):
        # Load file using Person 1, display using Person 2
        file = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap")])
        if file:
            packets = self.capture.load(file)
            self.display.clear_table()
            for i, pkt in enumerate(packets, 1):
                src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                proto = "TCP" if pkt.haslayer(TCP) else "Other"
                self.display.add_packet(i, src, dst, proto)
            self.filters.show_stats(packets)
            messagebox.showinfo("Done", f"Loaded {len(packets)} packets")
    
    def save(self):
        # Save using Person 1's code
        if not self.capture.packets:
            messagebox.showwarning("No packets", "Nothing to save!")
            return
        file = filedialog.asksaveasfilename(defaultextension=".pcap")
        if file:
            self.capture.save(file)
            messagebox.showinfo("Done", "Saved!")
    
    def clear(self):
        # Clear all 3 components
        if self.capture.capturing:
            messagebox.showwarning("Wait", "Stop capture first!")
            return
        self.capture.clear()
        self.display.clear_table()
        self.filters.show_stats([])
        self.status.config(text="Cleared")

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()