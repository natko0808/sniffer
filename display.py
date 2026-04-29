'''
@ASSESSME.USERID:ms1648
@ASSESSME.AUTHOR: Marko Slivaric
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import tkinter as tk
from tkinter import ttk, scrolledtext

class Display:
    def __init__(self, parent):
        self.parent = parent
        self.click_callback = None
        self.make_gui()

    
    def make_gui(self):
        tk.Label(self.parent, text="Packets", font=("Arial", 12, "bold")).pack()

        self.table = ttk.Treeview(self. parent,columns=("No", "Source", "Dest", "Protocol"), show ="headings", height=15)

        self.table.heading("No", text="No")
        self.table.heading("Source", text="Source IP")
        self.table.heading("Dest", text="Destination IP")
        self.table.heading("Protocol", text="Protocol")

        self.table.column("No", width=50)
        self.table.column("Source", width=150)
        self.table.column("Dest", width=150)
        self.table.column("Protocol", width=100)

        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.bind("<<TreeviewSelect>>", self._clicked)

        tk.Label(self.parent, text="Packet Details", font=("Arial", 12, "bold")).pack()
        self.details = scrolledtext.ScrolledText(self.parent, height=15, font=("Courier", 10))
        self.details.pack(fill=tk.BOT, expand=True)

    def add_packet(self, num, src, dst, proto):
        self.table.insert("", tk.END, values=(num, src, dst, proto))
    
    def clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def show_details(self, packets):
        self.details.delete(1.0, tk.END)

        self.details.insert(tk.END, "PACKET DETAILS\n")
        self.details.insert(tk.END, "=" * 60 + "\n\n")
        self.details.insert(tk.END, packets.show(dump=True))

        self.details.insert(tk.END, "\n\nHEX AND ASCII\n")
        self.details.insert(tk.END, "=" * 60 + "\n")

        data = bytes(packets)

        for i in range(0, len(data), 16):
            hex_str = ""
            ascii_str = ""

            for j in range(16):
                if i + j < len(data):
                    byte = data[i+j]
                    hex_str += f"{byte:02x} "
                    ascii_str += chr(byte) if 32 <= byte <= 127 else "."
                else:
                    hex_str += "   "

            self.details.insert(tk.END, f"{hex_str} {ascii_str}\n")

    def _clicked(self, event):
        selection = self.table.selection()
        if selection and self.click_callback:
            item = self.table.item(selection[0])
            packet_num = int(item['values'][0]) -1
            self.click_callback(packet_num)

    def set_click_callback(self, func):
        self.click_callback = func

        