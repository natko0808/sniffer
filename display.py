'''
@ASSESSME.USERID: YOUR_GROUP_NAME
@ASSESSME.AUTHOR: Your Name - yourRIT, Teammate Name - teammateRIT
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from packet_utils import PacketSummary


class Display:
    """Render the packet table and the details panel."""

    def __init__(self, parent: tk.Widget):
        self.parent = parent
        self.click_callback = None
        self._build_gui()

    def _build_gui(self) -> None:
        container = ttk.Frame(self.parent, padding=(10, 10, 10, 0))
        container.pack(fill=tk.BOTH, expand=True)

        paned = ttk.PanedWindow(container, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True)

        table_frame = ttk.LabelFrame(paned, text="Captured Packets", padding=8)
        details_frame = ttk.LabelFrame(paned, text="Packet Details", padding=8)
        paned.add(table_frame, weight=3)
        paned.add(details_frame, weight=2)

        columns = (
            "number",
            "time",
            "protocol",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "src_mac",
            "dst_mac",
            "length",
            "fragmentation",
        )

        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        headings = {
            "number": ("No", 60),
            "time": ("Time", 120),
            "protocol": ("Protocol", 90),
            "src_ip": ("Source IP", 140),
            "dst_ip": ("Destination IP", 140),
            "src_port": ("Src Port", 90),
            "dst_port": ("Dst Port", 90),
            "src_mac": ("Source MAC", 150),
            "dst_mac": ("Destination MAC", 150),
            "length": ("Length", 80),
            "fragmentation": ("Fragmentation", 150),
        }

        for column_name, (heading_text, width) in headings.items():
            self.table.heading(column_name, text=heading_text)
            self.table.column(column_name, width=width, anchor=tk.W, stretch=True)

        table_scroll_y = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        table_scroll_x = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.table.xview)
        self.table.configure(yscrollcommand=table_scroll_y.set, xscrollcommand=table_scroll_x.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        table_scroll_y.grid(row=0, column=1, sticky="ns")
        table_scroll_x.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.table.bind("<<TreeviewSelect>>", self._on_select)

        self.details = tk.Text(
            details_frame,
            wrap="none",
            font=("Menlo", 11),
            height=18,
        )
        details_scroll_y = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details.yview)
        details_scroll_x = ttk.Scrollbar(details_frame, orient=tk.HORIZONTAL, command=self.details.xview)
        self.details.configure(yscrollcommand=details_scroll_y.set, xscrollcommand=details_scroll_x.set)

        self.details.grid(row=0, column=0, sticky="nsew")
        details_scroll_y.grid(row=0, column=1, sticky="ns")
        details_scroll_x.grid(row=1, column=0, sticky="ew")

        details_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)

        self.show_details("Select a packet to inspect its parsed headers and payload.")

    def set_click_callback(self, callback) -> None:
        self.click_callback = callback

    def add_packet(self, summary: PacketSummary) -> None:
        row_id = self._row_id(summary.number)
        self.table.insert(
            "",
            tk.END,
            iid=row_id,
            values=(
                summary.number,
                summary.time_text,
                summary.protocol,
                summary.src_ip,
                summary.dst_ip,
                summary.src_port,
                summary.dst_port,
                summary.src_mac,
                summary.dst_mac,
                summary.length,
                summary.fragmentation,
            ),
        )
        self.table.see(row_id)

    def replace_packets(self, summaries: list[PacketSummary]) -> None:
        self.clear_packets()
        for summary in summaries:
            self.add_packet(summary)

    def clear_packets(self) -> None:
        for item in self.table.get_children():
            self.table.delete(item)

    def show_details(self, text: str) -> None:
        self.details.delete("1.0", tk.END)
        self.details.insert(tk.END, text)
        self.details.see("1.0")

    def _on_select(self, _event) -> None:
        if not self.click_callback:
            return

        selection = self.table.selection()
        if not selection:
            return

        values = self.table.item(selection[0], "values")
        if values:
            self.click_callback(int(values[0]))

    @staticmethod
    def _row_id(packet_number: int) -> str:
        return f"packet-{packet_number}"
