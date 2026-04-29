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

from packet_utils import FilterCriteria, PacketSummary, format_statistics


class Filters:
    """Render filter controls and the statistics panel."""

    def __init__(self, parent: tk.Widget):
        self.parent = parent
        self.apply_callback = None
        self._build_gui()

    def _build_gui(self) -> None:
        container = ttk.Frame(self.parent, padding=(0, 10, 10, 10))
        container.pack(fill=tk.BOTH, expand=True)

        filter_box = ttk.LabelFrame(container, text="Filters", padding=10)
        filter_box.pack(fill=tk.X)

        self.protocol_var = tk.StringVar(value="All")
        self.source_ip_var = tk.StringVar()
        self.destination_ip_var = tk.StringVar()
        self.source_port_var = tk.StringVar()
        self.destination_port_var = tk.StringVar()

        ttk.Label(filter_box, text="Protocol").grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.protocol_combo = ttk.Combobox(
            filter_box,
            textvariable=self.protocol_var,
            state="readonly",
            values=("All", "TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6", "Ethernet"),
            width=16,
        )
        self.protocol_combo.grid(row=1, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(filter_box, text="Source IP").grid(row=2, column=0, sticky="w", pady=(10, 6))
        self.source_ip_entry = ttk.Entry(filter_box, textvariable=self.source_ip_var)
        self.source_ip_entry.grid(row=3, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(filter_box, text="Destination IP").grid(row=4, column=0, sticky="w", pady=(10, 6))
        self.destination_ip_entry = ttk.Entry(filter_box, textvariable=self.destination_ip_var)
        self.destination_ip_entry.grid(row=5, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(filter_box, text="Source Port").grid(row=6, column=0, sticky="w", pady=(10, 6))
        self.source_port_entry = ttk.Entry(filter_box, textvariable=self.source_port_var)
        self.source_port_entry.grid(row=7, column=0, sticky="ew", padx=(0, 8))

        ttk.Label(filter_box, text="Destination Port").grid(row=8, column=0, sticky="w", pady=(10, 6))
        self.destination_port_entry = ttk.Entry(filter_box, textvariable=self.destination_port_var)
        self.destination_port_entry.grid(row=9, column=0, sticky="ew", padx=(0, 8))

        button_row = ttk.Frame(filter_box)
        button_row.grid(row=10, column=0, sticky="ew", pady=(12, 0))

        ttk.Button(button_row, text="Apply", command=self.apply).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(button_row, text="Reset", command=self.reset).pack(side=tk.LEFT)

        filter_box.columnconfigure(0, weight=1)

        for widget in (
            self.protocol_combo,
            self.source_ip_entry,
            self.destination_ip_entry,
            self.source_port_entry,
            self.destination_port_entry,
        ):
            widget.bind("<Return>", lambda _event: self.apply())

        stats_box = ttk.LabelFrame(container, text="Statistics", padding=10)
        stats_box.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.stats = tk.Text(stats_box, wrap="word", height=20, font=("Menlo", 10))
        stats_scroll = ttk.Scrollbar(stats_box, orient=tk.VERTICAL, command=self.stats.yview)
        self.stats.configure(yscrollcommand=stats_scroll.set)
        self.stats.grid(row=0, column=0, sticky="nsew")
        stats_scroll.grid(row=0, column=1, sticky="ns")

        stats_box.rowconfigure(0, weight=1)
        stats_box.columnconfigure(0, weight=1)

        self.show_statistics([], [])

    def get_criteria(self) -> FilterCriteria:
        return FilterCriteria(
            protocol=self.protocol_var.get(),
            source_ip=self.source_ip_var.get(),
            destination_ip=self.destination_ip_var.get(),
            source_port=self.source_port_var.get(),
            destination_port=self.destination_port_var.get(),
        )

    def set_apply_callback(self, callback) -> None:
        self.apply_callback = callback

    def apply(self) -> None:
        if self.apply_callback:
            self.apply_callback()

    def reset(self) -> None:
        self.protocol_var.set("All")
        self.source_ip_var.set("")
        self.destination_ip_var.set("")
        self.source_port_var.set("")
        self.destination_port_var.set("")
        self.apply()

    def show_statistics(
        self,
        all_summaries: list[PacketSummary],
        visible_summaries: list[PacketSummary],
    ) -> None:
        stats_text = format_statistics(all_summaries, visible_summaries)
        self.stats.delete("1.0", tk.END)
        self.stats.insert(tk.END, stats_text)
