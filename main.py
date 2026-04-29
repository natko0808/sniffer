'''
@ASSESSME.USERID: YOUR_GROUP_NAME
@ASSESSME.AUTHOR: Your Name - yourRIT, Teammate Name - teammateRIT
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from __future__ import annotations

from pathlib import Path
from queue import Empty, Queue
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import bootstrap  # noqa: F401

from capture import Capture
from display import Display
from filters import Filters
from packet_utils import PacketSummary, build_packet_summary, format_packet_details, packet_matches


class PacketSnifferApp:
    """Coordinate capture, filtering, and GUI updates for the sniffer."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NSSA290 Network Packet Sniffer")
        self.root.geometry("1600x920")
        self.root.minsize(1200, 760)

        self.packet_queue: Queue[tuple[object, PacketSummary]] = Queue()
        self.capture = Capture(self._queue_captured_packet)
        self.all_summaries: list[PacketSummary] = []
        self.visible_summaries: list[PacketSummary] = []

        self.status_var = tk.StringVar(value="Ready. Select an interface or load a PCAP file.")
        self.interface_var = tk.StringVar()

        self._configure_style()
        self._build_gui()
        self._refresh_interfaces(select_first=True)
        self._render_empty_state()

        self.root.after(100, self._process_packet_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

    def _build_gui(self) -> None:
        controls = ttk.LabelFrame(self.root, text="Capture Controls", padding=10)
        controls.pack(fill=tk.X, padx=10, pady=(10, 0))

        ttk.Label(controls, text="Interface").grid(row=0, column=0, sticky="w")
        self.interface_combo = ttk.Combobox(
            controls,
            textvariable=self.interface_var,
            state="readonly",
            width=38,
        )
        self.interface_combo.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=(4, 0))

        ttk.Button(controls, text="Refresh Interfaces", command=self._refresh_interfaces).grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(0, 8),
            pady=(4, 0),
        )

        self.start_button = ttk.Button(controls, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=1, column=2, sticky="ew", padx=(0, 8), pady=(4, 0))

        self.stop_button = ttk.Button(controls, text="Stop Capture", command=self.stop_capture)
        self.stop_button.grid(row=1, column=3, sticky="ew", padx=(0, 8), pady=(4, 0))

        ttk.Button(controls, text="Load PCAP", command=self.load_capture_file).grid(
            row=1,
            column=4,
            sticky="ew",
            padx=(0, 8),
            pady=(4, 0),
        )

        ttk.Button(controls, text="Save PCAP", command=self.save_capture_file).grid(
            row=1,
            column=5,
            sticky="ew",
            padx=(0, 8),
            pady=(4, 0),
        )

        ttk.Button(controls, text="Clear", command=self.clear_capture).grid(
            row=1,
            column=6,
            sticky="ew",
            pady=(4, 0),
        )

        status_label = ttk.Label(controls, textvariable=self.status_var)
        status_label.grid(row=2, column=0, columnspan=7, sticky="w", pady=(10, 0))

        for column in range(7):
            controls.columnconfigure(column, weight=1 if column == 0 else 0)

        content = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left_panel = ttk.Frame(content)
        right_panel = ttk.Frame(content, width=320)
        content.add(left_panel, weight=4)
        content.add(right_panel, weight=1)

        self.display = Display(left_panel)
        self.display.set_click_callback(self.show_packet_details)

        self.filters = Filters(right_panel)
        self.filters.set_apply_callback(self.apply_filters)

        self.stop_button.state(["disabled"])

    def start_capture(self) -> None:
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showwarning("Interface Required", "Select a network interface before starting capture.")
            return

        if self.capture.is_running:
            return

        self._clear_data(stop_capture=False)

        try:
            self.capture.start(interface)
        except Exception as exc:
            self._set_status("Live capture failed to start.")
            messagebox.showerror(
                "Unable to Start Capture",
                (
                    f"Could not start live capture on '{interface}'.\n\n"
                    f"{exc}\n\n"
                    "Live packet capture may require elevated permissions on your system. "
                    "You can still use 'Load PCAP' for offline analysis."
                ),
            )
            return

        self.start_button.state(["disabled"])
        self.stop_button.state(["!disabled"])
        self.display.show_details("Capture running. Select a packet to inspect its parsed headers and payload.")
        self.filters.show_statistics(self.all_summaries, self.visible_summaries)
        self._set_status(f"Capturing packets on {interface}...")

    def stop_capture(self) -> None:
        if not self.capture.is_running:
            return

        packet_count = self.capture.stop()
        self.start_button.state(["!disabled"])
        self.stop_button.state(["disabled"])
        self._set_status(f"Capture stopped. {packet_count} packet(s) available for analysis.")

    def load_capture_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Open Packet Capture",
            filetypes=(
                ("Packet Captures", "*.pcap *.pcapng"),
                ("All Files", "*.*"),
            ),
        )
        if not filename:
            return

        if self.capture.is_running:
            self.stop_capture()

        try:
            packets = self.capture.load(filename)
        except Exception as exc:
            messagebox.showerror("Load Failed", f"Could not load the selected capture file.\n\n{exc}")
            return

        self.all_summaries = [
            build_packet_summary(packet, index + 1)
            for index, packet in enumerate(packets)
        ]
        self.apply_filters()
        self.display.show_details("Capture file loaded. Select a packet to inspect its parsed headers and payload.")
        self._set_status(f"Loaded {len(self.all_summaries)} packet(s) from {Path(filename).name}.")

    def save_capture_file(self) -> None:
        packets = self.capture.get_packets()
        if not packets:
            messagebox.showinfo("Nothing to Save", "There are no packets to save yet.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Packet Capture",
            defaultextension=".pcap",
            filetypes=(
                ("PCAP Files", "*.pcap"),
                ("All Files", "*.*"),
            ),
        )
        if not filename:
            return

        try:
            self.capture.save(filename)
        except Exception as exc:
            messagebox.showerror("Save Failed", f"Could not save the capture file.\n\n{exc}")
            return

        self._set_status(f"Saved {len(packets)} packet(s) to {Path(filename).name}.")

    def clear_capture(self) -> None:
        self._clear_data(stop_capture=True)
        self._set_status("Capture buffer cleared.")

    def apply_filters(self) -> None:
        criteria = self.filters.get_criteria()
        self.visible_summaries = [
            summary for summary in self.all_summaries if packet_matches(summary, criteria)
        ]

        self.display.replace_packets(self.visible_summaries)
        self.filters.show_statistics(self.all_summaries, self.visible_summaries)

        if self.visible_summaries:
            self._set_status(
                f"Showing {len(self.visible_summaries)} of {len(self.all_summaries)} packet(s)."
            )
        else:
            self._set_status(
                f"No packets match the current filters. Total packets loaded: {len(self.all_summaries)}."
            )

    def show_packet_details(self, packet_number: int) -> None:
        packet = self.capture.get_packet(packet_number)
        if packet is None or not (1 <= packet_number <= len(self.all_summaries)):
            return

        summary = self.all_summaries[packet_number - 1]
        self.display.show_details(format_packet_details(packet, summary))

    def _refresh_interfaces(self, select_first: bool = False) -> None:
        interfaces = self.capture.list_interfaces()
        self.interface_combo["values"] = interfaces

        if not interfaces:
            self.interface_var.set("")
            self._set_status("No interfaces were detected. You can still load a PCAP file.")
            return

        if select_first or self.interface_var.get() not in interfaces:
            self.interface_var.set(interfaces[0])

    def _queue_captured_packet(self, packet: object, packet_number: int) -> None:
        summary = build_packet_summary(packet, packet_number)
        self.packet_queue.put((packet, summary))

    def _process_packet_queue(self) -> None:
        processed_packets = 0
        criteria = self.filters.get_criteria()

        while True:
            try:
                _packet, summary = self.packet_queue.get_nowait()
            except Empty:
                break

            self.all_summaries.append(summary)
            if packet_matches(summary, criteria):
                self.visible_summaries.append(summary)
                self.display.add_packet(summary)
            processed_packets += 1

        if processed_packets:
            self.filters.show_statistics(self.all_summaries, self.visible_summaries)
            self._set_status(
                (
                    f"Capturing packets on {self.interface_var.get()}... "
                    f"Total: {len(self.all_summaries)} | Displayed: {len(self.visible_summaries)}"
                )
            )

        self.root.after(100, self._process_packet_queue)

    def _clear_data(self, stop_capture: bool) -> None:
        if stop_capture and self.capture.is_running:
            self.stop_capture()

        self.capture.clear()

        self.all_summaries.clear()
        self.visible_summaries.clear()
        self.display.clear_packets()
        self.display.show_details("Select a packet to inspect its parsed headers and payload.")
        self.filters.show_statistics(self.all_summaries, self.visible_summaries)

    def _render_empty_state(self) -> None:
        self.display.clear_packets()
        self.display.show_details("Select a packet to inspect its parsed headers and payload.")
        self.filters.show_statistics(self.all_summaries, self.visible_summaries)

    def _set_status(self, message: str) -> None:
        self.status_var.set(message)

    def _on_close(self) -> None:
        if self.capture.is_running:
            self.capture.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    PacketSnifferApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
