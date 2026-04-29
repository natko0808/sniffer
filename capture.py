'''
@ASSESSME.USERID: YOUR_GROUP_NAME
@ASSESSME.AUTHOR: Your Name - yourRIT, Teammate Name - teammateRIT
@ASSESSME.DESCRIPTION: Problem Solving 9
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

from __future__ import annotations

import threading
from typing import Callable, Optional

import bootstrap  # noqa: F401
from scapy.all import AsyncSniffer, get_if_list, rdpcap, wrpcap


PacketCallback = Callable[[object, int], None]


class Capture:
    """Manage live sniffing plus offline packet buffers for the GUI."""

    def __init__(self, callback: PacketCallback):
        self.callback = callback
        self._lock = threading.Lock()
        self._packets: list[object] = []
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def list_interfaces(self) -> list[str]:
        return sorted(dict.fromkeys(get_if_list()))

    def start(self, interface: str) -> None:
        if self._running:
            raise RuntimeError("Packet capture is already running.")

        self.clear()
        self._sniffer = AsyncSniffer(iface=interface, prn=self._handle_packet, store=False)
        self._running = True

        try:
            self._sniffer.start()
        except Exception:
            self._sniffer = None
            self._running = False
            raise

    def stop(self) -> int:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
        self._running = False
        return self.packet_count

    def clear(self) -> None:
        with self._lock:
            self._packets = []

    def load(self, filename: str) -> list[object]:
        packets = list(rdpcap(filename))
        with self._lock:
            self._packets = packets
        self._running = False
        self._sniffer = None
        return list(self._packets)

    def save(self, filename: str) -> None:
        packets = self.get_packets()
        wrpcap(filename, packets)

    def get_packets(self) -> list[object]:
        with self._lock:
            return list(self._packets)

    def get_packet(self, packet_number: int) -> Optional[object]:
        with self._lock:
            index = packet_number - 1
            if 0 <= index < len(self._packets):
                return self._packets[index]
        return None

    @property
    def packet_count(self) -> int:
        with self._lock:
            return len(self._packets)

    def _handle_packet(self, packet: object) -> None:
        with self._lock:
            self._packets.append(packet)
            packet_number = len(self._packets)

        self.callback(packet, packet_number)
