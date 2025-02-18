#!/usr/bin/env python3
import re
import logging
from typing import Callable, List, Tuple, Optional
from scapy.all import sniff, Packet, Raw

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(fmt)
    logger.addHandler(ch)

def is_hex_string(s: str) -> bool:
    s_clean = s.strip().replace(" ", "").replace("\n", "")
    return all(c in "0123456789abcdefABCDEF" for c in s_clean)

def hex_to_ascii(s: str) -> str:
    s_clean = s.strip().replace(" ", "").replace("\n", "")
    try:
        return bytes.fromhex(s_clean).decode("utf-8", errors="replace")
    except Exception:
        return ""

def classify_packet(packet_text: str) -> Tuple[str, List[str]]:
    details: List[str] = []
    classification: str = "Unknown"
    if re.search(r"HTTP/1\.[01]", packet_text, re.IGNORECASE) or \
       re.search(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s", packet_text, re.IGNORECASE):
        classification = "HTTP Packet"
        details.append("HTTP protocol indicators detected.")
    elif "DNS" in packet_text.upper():
        classification = "DNS Packet"
        details.append("DNS protocol indicators detected.")
    elif re.search(r"(?i)(src_port|dst_port)\s*:\s*\d+", packet_text):
        classification = "TCP/UDP Packet"
        details.append("TCP/UDP port information detected.")
    elif re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", packet_text):
        classification = "IP Packet"
        details.append("IP address pattern detected.")
    else:
        details.append("No specific protocol pattern detected.")
    details.append(f"Packet length: {len(packet_text)} characters.")
    return classification, details

def dissect_packet(raw_packet: Packet) -> str:
    layers: List[str] = []
    pkt: Optional[Packet] = raw_packet
    while pkt:
        layers.append(pkt.__class__.__name__)
        pkt = pkt.payload
        if pkt is None or pkt == b"" or (hasattr(pkt, "payload") and pkt.payload == pkt):
            break
    return " -> ".join(layers)

def live_sniff(callback: Callable[[str], None],
               filter_expr: Optional[str] = None,
               count: int = 0,
               timeout: Optional[int] = None) -> None:
    def process_packet(packet: Packet) -> None:
        try:
            summary = dissect_packet(packet)
            raw_payload = ""
            if Raw in packet:
                try:
                    raw_payload = packet[Raw].load.decode("utf-8", errors="replace")
                except Exception as e:
                    logger.exception(f"Error decoding raw payload: {e}")
            result = f"Packet: {summary}\nRaw Data: {raw_payload}\n{'-' * 40}\n"
            callback(result)
        except Exception as e:
            logger.exception(f"Exception processing packet: {e}")
    logger.info(f"Starting live sniffing with filter='{filter_expr}', count={count}, timeout={timeout}")
    try:
        sniff(filter=filter_expr, prn=process_packet, count=count, timeout=timeout)
    except Exception as e:
        logger.exception(f"Exception during live sniffing: {e}")
