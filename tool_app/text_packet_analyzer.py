#!/usr/bin/env python3
import re
import logging
from typing import Tuple, List

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(fmt)
    logger.addHandler(ch)

def extract_urls(text: str) -> List[str]:
    pattern = r'(https?://[^\s]+)'
    return re.findall(pattern, text)

def count_words(text: str) -> int:
    words = re.findall(r'\w+', text)
    return len(words)

def find_emails(text: str) -> List[str]:
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(pattern, text)

def analyze_text_packet(packet_text: str) -> Tuple[List[str], int, List[str]]:
    urls = extract_urls(packet_text)
    word_count = count_words(packet_text)
    emails = find_emails(packet_text)
    return urls, word_count, emails
