#!/usr/bin/env python3
from pathlib import Path

class Config:
    OUTPUT_DIR = Path(".")
    MAX_TIMEOUT = 10
    VERIFY_CERTIFICATE = False
    CIPHERSUITES = []
    REVEALING_HEADERS = []
    REVEALING_HEADERS_LOWER = []
    
    USER_AGENT = "Mozilla/5.0"