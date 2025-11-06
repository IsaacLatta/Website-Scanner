from dataclasses import dataclass
from typing import List, Pattern

@dataclass
class Signature:
    display_name: str
    category: str
    aliases: List[str]

@dataclass(frozen=True)
class StackTraceSignature:
    language: str
    display_name: str
    header_patterns: List[Pattern[str]]
    frame_patterns: List[Pattern[str]]
