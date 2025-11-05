from dataclasses import dataclass
from typing import List

@dataclass
class Signature:
    display_name: str
    category: str
    aliases: List[str]