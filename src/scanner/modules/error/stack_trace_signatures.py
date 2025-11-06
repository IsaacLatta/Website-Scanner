from __future__ import annotations

import re
from typing import List

from scanner.modules.error.signature import StackTraceSignature

JS_HEADER_PATTERNS = [
    re.compile(r"^Error: .+"),
    re.compile(r"^[A-Za-z]+Error: .+"),
]

JS_FRAME_PATTERNS = [
    re.compile(r"^\s+at .+\(.+:\d+:\d+\)$"),
    re.compile(r"^\s+at .+:\d+:\d+$"),
]

js_signature = StackTraceSignature(
    language="javascript",
    display_name="JavaScript / Node.js",
    header_patterns=JS_HEADER_PATTERNS,
    frame_patterns=JS_FRAME_PATTERNS,
)

PY_HEADER_PATTERNS = [
    re.compile(r"^Traceback \(most recent call last\):"),
    re.compile(r'^  File ".*", line \d+'),
    re.compile(r"^.+\.py:\d+: RuntimeWarning: .+"),
]

PY_FRAME_PATTERNS = [
    re.compile(r'^  File ".*", line \d+.*'),
    re.compile(r"^[A-Za-z_][A-Za-z0-9_]*Error: .+"),
    re.compile(r"^RuntimeWarning: .+"),
]

python_signature = StackTraceSignature(
    language="python",
    display_name="Python",
    header_patterns=PY_HEADER_PATTERNS,
    frame_patterns=PY_FRAME_PATTERNS,
)

JAVA_HEADER_PATTERNS = [
    re.compile(r'^Exception in thread ".*" .+'),
    re.compile(r'^[a-zA-Z0-9_.]+(?:Exception|Error): .+'),
]

JAVA_FRAME_PATTERNS = [
    re.compile(r'^\s*at [\w.$]+\(.*\.java:\d+\)$'),
]

java_signature = StackTraceSignature(
    language="java",
    display_name="Java",
    header_patterns=JAVA_HEADER_PATTERNS,
    frame_patterns=JAVA_FRAME_PATTERNS,
)

GO_HEADER_PATTERNS = [
    re.compile(r"^panic: .+"),
    re.compile(r"^fatal error: .+"),
]

GO_FRAME_PATTERNS = [
    re.compile(r"^goroutine \d+ \[[^\]]+\]:"),
    re.compile(r"^\s*[A-Za-z0-9_.]+\([^)]*\)$"),
    re.compile(r"^\s+/.+\.go:\d+.*$"),
]

go_signature = StackTraceSignature(
    language="go",
    display_name="Go",
    header_patterns=GO_HEADER_PATTERNS,
    frame_patterns=GO_FRAME_PATTERNS,
)

RUBY_HEADER_PATTERNS = [
    re.compile(r"^[^:\n]+\.rb:\d+:in `[^`]+': .+ \(.+\)$"),
]

RUBY_FRAME_PATTERNS = [
    re.compile(r"^\s*from [^:\n]+\.rb:\d+:in `[^`]+'$"),
]

ruby_signature = StackTraceSignature(
    language="ruby",
    display_name="Ruby",
    header_patterns=RUBY_HEADER_PATTERNS,
    frame_patterns=RUBY_FRAME_PATTERNS,
)

PHP_HEADER_PATTERNS = [
    re.compile(r"^PHP Fatal error:\s+Uncaught .+"),
    re.compile(
        r"^Uncaught [A-Za-z_\\][A-Za-z0-9_\\]*: .+ in .+\.php:\d+.*Stack trace:"
    ),
]

PHP_FRAME_PATTERNS = [
    re.compile(r"Stack trace:"),
    re.compile(r"^#\d+\s+.+"),
]

php_signature = StackTraceSignature(
    language="php",
    display_name="PHP",
    header_patterns=PHP_HEADER_PATTERNS,
    frame_patterns=PHP_FRAME_PATTERNS,
)

CS_HEADER_PATTERNS = [
    re.compile(
        r"^\s*Unhandled exception\.\s+System\.[A-Za-z0-9]+Exception: .+"
    ),
    re.compile(
        r"^\s*System\.[A-Za-z0-9]+Exception: .+"
    ),
]

CS_FRAME_PATTERNS = [
    re.compile(r"^\s*at .+"),
]

csharp_signature = StackTraceSignature(
    language="csharp",
    display_name="C# / .NET",
    header_patterns=CS_HEADER_PATTERNS,
    frame_patterns=CS_FRAME_PATTERNS,
)

STACKTRACE_SIGNATURES: List[StackTraceSignature] = [
    js_signature,
    python_signature,
    java_signature,
    go_signature,
    ruby_signature,
    php_signature,
    csharp_signature,
]
