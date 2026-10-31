"""Rich ANSI colored console logger and execution monitor — zero external dependencies."""
from __future__ import annotations

import sys
import datetime

# Terminal ANSI styling codes
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Standard & bright foreground colors
CYAN = "\033[36m"
BRIGHT_CYAN = "\033[96;1m"
GREEN = "\033[32m"
BRIGHT_GREEN = "\033[92;1m"
YELLOW = "\033[33m"
BRIGHT_YELLOW = "\033[93;1m"
RED = "\033[31m"
BRIGHT_RED = "\033[91;1m"
BLUE = "\033[34m"
BRIGHT_BLUE = "\033[94;1m"
MAGENTA = "\033[35m"
BRIGHT_MAGENTA = "\033[95;1m"

# Background badges
BG_RED = "\033[41;1;37m"
BG_YELLOW = "\033[43;1;30m"
BG_BLUE = "\033[44;1;37m"
BG_CYAN = "\033[46;1;30m"
BG_GREEN = "\033[42;1;30m"

COLORS = {
    "cyan": BRIGHT_CYAN,
    "green": BRIGHT_GREEN,
    "yellow": BRIGHT_YELLOW,
    "red": BRIGHT_RED,
    "blue": BRIGHT_BLUE,
    "magenta": BRIGHT_MAGENTA,
    "reset": RESET,
}

def _emit(prefix: str, color_code: str, msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"{color_code}[{prefix}]{RESET} {DIM}{ts}{RESET} {msg}\n")
    sys.stdout.flush()

def info(msg: str) -> None:
    """Informational message with bright cyan prefix."""
    _emit("*", BRIGHT_CYAN, msg)

def debug(msg: str) -> None:
    """Debug trace message (suppressed unless RECONX_DEBUG=1)."""
    import os
    if os.environ.get("RECONX_DEBUG") == "1":
        _emit(".", DIM, msg)

def ok(msg: str) -> None:
    """Success message with bright green prefix."""
    _emit("+", BRIGHT_GREEN, msg)

def warn(msg: str) -> None:
    """Warning or alert message with bright yellow prefix."""
    _emit("!", BRIGHT_YELLOW, msg)

def error(msg: str) -> None:
    """Error message with bright red prefix."""
    _emit("-", BRIGHT_RED, msg)

def step(tag: str, msg: str) -> None:
    """Active multi-threaded step indicator with bright magenta tag."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    sys.stdout.write(f"{BRIGHT_MAGENTA}[~]{RESET} {DIM}{ts}{RESET} {BOLD}[{tag}]{RESET} {msg}\n")
    sys.stdout.flush()

def banner(target: str, mode: str, concurrency: int = 8, proxy: str = "") -> None:
    """Print high-visibility execution banner with target metadata and concurrency stats."""
    proxy_str = proxy if proxy else "Direct connection (No proxy)"
    border = f"{BRIGHT_CYAN}{'═' * 76}{RESET}"
    sys.stdout.write(f"\n{border}\n")
    sys.stdout.write(f"  {BOLD}{BRIGHT_CYAN}ReconX v0.3.3{RESET} — {BOLD}Red-Team Attack Surface & Intelligence Engine{RESET}\n")
    sys.stdout.write(f"{border}\n")
    sys.stdout.write(f"  {BOLD}• Target Host{RESET}    : {BRIGHT_GREEN}{target}{RESET}\n")
    sys.stdout.write(f"  {BOLD}• Recon Mode{RESET}     : {BRIGHT_CYAN}{mode.upper()}{RESET}\n")
    sys.stdout.write(f"  {BOLD}• Concurrency{RESET}    : {BRIGHT_YELLOW}{concurrency} parallel async worker threads{RESET}\n")
    sys.stdout.write(f"  {BOLD}• Routing Proxy{RESET}  : {DIM}{proxy_str}{RESET}\n")
    sys.stdout.write(f"{border}\n\n")
    sys.stdout.flush()
