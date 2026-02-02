"""
Utility Functions Module

Common utilities for file handling, target parsing, output formatting, and logging.
Uses native ANSI escape codes for colors (works on Linux/Mac/Windows 10+).
No external dependencies required.
"""

import os
import sys
import logging
import ipaddress
from pathlib import Path
from typing import List, Set, Tuple, Optional, Iterator
from datetime import datetime


# =============================================================================
# Native ANSI Color Support (no colorama needed)
# =============================================================================

def _supports_color() -> bool:
    """Check if terminal supports colors."""
    # Always support color on Linux/Mac
    if sys.platform != "win32":
        return True
    # Windows 10+ supports ANSI
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        return True
    except:
        return os.environ.get("TERM") is not None


# Use native ANSI codes - works on Linux/Mac without any dependencies
_USE_COLOR = _supports_color()


class Fore:
    """ANSI foreground colors."""
    if _USE_COLOR:
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"
        RESET = "\033[0m"
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""


class Style:
    """ANSI text styles."""
    if _USE_COLOR:
        BRIGHT = "\033[1m"
        DIM = "\033[2m"
        NORMAL = "\033[22m"
        RESET_ALL = "\033[0m"
    else:
        BRIGHT = DIM = NORMAL = RESET_ALL = ""


# For compatibility
HAS_COLORAMA = True  # We always have color support now via native ANSI


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(
    log_level: str = "INFO",
    log_file: Optional[str] = None,
    quiet: bool = False
) -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger("auto_nmap")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    logger.handlers.clear()

    if not quiet:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        console_format = logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S"
        )
        console_handler.setFormatter(console_format)
        logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger


# =============================================================================
# Color Output
# =============================================================================

class Colors:
    """Terminal colors for output."""
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    RESET = Style.RESET_ALL
    BOLD = Style.BRIGHT
    DIM = Style.DIM


def print_banner():
    """Print the application banner."""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   {Colors.WHITE}█████╗ ██╗   ██╗████████╗ ██████╗     ███╗   ██╗███╗   ███╗ █████╗ ██████╗{Colors.CYAN} ║
║  {Colors.WHITE}██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ████╗  ██║████╗ ████║██╔══██╗██╔══██╗{Colors.CYAN}║
║  {Colors.WHITE}███████║██║   ██║   ██║   ██║   ██║    ██╔██╗ ██║██╔████╔██║███████║██████╔╝{Colors.CYAN}║
║  {Colors.WHITE}██╔══██║██║   ██║   ██║   ██║   ██║    ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝{Colors.CYAN} ║
║  {Colors.WHITE}██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║{Colors.CYAN}     ║
║  {Colors.WHITE}╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝{Colors.CYAN}     ║
║                                                                       ║
║                    {Colors.GREEN}Automated Network Scanner v3.0{Colors.CYAN}                    ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)


def print_status(message: str, status: str = "info"):
    """Print a status message with color coding."""
    colors = {
        "info": Colors.BLUE,
        "success": Colors.GREEN,
        "warning": Colors.YELLOW,
        "error": Colors.RED,
        "debug": Colors.DIM,
    }
    symbols = {
        "info": "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error": "[-]",
        "debug": "[D]",
    }
    color = colors.get(status, Colors.WHITE)
    symbol = symbols.get(status, "[*]")
    print(f"{color}{symbol} {message}{Colors.RESET}")


def print_header(title: str):
    """Print a section header."""
    width = 60
    print(f"\n{Colors.CYAN}{'=' * width}")
    print(f"{title.center(width)}")
    print(f"{'=' * width}{Colors.RESET}\n")


# =============================================================================
# Target Parsing
# =============================================================================

def parse_targets(target_spec: str) -> List[str]:
    """
    Parse target specification into list of targets.
    
    Supports: IP, CIDR, range (1.1.1.1-50), hostname, file path
    """
    targets = []
    
    if not target_spec:
        return targets
    
    # Check if it's a file
    if os.path.isfile(target_spec):
        return read_file_lines(target_spec)
    
    # Handle @file syntax
    if target_spec.startswith("@") and os.path.isfile(target_spec[1:]):
        return read_file_lines(target_spec[1:])
    
    # Split by comma
    for spec in target_spec.split(","):
        spec = spec.strip()
        if not spec:
            continue
        
        # Check for range (e.g., 192.168.1.1-50)
        if "-" in spec and not "/" in spec:
            try:
                targets.extend(expand_ip_range(spec))
            except ValueError:
                targets.append(spec)  # Treat as hostname
        else:
            targets.append(spec)
    
    return targets


def expand_ip_range(range_spec: str) -> List[str]:
    """Expand IP range like 192.168.1.1-50 to list of IPs."""
    parts = range_spec.rsplit(".", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid range: {range_spec}")
    
    base = parts[0]
    range_part = parts[1]
    
    if "-" in range_part:
        start, end = range_part.split("-")
        start = int(start)
        end = int(end)
        return [f"{base}.{i}" for i in range(start, end + 1)]
    
    raise ValueError(f"Invalid range: {range_spec}")


def parse_ports(port_spec: str) -> List[int]:
    """Parse port specification into list of ports."""
    ports = []
    
    for spec in port_spec.split(","):
        spec = spec.strip()
        if "-" in spec:
            start, end = spec.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(spec))
    
    return sorted(set(ports))


# =============================================================================
# File Operations
# =============================================================================

def read_file_lines(filepath: str) -> List[str]:
    """Read non-empty lines from a file."""
    lines = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    except IOError as e:
        print_status(f"Error reading {filepath}: {e}", "error")
    return lines


def write_file_lines(filepath: str, lines: List[str]):
    """Write lines to a file."""
    try:
        with open(filepath, "w") as f:
            for line in lines:
                f.write(f"{line}\n")
    except IOError as e:
        print_status(f"Error writing {filepath}: {e}", "error")


def ensure_directories(base_dir: str):
    """Create necessary output directories."""
    dirs = [
        base_dir,
        f"{base_dir}/scans",
        f"{base_dir}/reports",
        f"{base_dir}/nse_scans",
        f"{base_dir}/open-ports",
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Get current timestamp for filenames."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# =============================================================================
# System Checks
# =============================================================================

def require_root():
    """Check if running as root, warn if not."""
    if os.geteuid() != 0:
        print_status("Warning: Not running as root. Some scan types may fail.", "warning")
        print_status("Run with: sudo python3 auto_nmap_v3.py ...", "info")


def check_nmap_installed() -> bool:
    """Check if nmap is installed."""
    import shutil
    return shutil.which("nmap") is not None


# =============================================================================
# Custom Exceptions
# =============================================================================

class NmapError(Exception):
    """Custom exception for nmap-related errors."""
    pass


class ScanError(NmapError):
    """Error during scanning."""
    pass


class ParseError(NmapError):
    """Error parsing scan results."""
    pass
