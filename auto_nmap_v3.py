#!/usr/bin/env python3
"""
Auto Nmap v3.0 - Automated Network Scanning & Enumeration

A comprehensive Python 3 network scanning tool featuring:
- Multithreaded NSE script execution for faster scanning
- Automatic NSE script selection based on discovered open ports
- 200+ pre-configured NSE scripts across 50+ services
- Intelligent speed controls for modern networks
- Multiple report formats (TXT, JSON, CSV, HTML) with remediation guidance

REQUIREMENTS:
    - Python 3.8+
    - nmap (command-line tool)
    - python-nmap library
    - Root/sudo privileges (for SYN scans)

INSTALLATION:
    pip3 install python-nmap prettytable colorama

QUICK START:
    # Full scan with automatic speed detection
    sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full

    # Fast scan for modern networks
    sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --speed fast

    # Safe scan with minimal network impact
    sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --speed slow

PROJECT FILES:
    auto_nmap_v3.py  - Main entry point (this file) - CLI and workflow orchestration
    scanner.py       - Core scanning engine using python-nmap library
    executor.py      - Multithreaded NSE script execution with ThreadPoolExecutor
    nse_configs.py   - Database of 200+ NSE scripts mapped to ports/services
    remediations.py  - 45+ remediation recommendations with severity ratings
    reporter.py      - Report generation (TXT, JSON, CSV, HTML) with findings analysis
    utils.py         - Utility functions: logging, parsing, file I/O, colors

Author: Auto Nmap Project
License: MIT
Version: 3.0.0
"""

import argparse
import sys
import os
import subprocess
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
from textwrap import dedent

# Version info
__version__ = "3.0.0"
__author__ = "Auto Nmap Project"


# =============================================================================
# Dependency Check and Installation
# =============================================================================

def check_dependencies() -> Dict[str, bool]:
    """Check if required dependencies are installed."""
    # Only python-nmap is truly required
    # prettytable and colorama are optional - we have built-in fallbacks
    deps = {
        "python-nmap": False,
    }

    try:
        import nmap
        deps["python-nmap"] = True
    except ImportError:
        pass

    return deps


def is_externally_managed() -> bool:
    """Check if Python environment is externally managed (PEP 668)."""
    # Check for EXTERNALLY-MANAGED marker file
    import sysconfig
    stdlib = sysconfig.get_path("stdlib")
    marker = Path(stdlib).parent / "EXTERNALLY-MANAGED"
    if marker.exists():
        return True
    # Also check common Kali/Debian locations
    for path in ["/usr/lib/python3.11/EXTERNALLY-MANAGED", 
                 "/usr/lib/python3.12/EXTERNALLY-MANAGED",
                 "/usr/lib/python3.13/EXTERNALLY-MANAGED"]:
        if os.path.exists(path):
            return True
    return False


def is_kali_or_debian() -> bool:
    """Check if running on Kali Linux or Debian-based system."""
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                content = f.read().lower()
                return any(x in content for x in ["kali", "debian", "ubuntu"])
    except:
        pass
    return False


def install_dependencies(deps: Dict[str, bool]) -> bool:
    """
    Install missing dependencies with smart detection for Kali/Debian.
    
    Automatically handles PEP 668 'externally-managed-environment' error.
    Only python-nmap is required - prettytable and colorama are optional.
    """
    missing = [name for name, installed in deps.items() if not installed]

    if not missing:
        return True

    # Only python-nmap is required - others have built-in fallbacks
    packages = ["python-nmap"]
    apt_packages = ["python3-nmap"]
    
    print("\n" + "=" * 60)
    print("MISSING DEPENDENCIES DETECTED")
    print("=" * 60)
    print(f"\nThe following Python packages are required:")
    for dep in missing:
        print(f"  - {dep}")
    
    # Detect system type
    is_managed = is_externally_managed()
    is_debian = is_kali_or_debian()
    
    if is_managed or is_debian:
        print("\n[!] Detected Kali/Debian/Ubuntu with PEP 668 protection")
        print("\nInstallation Options:")
        print("  1. Use apt install (RECOMMENDED)")
        print("  2. Create virtual environment (auto-setup)")
        print("  3. Use pip with --break-system-packages")
        print("  4. Show manual options")
        print("  5. Exit")
        
        print("\nSelect option [1-5]: ", end="")
        sys.stdout.flush()
        
        try:
            response = input().strip() or "1"
        except EOFError:
            response = "4"
        
        if response == "1":
            # APT install - best for Kali
            print("\nInstalling via apt (may require sudo password)...")
            try:
                cmd = ["sudo", "apt", "install", "-y"] + apt_packages
                print(f"Running: {' '.join(cmd)}")
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print("\n" + "=" * 60)
                    print("SUCCESS! Dependencies installed via apt.")
                    print("Please restart the script now.")
                    print("=" * 60 + "\n")
                    return True
                else:
                    print("\napt install failed. Try option 2 or 3.")
                    return False
            except Exception as e:
                print(f"\nError: {e}")
                print("Try running manually: sudo apt install " + " ".join(apt_packages))
                return False
        
        elif response == "2":
            # Create virtual environment automatically
            print("\nSetting up virtual environment...")
            script_dir = Path(__file__).parent.absolute()
            venv_dir = script_dir / "venv"
            
            try:
                # Check for python3-venv
                import venv
                
                # Create venv
                print(f"[*] Creating virtual environment in {venv_dir}...")
                if venv_dir.exists():
                    import shutil
                    shutil.rmtree(venv_dir)
                
                venv.create(venv_dir, with_pip=True)
                print("[+] Virtual environment created!")
                
                # Install python-nmap in venv
                print("[*] Installing python-nmap...")
                venv_pip = venv_dir / "bin" / "pip"
                result = subprocess.run([str(venv_pip), "install", "python-nmap"])
                
                if result.returncode == 0:
                    print("\n" + "=" * 60)
                    print("SUCCESS! Virtual environment ready.")
                    print("=" * 60)
                    print("\nTo use Auto Nmap, run:")
                    print(f"\n  sudo {venv_dir}/bin/python {script_dir}/auto_nmap_v3.py -t <target> --full")
                    print("\nOr use the launcher script:")
                    print(f"\n  sudo bash {script_dir}/run.sh -t <target> --full")
                    print()
                    return True
                else:
                    print("\nFailed to install python-nmap in venv.")
                    return False
                    
            except Exception as e:
                print(f"\nError creating virtual environment: {e}")
                print("\nTry running setup.sh instead:")
                print(f"  bash {script_dir}/setup.sh")
                return False
                
        elif response == "3":
            # pip with --break-system-packages
            print("\nInstalling via pip with --break-system-packages...")
            try:
                cmd = [sys.executable, "-m", "pip", "install", "--break-system-packages"] + packages
                print(f"Running: {' '.join(cmd)}")
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print("\n" + "=" * 60)
                    print("SUCCESS! Dependencies installed.")
                    print("Please restart the script now.")
                    print("=" * 60 + "\n")
                    return True
                else:
                    print("\nInstallation failed. Try with sudo:")
                    print(f"  sudo pip3 install --break-system-packages {' '.join(packages)}")
                    return False
            except Exception as e:
                print(f"\nError: {e}")
                return False
                
        elif response == "4":
            script_dir = Path(__file__).parent.absolute()
            print("\n" + "=" * 60)
            print("MANUAL INSTALLATION OPTIONS")
            print("=" * 60)
            print("\n[Option A] APT Install (Recommended for Kali):")
            print(f"  sudo apt install {' '.join(apt_packages)}")
            print("\n[Option B] Run setup script:")
            print(f"  bash {script_dir}/setup.sh")
            print(f"  sudo bash {script_dir}/run.sh -t <target> --full")
            print("\n[Option C] Pip with --break-system-packages:")
            print(f"  pip3 install --break-system-packages {' '.join(packages)}")
            print("\n[Option D] Manual Virtual Environment:")
            print(f"  cd {script_dir}")
            print("  python3 -m venv venv")
            print("  source venv/bin/activate")
            print(f"  pip install {' '.join(packages)}")
            print("  sudo ./venv/bin/python auto_nmap_v3.py -t <target> --full")
            print()
            return False
        else:
            print("\nExiting. Install dependencies manually and restart.")
            return False
    
    else:
        # Standard system - try normal pip
        print("\nInstallation Options:")
        print("  1. Install automatically with pip")
        print("  2. Show manual install command")
        print("  3. Exit")
        
        print("\nSelect option [1-3]: ", end="")
        sys.stdout.flush()
        
        try:
            response = input().strip() or "1"
        except EOFError:
            response = "2"
        
        if response == "1":
            print("\nInstalling dependencies...")
            try:
                cmd = [sys.executable, "-m", "pip", "install"] + packages
                result = subprocess.run(cmd)
                if result.returncode == 0:
                    print("\n" + "=" * 60)
                    print("SUCCESS! Dependencies installed.")
                    print("Please restart the script now.")
                    print("=" * 60 + "\n")
                    return True
                else:
                    print("\nInstallation failed.")
                    print(f"Try manually: pip3 install {' '.join(packages)}")
                    return False
            except Exception as e:
                print(f"\nError: {e}")
                return False
        elif response == "2":
            print(f"\nRun: pip3 install {' '.join(packages)}")
            return False
        else:
            return False


# Check dependencies before importing
_deps = check_dependencies()
if not all(_deps.values()):
    if not install_dependencies(_deps):
        sys.exit(1)
    sys.exit(0)

# Now import our modules (dependencies are installed)
from utils import (
    setup_logging,
    print_banner,
    print_status,
    print_header,
    parse_targets,
    parse_ports,
    ensure_directories,
    read_file_lines,
    write_file_lines,
    require_root,
    Colors,
    NmapError,
)
from scanner import (
    NmapScanner,
    ScanOptions,
    ScanResult,
)
from executor import (
    NSEExecutor,
    run_nse_scans_parallel,
)
from reporter import (
    ReportGenerator,
    generate_report,
)
from nse_configs import (
    COMMON_TCP_PORTS,
    COMMON_UDP_PORTS,
    get_all_tcp_ports,
    get_all_udp_ports,
    ALL_SERVICE_CONFIGS,
    ScanCategory,
)


# =============================================================================
# Speed Presets
# =============================================================================

SPEED_PRESETS = {
    "paranoid": {
        "description": "Extremely slow, IDS evasion",
        "min_hostgroup": 1,
        "min_rate": 10,
        "max_rate": 50,
        "timing_template": 0,
        "max_retries": 10,
        "host_timeout": "60m",
        "use_case": "Avoiding IDS/IPS detection",
    },
    "sneaky": {
        "description": "Very slow, reduced detection",
        "min_hostgroup": 1,
        "min_rate": 50,
        "max_rate": 100,
        "timing_template": 1,
        "max_retries": 6,
        "host_timeout": "45m",
        "use_case": "Stealth security assessments",
    },
    "slow": {
        "description": "Safe for fragile networks",
        "min_hostgroup": 2,
        "min_rate": 100,
        "max_rate": 300,
        "timing_template": 2,
        "max_retries": 4,
        "host_timeout": "30m",
        "use_case": "Legacy systems, IoT, embedded devices",
    },
    "normal": {
        "description": "Balanced speed and reliability (DEFAULT)",
        "min_hostgroup": 8,
        "min_rate": 300,
        "max_rate": 1000,
        "timing_template": 3,
        "max_retries": 3,
        "host_timeout": "20m",
        "use_case": "Most enterprise networks",
    },
    "fast": {
        "description": "Fast scanning for modern networks",
        "min_hostgroup": 16,
        "min_rate": 1000,
        "max_rate": 3000,
        "timing_template": 4,
        "max_retries": 2,
        "host_timeout": "15m",
        "use_case": "Modern LANs, cloud environments",
    },
    "aggressive": {
        "description": "Very fast, may miss some hosts",
        "min_hostgroup": 32,
        "min_rate": 3000,
        "max_rate": 5000,
        "timing_template": 4,
        "max_retries": 1,
        "host_timeout": "10m",
        "use_case": "CTFs, labs, local testing",
    },
    "insane": {
        "description": "Maximum speed, local networks only",
        "min_hostgroup": 64,
        "min_rate": 5000,
        "max_rate": 10000,
        "timing_template": 5,
        "max_retries": 1,
        "host_timeout": "5m",
        "use_case": "Localhost, isolated lab networks",
    },
}


# =============================================================================
# Rich Help Formatter
# =============================================================================

class RichHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter for better help display."""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=40, width=100)


# =============================================================================
# Argument Parser
# =============================================================================

def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser with detailed help."""

    # Build speed presets help text
    speed_help_lines = ["Available speed presets:\n"]
    for name, preset in SPEED_PRESETS.items():
        default_marker = " (DEFAULT)" if name == "normal" else ""
        speed_help_lines.append(f"  {name:12}{default_marker}")
        speed_help_lines.append(f"      {preset['description']}")
        speed_help_lines.append(f"      min-rate: {preset['min_rate']}, "
                               f"min-hostgroup: {preset['min_hostgroup']}")
        speed_help_lines.append(f"      Use case: {preset['use_case']}\n")
    speed_help = "\n".join(speed_help_lines)

    epilog = f"""
================================================================================
HOW IT WORKS
================================================================================

FULL SCAN WORKFLOW (--full):
  When you run a full scan, Auto Nmap executes 4 phases automatically:

  Phase 1: HOST DISCOVERY    - Ping sweep (-sn) to find alive hosts
  Phase 2: PORT SCANNING     - SYN scan (-sS) on alive hosts for open ports
  Phase 3: VERSION DETECTION - Service fingerprinting (-sV) on open ports
  Phase 4: NSE SCRIPTS       - Runs 200+ scripts based on discovered services

NSE SCRIPT CATEGORIES:
  safe       - Non-intrusive info gathering (banners, certs, headers)
  discovery  - Service and OS identification
  enum       - Resource enumeration (users, shares, databases)
  vuln       - Known vulnerabilities (Heartbleed, EternalBlue, Shellshock)
  auth       - Authentication issues (anonymous access, empty passwords)
  brute      - Password attacks (SSH, FTP, SMB, MySQL brute force)
  intrusive  - Aggressive tests (may crash or modify services)

OUTPUT FILES GENERATED:
  security_report_*.html  - Styled HTML with severity cards, expandable findings
  scan_report_*.txt       - Plain text summary with disclaimers
  scan_report_*.json      - Machine-readable for SIEM/automation
  findings_*.csv          - Security findings for ticketing systems
  hosts_ports_*.csv       - All discovered hosts and open ports
  summary_*.csv           - Summary metrics for reporting

================================================================================
SPEED PRESETS (--speed)
================================================================================

{speed_help}
RECOMMENDED FOR MODERN NETWORKS:
  - Local LAN (1Gbps+):     --speed fast or --speed aggressive
  - Corporate Network:      --speed normal or --speed fast
  - Cloud/AWS/Azure:        --speed fast
  - Remote/Internet:        --speed normal
  - Legacy/Fragile:         --speed slow

================================================================================
EXAMPLES
================================================================================

BASIC SCANS:
  # Full scan of a subnet (discovery + ports + NSE)
  sudo python3 {sys.argv[0]} -t 192.168.1.0/24 --full

  # Quick ping sweep to find alive hosts
  sudo python3 {sys.argv[0]} -t 10.0.0.0/24 --ping-sweep

  # Port scan specific hosts
  sudo python3 {sys.argv[0]} -t 192.168.1.1,192.168.1.2 --port-scan

SPEED CONTROL:
  # Fast scan for modern LAN
  sudo python3 {sys.argv[0]} -t 192.168.1.0/24 --full --speed fast

  # Slow scan for legacy/fragile networks
  sudo python3 {sys.argv[0]} -t 10.0.0.0/24 --full --speed slow

VULNERABILITY SCANNING:
  # Run only vulnerability-related NSE scripts
  sudo python3 {sys.argv[0]} -t 192.168.1.1 --port-scan --nse --vuln-only

  # Check for EternalBlue (MS17-010)
  sudo python3 {sys.argv[0]} -t 192.168.1.0/24 -p 445 --nse --vuln-only

NSE SCRIPTING:
  # Run NSE scripts on discovered services
  sudo python3 {sys.argv[0]} -t 192.168.1.1 --port-scan --nse

  # Include brute force scripts
  sudo python3 {sys.argv[0]} -t 192.168.1.1 --nse --brute --threads 10

  # Safe scripts only (non-disruptive)
  sudo python3 {sys.argv[0]} -t 192.168.1.1 --full --safe-only

SERVICE-SPECIFIC SCANS:
  # Web server scanning
  sudo python3 {sys.argv[0]} -t 192.168.1.1 -p 80,443,8080 --nse

  # SMB/Windows scanning
  sudo python3 {sys.argv[0]} -t 192.168.1.1 -p 139,445 --nse

  # Database scanning
  sudo python3 {sys.argv[0]} -t 192.168.1.1 -p 1433,3306,5432,27017 --nse

REAL-WORLD SCENARIOS:
  # Penetration test - initial recon
  sudo python3 {sys.argv[0]} -t 10.0.0.0/24 --ping-sweep --speed fast

  # Internal vulnerability assessment
  sudo python3 {sys.argv[0]} -t 192.168.1.0/24 --full --vuln-only --speed fast

  # CTF/HackTheBox machine scan
  sudo python3 {sys.argv[0]} -t 10.10.10.5 --full --speed aggressive --brute

  # Security audit with full documentation
  sudo python3 {sys.argv[0]} -t 192.168.1.0/24 --full -o ./audit --report-formats txt,json,csv,html

================================================================================
PROJECT FILES
================================================================================

  auto_nmap_v3.py   Main entry point - CLI and workflow orchestration
  scanner.py        Core scanning engine using python-nmap library
  executor.py       Multithreaded NSE script execution
  nse_configs.py    Database of 200+ NSE scripts mapped to ports/services
  remediations.py   45+ remediation recommendations with severity ratings
  reporter.py       Report generation (TXT, JSON, CSV, HTML)
  utils.py          Utility functions: logging, parsing, file I/O

================================================================================
SUPPORTED SERVICES (27+)
================================================================================

  FTP (21)          SSH (22)          Telnet (23)       SMTP (25,465,587)
  DNS (53)          HTTP (80,8080)    HTTPS (443,8443)  SMB (139,445)
  SNMP (161)        LDAP (389,636)    MS-SQL (1433)     MySQL (3306)
  PostgreSQL (5432) Oracle (1521)     RDP (3389)        VNC (5900-5902)
  Redis (6379)      MongoDB (27017)   Elasticsearch     Docker (2375,2376)
  Kubernetes        NFS (2049)        Memcached         CouchDB (5984)
  WinRM (5985)      Kerberos (88)     MQTT (1883,8883)

Run --list-services to see all configured scripts for each service.

================================================================================
"""

    parser = argparse.ArgumentParser(
        prog="auto_nmap_v3.py",
        description=dedent("""
        ╔═══════════════════════════════════════════════════════════════════════╗
        ║                        AUTO NMAP v3.0                                 ║
        ║              Automated Network Scanning & Enumeration                 ║
        ╚═══════════════════════════════════════════════════════════════════════╝

        A powerful Python 3 network scanner that automatically discovers hosts,
        scans ports, detects services, and runs appropriate NSE scripts based
        on what's found. Features multithreaded execution for fast scanning.
        """),
        epilog=epilog,
        formatter_class=RichHelpFormatter,
    )

    # Target Specification
    target_group = parser.add_argument_group("TARGET SPECIFICATION")
    target_group.add_argument(
        "-t", "--targets",
        metavar="TARGET",
        help="Target specification: IP, CIDR, range, hostname, or file path"
    )
    target_group.add_argument(
        "-iL", "--input-list",
        metavar="FILE",
        help="Read targets from file (one per line)"
    )
    target_group.add_argument(
        "--exclude",
        metavar="HOSTS",
        help="Exclude hosts/networks from scan"
    )
    target_group.add_argument(
        "--exclude-file",
        metavar="FILE",
        help="Exclude hosts listed in file"
    )

    # Scan Types
    scan_group = parser.add_argument_group("SCAN TYPES")
    scan_group.add_argument(
        "--full",
        action="store_true",
        help="Full scan: discovery + ports + version + NSE (RECOMMENDED)"
    )
    scan_group.add_argument(
        "--ping-sweep",
        action="store_true",
        help="Host discovery only (find alive hosts)"
    )
    scan_group.add_argument(
        "--port-scan",
        action="store_true",
        help="TCP/UDP port scan"
    )
    scan_group.add_argument(
        "--version-scan",
        action="store_true",
        help="Service version detection"
    )
    scan_group.add_argument(
        "--nse",
        action="store_true",
        help="Run NSE scripts based on open ports"
    )

    # Port Specification
    port_group = parser.add_argument_group("PORT SPECIFICATION")
    port_group.add_argument(
        "-p", "--ports",
        metavar="PORTS",
        help="TCP ports to scan (e.g., 22,80,443 or 1-1024)"
    )
    port_group.add_argument(
        "--udp-ports",
        metavar="PORTS",
        help="UDP ports to scan"
    )
    port_group.add_argument(
        "--all-tcp",
        action="store_true",
        help="Scan all 65535 TCP ports"
    )
    port_group.add_argument(
        "--top-ports",
        type=int,
        metavar="N",
        help="Scan top N most common ports"
    )

    # Speed Control
    speed_group = parser.add_argument_group("SPEED CONTROL")
    speed_group.add_argument(
        "--speed",
        choices=list(SPEED_PRESETS.keys()),
        default="normal",
        help="Speed preset (default: normal)"
    )
    speed_group.add_argument(
        "--min-hostgroup",
        type=int,
        metavar="N",
        help="Minimum hosts to scan in parallel"
    )
    speed_group.add_argument(
        "--min-rate",
        type=int,
        metavar="N",
        help="Minimum packets per second"
    )
    speed_group.add_argument(
        "--max-rate",
        type=int,
        metavar="N",
        help="Maximum packets per second"
    )
    speed_group.add_argument(
        "--max-retries",
        type=int,
        metavar="N",
        help="Maximum probe retries"
    )
    speed_group.add_argument(
        "--host-timeout",
        metavar="TIME",
        help="Give up on host after this time (e.g., 30m)"
    )

    # NSE Options
    nse_group = parser.add_argument_group("NSE SCRIPT OPTIONS")
    nse_group.add_argument(
        "--brute",
        action="store_true",
        help="Include brute force scripts"
    )
    nse_group.add_argument(
        "--intrusive",
        action="store_true",
        help="Include intrusive scripts"
    )
    nse_group.add_argument(
        "--vuln-only",
        action="store_true",
        help="Only run vulnerability scripts"
    )
    nse_group.add_argument(
        "--safe-only",
        action="store_true",
        help="Only run safe scripts"
    )
    nse_group.add_argument(
        "--threads",
        type=int,
        default=5,
        metavar="N",
        help="Parallel NSE threads (default: 5)"
    )
    nse_group.add_argument(
        "--scripts",
        metavar="SCRIPTS",
        help="Custom NSE scripts to run (comma-separated)"
    )

    # Output Options
    output_group = parser.add_argument_group("OUTPUT OPTIONS")
    output_group.add_argument(
        "-o", "--output-dir",
        metavar="DIR",
        default="output",
        help="Output directory (default: output)"
    )
    output_group.add_argument(
        "--report-formats",
        metavar="FORMATS",
        default="txt,json,csv,html",
        help="Report formats: txt,json,csv,html (default: all)"
    )
    output_group.add_argument(
        "--no-report",
        action="store_true",
        help="Skip report generation"
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    output_group.add_argument(
        "--debug",
        action="store_true",
        help="Debug mode (very verbose)"
    )

    # Utility Options
    util_group = parser.add_argument_group("UTILITY OPTIONS")
    util_group.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode with guided menu"
    )
    util_group.add_argument(
        "--list-services",
        action="store_true",
        help="List all configured services and scripts"
    )
    util_group.add_argument(
        "--list-scripts",
        metavar="PORT",
        type=int,
        help="List scripts for a specific port"
    )
    util_group.add_argument(
        "--list-speeds",
        action="store_true",
        help="Show detailed speed preset information"
    )
    util_group.add_argument(
        "--version",
        action="version",
        version=f"Auto Nmap v{__version__}"
    )

    return parser


# =============================================================================
# Utility Commands
# =============================================================================

def list_services():
    """List all configured services and their scripts."""
    print_header("CONFIGURED SERVICES")
    
    for config in ALL_SERVICE_CONFIGS:
        print(f"\n{Colors.BOLD}{config.name}{Colors.RESET}")
        print(f"  Ports: {', '.join(map(str, config.ports))}")
        print(f"  Protocol: {config.protocol}")
        print(f"  Scripts ({len(config.scripts)}):")
        for script in config.scripts[:5]:  # Show first 5
            categories = ", ".join(c.value for c in script.categories)
            print(f"    - {script.name} [{categories}]")
        if len(config.scripts) > 5:
            print(f"    ... and {len(config.scripts) - 5} more")


def list_scripts_for_port(port: int):
    """List scripts configured for a specific port."""
    from nse_configs import get_service_config_for_port
    
    config = get_service_config_for_port(port)
    if config:
        print_header(f"SCRIPTS FOR PORT {port} ({config.name})")
        for script in config.scripts:
            categories = ", ".join(c.value for c in script.categories)
            print(f"\n  {Colors.BOLD}{script.name}{Colors.RESET}")
            print(f"    {script.description}")
            print(f"    Categories: {categories}")
            if script.args:
                print(f"    Args: {script.args}")
    else:
        print(f"No scripts configured for port {port}")


def list_speed_presets():
    """Show detailed speed preset information."""
    print_header("SPEED PRESETS")
    
    for name, preset in SPEED_PRESETS.items():
        default = " (DEFAULT)" if name == "normal" else ""
        print(f"\n{Colors.BOLD}--speed {name}{default}{Colors.RESET}")
        print(f"  Description: {preset['description']}")
        print(f"  Use case:    {preset['use_case']}")
        print(f"  Settings:")
        print(f"    min-hostgroup: {preset['min_hostgroup']}")
        print(f"    min-rate:      {preset['min_rate']} packets/sec")
        print(f"    max-rate:      {preset['max_rate']} packets/sec")
        print(f"    timing:        -T{preset['timing_template']}")
        print(f"    max-retries:   {preset['max_retries']}")
        print(f"    host-timeout:  {preset['host_timeout']}")


# =============================================================================
# Interactive Mode
# =============================================================================

def interactive_mode() -> Dict[str, Any]:
    """Run interactive mode to gather scan options."""
    print_banner()
    print_header("INTERACTIVE MODE")
    
    options = {}
    
    # Get targets
    print("\nEnter target(s) to scan:")
    print("  Examples: 192.168.1.1, 192.168.1.0/24, 10.0.0.1-50, targets.txt")
    options["targets"] = input("Target(s): ").strip()
    
    if not options["targets"]:
        print("No targets specified. Exiting.")
        sys.exit(1)
    
    # Get scan type
    print("\nSelect scan type:")
    print("  1. Full scan (recommended)")
    print("  2. Ping sweep only")
    print("  3. Port scan only")
    print("  4. Port scan + NSE scripts")
    
    scan_choice = input("Choice [1-4, default=1]: ").strip() or "1"
    
    if scan_choice == "1":
        options["full"] = True
    elif scan_choice == "2":
        options["ping_sweep"] = True
    elif scan_choice == "3":
        options["port_scan"] = True
    else:
        options["port_scan"] = True
        options["nse"] = True
    
    # Get speed
    print("\nSelect scan speed:")
    print("  1. Slow (safe for fragile networks)")
    print("  2. Normal (balanced)")
    print("  3. Fast (modern networks)")
    print("  4. Aggressive (labs/CTFs)")
    
    speed_choice = input("Choice [1-4, default=2]: ").strip() or "2"
    speed_map = {"1": "slow", "2": "normal", "3": "fast", "4": "aggressive"}
    options["speed"] = speed_map.get(speed_choice, "normal")
    
    # NSE options
    if options.get("nse") or options.get("full"):
        print("\nInclude brute force scripts? (slower but thorough)")
        brute = input("Include brute [y/N]: ").strip().lower()
        options["brute"] = brute == "y"
    
    return options


# =============================================================================
# Main Scan Function
# =============================================================================

def run_scan(args) -> Optional[ScanResult]:
    """Execute the scan based on provided arguments."""
    
    # Get speed preset settings
    preset = SPEED_PRESETS[args.speed]
    
    # Build scan options
    scan_opts = ScanOptions(
        targets=parse_targets(args.targets or args.input_list),
        timing_template=preset["timing_template"],
        min_hostgroup=args.min_hostgroup or preset["min_hostgroup"],
        min_rate=args.min_rate or preset["min_rate"],
        max_rate=args.max_rate or preset["max_rate"],
        max_retries=args.max_retries or preset["max_retries"],
        host_timeout=args.host_timeout or preset["host_timeout"],
        version_detection=args.version_scan or args.full,
        run_nse=args.nse or args.full,
        include_brute=args.brute,
        include_intrusive=args.intrusive,
    )
    
    # Parse ports if specified
    if args.ports:
        scan_opts.tcp_ports = parse_ports(args.ports)
    elif args.all_tcp:
        scan_opts.all_tcp_ports = True
    elif args.top_ports:
        scan_opts.tcp_ports = COMMON_TCP_PORTS[:args.top_ports]
    
    if args.udp_ports:
        scan_opts.udp_ports = parse_ports(args.udp_ports)
    
    # Parse exclusions
    if args.exclude:
        scan_opts.exclude = [h.strip() for h in args.exclude.split(",")]
    if args.exclude_file and os.path.exists(args.exclude_file):
        scan_opts.exclude.extend(read_file_lines(args.exclude_file))
    
    # Create scanner
    scanner = NmapScanner(scan_opts)
    
    # Run appropriate scan type
    result = None
    
    if args.ping_sweep:
        print_status("Running ping sweep...", "info")
        result = scanner.ping_sweep()
        
    elif args.port_scan or args.full:
        if args.full:
            # Full scan: ping sweep -> port scan -> version -> NSE
            print_status("Running full scan...", "info")
            
            # Ping sweep first
            print_status("Phase 1: Host discovery", "info")
            alive_result = scanner.ping_sweep()
            
            if not alive_result.alive_hosts:
                print_status("No alive hosts found", "warning")
                return None
            
            print_status(f"Found {len(alive_result.alive_hosts)} alive hosts", "success")
            
            # Port scan alive hosts
            print_status("Phase 2: Port scanning", "info")
            scan_opts.targets = alive_result.alive_hosts
            result = scanner.port_scan()
            
            # Version detection
            if scan_opts.version_detection and result.open_ports_by_host:
                print_status("Phase 3: Version detection", "info")
                result = scanner.version_scan(result)
            
            # NSE scripts
            if scan_opts.run_nse and result.open_ports_by_host:
                print_status("Phase 4: NSE scripts", "info")
                nse_results = run_nse_scans_parallel(
                    result,
                    threads=args.threads,
                    include_brute=args.brute,
                    include_intrusive=args.intrusive,
                    vuln_only=args.vuln_only,
                    safe_only=args.safe_only,
                )
                # Merge NSE results
                for host in result.hosts.values():
                    for key, output in nse_results.items():
                        if host.ip in key:
                            host.scripts_output[key] = output
        else:
            # Just port scan
            print_status("Running port scan...", "info")
            result = scanner.port_scan()
    
    elif args.nse:
        print_status("Running NSE scripts only...", "info")
        # Need to load previous scan results or scan first
        print_status("Port scan required before NSE scripts", "warning")
        result = scanner.port_scan()
        if result.open_ports_by_host:
            nse_results = run_nse_scans_parallel(
                result,
                threads=args.threads,
                include_brute=args.brute,
                include_intrusive=args.intrusive,
            )
    
    return result


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else "WARNING")
    setup_logging(log_level)
    
    # Handle utility commands
    if args.list_services:
        list_services()
        return 0
    
    if args.list_scripts:
        list_scripts_for_port(args.list_scripts)
        return 0
    
    if args.list_speeds:
        list_speed_presets()
        return 0
    
    # Interactive mode
    if args.interactive:
        opts = interactive_mode()
        # Apply interactive options to args
        args.targets = opts.get("targets")
        args.full = opts.get("full", False)
        args.ping_sweep = opts.get("ping_sweep", False)
        args.port_scan = opts.get("port_scan", False)
        args.nse = opts.get("nse", False)
        args.speed = opts.get("speed", "normal")
        args.brute = opts.get("brute", False)
    
    # Check for targets
    if not args.targets and not args.input_list:
        parser.print_help()
        print("\nError: No targets specified. Use -t or -iL to specify targets.")
        return 1
    
    # Check for root (for SYN scans)
    if not args.ping_sweep:
        require_root()
    
    # Print banner
    print_banner()
    
    # Ensure output directories exist
    ensure_directories(args.output_dir)
    
    # Run the scan
    try:
        result = run_scan(args)
        
        if result and not args.no_report:
            # Generate reports
            print_status("Generating reports...", "info")
            reporter = ReportGenerator(result, output_dir=f"{args.output_dir}/reports")
            reports = reporter.generate_all_reports()
            
            print_status(f"Reports saved to {args.output_dir}/reports/", "success")
            for fmt, path in reports.items():
                print(f"  - {fmt}: {path}")
        
        print_status("Scan complete!", "success")
        return 0
        
    except NmapError as e:
        print_status(f"Scan error: {e}", "error")
        return 1
    except KeyboardInterrupt:
        print_status("\nScan interrupted by user", "warning")
        return 130
    except Exception as e:
        print_status(f"Unexpected error: {e}", "error")
        if args.debug:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
