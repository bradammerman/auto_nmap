# Auto Nmap v3.0

**Automated Network Scanning & Enumeration Tool**

A powerful Python 3 network scanner that automatically discovers hosts, scans ports, detects services, and runs appropriate NSE scripts based on discovered services.

## Features

- **Automatic NSE Selection**: 200+ pre-configured NSE scripts run based on discovered open ports
- **Multithreaded Execution**: Parallel NSE scanning for faster results
- **Smart Speed Presets**: From "paranoid" (IDS evasion) to "insane" (maximum speed)
- **Multiple Report Formats**: TXT, JSON, CSV, and styled HTML reports
- **Remediation Guidance**: 45+ remediation recommendations with severity ratings
- **Kali Linux Support**: Automatic handling of externally-managed-environment errors

## How It Works

### Full Scan Workflow (`--full`)

When you run a full scan, Auto Nmap executes 4 phases automatically:

| Phase | Description | Nmap Flags |
|-------|-------------|------------|
| **1. Host Discovery** | Ping sweep to find alive hosts | `-sn` |
| **2. Port Scanning** | SYN scan on alive hosts for open ports | `-sS` |
| **3. Version Detection** | Service fingerprinting on open ports | `-sV` |
| **4. NSE Scripts** | Runs appropriate scripts based on discovered services | `--script` |

### What Each NSE Category Does

| Category | What It Scans For | Example Scripts |
|----------|-------------------|-----------------|
| **Safe** | Non-intrusive info gathering | Banners, SSL certs, HTTP headers |
| **Discovery** | Service and OS identification | Version detection, OS fingerprinting |
| **Enum** | Resource enumeration | Users, shares, databases, directories |
| **Vuln** | Known vulnerabilities | Heartbleed, EternalBlue, Shellshock, BlueKeep |
| **Auth** | Authentication issues | Anonymous access, empty passwords, weak auth |
| **Brute** | Password attacks | SSH, FTP, SMB, MySQL, RDP brute force |
| **Intrusive** | Aggressive tests | May crash or modify services |

### All Command-Line Options

#### Target Specification
| Flag | Description |
|------|-------------|
| `-t, --targets` | Target: IP, CIDR, range, hostname, or file path |
| `-iL, --input-list` | Read targets from file (one per line) |
| `--exclude` | Exclude specific hosts/networks |
| `--exclude-file` | Exclude hosts listed in a file |

#### Scan Types
| Flag | Description |
|------|-------------|
| `--full` | Complete scan: discovery → ports → version → NSE (RECOMMENDED) |
| `--ping-sweep` | Host discovery only (no port scan) |
| `--port-scan` | TCP/UDP port scan |
| `--version-scan` | Service version detection |
| `--nse` | Run NSE scripts based on open ports |

#### Port Specification
| Flag | Description |
|------|-------------|
| `-p, --ports` | Specific TCP ports (e.g., `22,80,443` or `1-1024`) |
| `--udp-ports` | Specific UDP ports |
| `--all-tcp` | Scan all 65,535 TCP ports |
| `--top-ports N` | Scan top N most common ports |

#### Speed Control
| Flag | Description |
|------|-------------|
| `--speed` | Preset: `paranoid`, `sneaky`, `slow`, `normal`, `fast`, `aggressive`, `insane` |
| `--min-hostgroup` | Minimum hosts to scan in parallel |
| `--min-rate` | Minimum packets per second |
| `--max-rate` | Maximum packets per second |
| `--max-retries` | Max probe retries |
| `--host-timeout` | Give up on host after this time (e.g., `30m`) |

#### NSE Script Options
| Flag | Description |
|------|-------------|
| `--brute` | Include brute force scripts |
| `--intrusive` | Include intrusive scripts (may crash services) |
| `--vuln-only` | Only vulnerability detection scripts |
| `--safe-only` | Only non-disruptive scripts |
| `--threads N` | Parallel NSE threads (default: 5) |
| `--scripts` | Custom NSE scripts (comma-separated) |

#### Output Options
| Flag | Description |
|------|-------------|
| `-o, --output-dir` | Output directory (default: `output`) |
| `--report-formats` | Report formats: `txt,json,csv,html` (default: all) |
| `--no-report` | Skip report generation |
| `-v, --verbose` | Verbose output |
| `--debug` | Very verbose debugging |

#### Utility Options
| Flag | Description |
|------|-------------|
| `-i, --interactive` | Guided menu mode |
| `--list-services` | Show all configured services and scripts |
| `--list-scripts PORT` | Show scripts for a specific port |
| `--list-speeds` | Show speed preset details |
| `--version` | Show version number |

### Output Files Generated

| File | Description |
|------|-------------|
| `security_report_*.html` | Styled HTML report with severity cards, expandable findings |
| `scan_report_*.txt` | Plain text summary with disclaimers |
| `scan_report_*.json` | Machine-readable JSON for SIEM/automation |
| `findings_*.csv` | Security findings for ticketing systems |
| `hosts_ports_*.csv` | All discovered hosts and open ports |
| `summary_*.csv` | Summary metrics for reporting |

## Quick Start

```bash
# Install the ONE required dependency
sudo apt install python3-nmap    # Kali/Debian (recommended)
# OR
pip3 install python-nmap         # Other systems

# Full scan of a subnet
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full

# Fast scan for modern networks
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full --speed fast

# Interactive mode
sudo python3 auto_nmap_v3.py -i
```

## Requirements

- Python 3.8+
- nmap (command-line tool)
- python-nmap (Python library)
- Root/sudo privileges (for SYN scans)

**Note:** prettytable and colorama are NOT required - the script uses built-in alternatives.

## Installation

### Kali Linux / Debian (Recommended)
```bash
sudo apt install python3-nmap
```

### Other Linux / macOS
```bash
pip3 install python-nmap
```

### If you get "externally-managed-environment" error
```bash
pip3 install --break-system-packages python-nmap
```

### Using Setup Script (Recommended for Kali)
```bash
# Clone the repository
git clone https://github.com/bradammerman/auto_nmap.git
cd auto_nmap

# Run setup (creates virtual environment)
bash setup.sh

# Use the quick launcher
sudo bash run.sh -t 192.168.1.0/24 --full
```

The script will automatically detect missing dependencies and offer to install them.

## Project Files

| File | Purpose |
|------|---------|
| `auto_nmap_v3.py` | Main entry point - CLI and workflow orchestration |
| `scanner.py` | Core scanning engine using python-nmap library |
| `executor.py` | Multithreaded NSE script execution |
| `nse_configs.py` | Database of 200+ NSE scripts mapped to ports |
| `remediations.py` | 45+ remediation recommendations with severity |
| `reporter.py` | Report generation (TXT, JSON, CSV, HTML) |
| `utils.py` | Utility functions: logging, parsing, colors |
| `requirements.txt` | Python dependencies |
| `setup.sh` | Setup script for virtual environment |
| `run.sh` | Quick launcher with sudo support |

## Speed Presets

| Preset | Description | Use Case |
|--------|-------------|----------|
| `paranoid` | Extremely slow, IDS evasion | Avoiding detection |
| `sneaky` | Very slow, reduced detection | Stealth assessments |
| `slow` | Safe for fragile networks | Legacy, IoT devices |
| `normal` | Balanced (DEFAULT) | Most networks |
| `fast` | Fast scanning | Modern LANs, cloud |
| `aggressive` | Very fast | Labs, CTFs |
| `insane` | Maximum speed | Local networks only |

## Scan Types & Examples

### Basic Scans

```bash
# Full comprehensive scan (discovery + ports + version + NSE)
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full

# Ping sweep - discover alive hosts only (no port scan)
sudo python3 auto_nmap_v3.py -t 10.0.0.0/24 --ping-sweep

# Port scan only (no NSE scripts)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --port-scan

# Port scan with service version detection
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --port-scan --version-scan

# Port scan with NSE scripts
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --port-scan --nse
```

### Speed-Controlled Scans

```bash
# Fast scan for modern networks (recommended for cloud/LAN)
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full --speed fast

# Aggressive scan for CTF/lab environments
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --speed aggressive

# Slow scan for fragile/legacy systems
sudo python3 auto_nmap_v3.py -t 10.0.0.0/24 --full --speed slow

# Stealth scan to avoid IDS detection
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --speed sneaky

# Paranoid mode for maximum stealth
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --speed paranoid
```

### Vulnerability Scanning

```bash
# Run only vulnerability-related NSE scripts
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --port-scan --nse --vuln-only

# Full scan with vulnerability focus
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full --vuln-only

# Scan for common vulnerabilities (EternalBlue, Heartbleed, etc.)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 445,443 --nse --vuln-only
```

### Brute Force & Authentication Testing

```bash
# Include brute force scripts (FTP, SSH, SMB, etc.)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --brute

# Brute force with more threads for speed
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --brute --threads 10

# Include intrusive scripts (may cause service disruption)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --intrusive

# Safe scripts only (non-disruptive)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --safe-only
```

### Port-Specific Scans

```bash
# Scan specific TCP ports
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 22,80,443,3389,8080 --nse

# Scan port ranges
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 1-1024 --nse

# Scan all 65535 TCP ports
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --all-tcp --nse

# Scan top N most common ports
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --top-ports 100 --nse

# Scan specific UDP ports
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --udp-ports 53,161,500 --nse
```

### Web Server Scanning

```bash
# Scan common web ports with HTTP NSE scripts
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 80,443,8080,8443 --nse

# Web vulnerability scan
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 80,443 --nse --vuln-only

# WordPress/Joomla enumeration
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 80,443 --nse
```

### Database Scanning

```bash
# Scan common database ports
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 1433,1521,3306,5432,27017 --nse

# MySQL scanning with brute force
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 3306 --nse --brute

# MS-SQL scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 1433,1434 --nse

# MongoDB scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 27017 --nse

# Redis scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 6379 --nse
```

### Windows/SMB Scanning

```bash
# SMB enumeration and vulnerability scan
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 139,445 --nse

# Check for EternalBlue (MS17-010)
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 -p 445 --nse --vuln-only

# Windows service enumeration
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 135,139,445,3389,5985 --nse

# RDP vulnerability scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 -p 3389 --nse --vuln-only
```

### Active Directory / Domain Scanning

```bash
# Kerberos and LDAP enumeration
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 88,389,636,3268 --nse

# Domain controller scan
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 53,88,135,139,389,445,636,3268 --nse
```

### Container/Cloud Scanning

```bash
# Docker API scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 2375,2376 --nse

# Kubernetes API scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 6443,10250,10255 --nse

# Elasticsearch scanning
sudo python3 auto_nmap_v3.py -t 192.168.1.1 -p 9200,9300 --nse
```

### Target Specification

```bash
# Single IP
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full

# CIDR notation
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full

# IP range
sudo python3 auto_nmap_v3.py -t 192.168.1.1-50 --full

# Multiple targets (comma-separated)
sudo python3 auto_nmap_v3.py -t 192.168.1.1,192.168.1.10,192.168.1.20 --full

# Targets from file
sudo python3 auto_nmap_v3.py -iL targets.txt --full

# Exclude specific hosts
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254 --full

# Exclude hosts from file
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --exclude-file exclude.txt --full
```

### Output & Reporting

```bash
# Specify output directory
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full -o ./my_scans

# Generate specific report formats
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --report-formats html,json

# Skip report generation
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --no-report

# Verbose output
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full -v

# Debug mode (very verbose)
sudo python3 auto_nmap_v3.py -t 192.168.1.1 --full --debug
```

### Interactive & Utility

```bash
# Interactive guided mode
sudo python3 auto_nmap_v3.py -i

# List all configured services and scripts
python3 auto_nmap_v3.py --list-services

# List scripts for a specific port
python3 auto_nmap_v3.py --list-scripts 445

# View speed preset details
python3 auto_nmap_v3.py --list-speeds

# Show help
python3 auto_nmap_v3.py --help
```

### Real-World Scenarios

```bash
# Penetration test - initial recon (fast discovery)
sudo python3 auto_nmap_v3.py -t 10.0.0.0/24 --ping-sweep --speed fast

# Penetration test - detailed scan of discovered hosts
sudo python3 auto_nmap_v3.py -t 10.0.0.5,10.0.0.10,10.0.0.15 --full --speed normal

# Internal vulnerability assessment
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full --vuln-only --speed fast

# External perimeter scan (stealth mode)
sudo python3 auto_nmap_v3.py -t target.com --full --speed sneaky

# CTF/HackTheBox machine scan
sudo python3 auto_nmap_v3.py -t 10.10.10.5 --full --speed aggressive --brute

# Security audit with full documentation
sudo python3 auto_nmap_v3.py -t 192.168.1.0/24 --full -o ./audit_2024 --report-formats txt,json,csv,html
```

## Report Formats

- **HTML**: Styled report with findings, remediations, severity badges, and expandable details
- **JSON**: Machine-readable for automation, SIEM integration, and API consumption
- **CSV**: Import into Excel, ticketing systems, vulnerability trackers (3 files: findings, hosts, summary)
- **TXT**: Plain text summary for quick review

All reports include important disclaimers that severity ratings are **baseline assessments** and should be adjusted based on your network context (internal vs external), existing security controls, and whether controls were whitelisted for scanning.

## Supported Services & NSE Scripts

Auto Nmap includes pre-configured NSE scripts for 27+ services:

| Service | Ports | Script Categories |
|---------|-------|-------------------|
| FTP | 21 | Auth, Vuln, Brute |
| SSH | 22 | Discovery, Auth, Brute |
| Telnet | 23 | Discovery, Brute |
| SMTP | 25, 465, 587 | Discovery, Enum, Vuln, Brute |
| DNS | 53 | Discovery, Enum |
| HTTP | 80, 8080, 8000, 3000, 5000 | Discovery, Enum, Vuln, Brute |
| HTTPS/SSL | 443, 8443 | Vuln (Heartbleed, POODLE), Discovery |
| SMB | 139, 445 | Discovery, Enum, Vuln (MS17-010, MS08-067), Brute |
| SNMP | 161 (UDP) | Discovery, Enum, Brute |
| LDAP | 389, 636, 3268 | Discovery, Enum, Brute |
| MS-SQL | 1433, 1434 | Discovery, Auth, Brute |
| MySQL | 3306 | Discovery, Enum, Vuln, Auth, Brute |
| PostgreSQL | 5432 | Brute |
| Oracle | 1521 | Discovery, Brute |
| RDP | 3389 | Discovery, Vuln (BlueKeep) |
| VNC | 5900-5902 | Discovery, Vuln, Brute |
| Redis | 6379 | Discovery, Brute |
| MongoDB | 27017 | Discovery, Enum, Brute |
| Elasticsearch | 9200, 9300 | Discovery |
| Docker | 2375, 2376 | Discovery |
| Kubernetes | 6443, 10250, 10255 | Discovery |
| NFS | 111, 2049 | Enum |
| Memcached | 11211 | Discovery |
| CouchDB | 5984 | Discovery, Enum |
| WinRM | 5985, 5986 | Discovery |
| Kerberos | 88 | Enum |
| MQTT | 1883, 8883 | Discovery |

## License

MIT License

## Disclaimer

**This tool is for authorized security testing only.** Always obtain proper written authorization before scanning networks. Unauthorized scanning may be illegal in your jurisdiction. The authors are not responsible for misuse of this tool.
