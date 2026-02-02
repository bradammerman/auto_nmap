"""
Core Scanner Module

Implements network scanning functionality using the python-nmap library.
Handles ping sweeps, port scans, version detection, and NSE script execution.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set

import nmap

from utils import print_status, NmapError, ScanError

logger = logging.getLogger("auto_nmap.scanner")


# Default port lists
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    636, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379,
    8000, 8080, 8443, 9200, 27017
]

COMMON_UDP_PORTS = [53, 67, 68, 69, 123, 161, 162, 500, 514, 1900]


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ScanOptions:
    """Configuration options for a scan."""
    targets: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    
    tcp_ports: List[int] = field(default_factory=lambda: COMMON_TCP_PORTS.copy())
    udp_ports: List[int] = field(default_factory=lambda: COMMON_UDP_PORTS.copy())
    all_tcp_ports: bool = False
    all_udp_ports: bool = False
    
    ping_sweep: bool = True
    version_detection: bool = True
    os_detection: bool = False
    aggressive: bool = False
    
    run_nse: bool = True
    include_brute: bool = False
    include_intrusive: bool = False
    nse_categories: Optional[Set[str]] = None
    custom_scripts: List[str] = field(default_factory=list)
    
    timing_template: int = 3
    min_hostgroup: int = 8
    min_rate: int = 300
    max_rate: int = 1000
    max_retries: int = 3
    host_timeout: str = "20m"


@dataclass
class HostResult:
    """Scan results for a single host."""
    ip: str
    hostname: str = ""
    state: str = "unknown"
    os_info: Optional[Dict[str, Any]] = None
    open_ports: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    scripts_output: Dict[str, str] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan results."""
    hosts: Dict[str, HostResult] = field(default_factory=dict)
    alive_hosts: List[str] = field(default_factory=list)
    open_ports_by_host: Dict[str, Dict[int, str]] = field(default_factory=dict)
    raw_output: str = ""
    command_line: str = ""
    scan_stats: Dict[str, Any] = field(default_factory=dict)

    def get_hosts_with_port(self, port: int, protocol: str = "tcp") -> List[str]:
        """Get all hosts that have a specific port open."""
        hosts = []
        for host, ports in self.open_ports_by_host.items():
            if port in ports and ports[port] == protocol:
                hosts.append(host)
        return hosts


# =============================================================================
# Scanner Class
# =============================================================================

class NmapScanner:
    """Main scanner class using python-nmap."""
    
    def __init__(self, options: ScanOptions):
        """Initialize scanner with options."""
        self.options = options
        self.nm = nmap.PortScanner()
        
    def _build_arguments(self, scan_type: str = "port") -> str:
        """Build nmap arguments string."""
        args = []
        
        # Timing and performance
        args.append(f"-T{self.options.timing_template}")
        args.append(f"--min-hostgroup {self.options.min_hostgroup}")
        args.append(f"--min-rate {self.options.min_rate}")
        
        if self.options.max_rate:
            args.append(f"--max-rate {self.options.max_rate}")
        if self.options.max_retries:
            args.append(f"--max-retries {self.options.max_retries}")
        if self.options.host_timeout:
            args.append(f"--host-timeout {self.options.host_timeout}")
        
        # Scan type specific
        if scan_type == "ping":
            args.append("-sn")  # Ping scan, no port scan
        elif scan_type == "port":
            args.append("-sS")  # SYN scan (requires root)
            if self.options.version_detection:
                args.append("-sV")
            if self.options.os_detection:
                args.append("-O")
        elif scan_type == "version":
            args.append("-sV")
            args.append("--version-intensity 5")
        
        # Exclusions
        if self.options.exclude:
            args.append(f"--exclude {','.join(self.options.exclude)}")
        
        return " ".join(args)
    
    def _get_port_string(self) -> str:
        """Build port specification string."""
        if self.options.all_tcp_ports:
            return "1-65535"
        elif self.options.tcp_ports:
            return ",".join(map(str, self.options.tcp_ports))
        return ",".join(map(str, COMMON_TCP_PORTS))
    
    def _parse_results(self, scan_data: dict) -> ScanResult:
        """Parse nmap scan results into ScanResult object."""
        result = ScanResult()
        result.command_line = self.nm.command_line()
        
        for host in self.nm.all_hosts():
            host_result = HostResult(ip=host)
            
            # Get hostname
            if "hostnames" in self.nm[host]:
                hostnames = self.nm[host]["hostnames"]
                if hostnames and hostnames[0].get("name"):
                    host_result.hostname = hostnames[0]["name"]
            
            # Get state
            host_result.state = self.nm[host].state()
            
            # Get open ports
            if host_result.state == "up":
                result.alive_hosts.append(host)
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        if port_info["state"] == "open":
                            host_result.open_ports[port] = {
                                "protocol": proto,
                                "state": port_info["state"],
                                "service": port_info.get("name", "unknown"),
                                "product": port_info.get("product", ""),
                                "version": port_info.get("version", ""),
                                "extrainfo": port_info.get("extrainfo", ""),
                            }
                            
                            # Track open ports by host
                            if host not in result.open_ports_by_host:
                                result.open_ports_by_host[host] = {}
                            result.open_ports_by_host[host][port] = proto
                            
                            # Capture script output
                            if "script" in port_info:
                                for script_name, output in port_info["script"].items():
                                    key = f"{host}:{port}/{proto}:{script_name}"
                                    host_result.scripts_output[key] = output
            
            result.hosts[host] = host_result
        
        return result
    
    def ping_sweep(self) -> ScanResult:
        """Perform ping sweep to discover alive hosts."""
        targets = " ".join(self.options.targets)
        args = self._build_arguments("ping")
        
        print_status(f"Starting ping sweep on {targets}", "info")
        logger.info(f"Ping sweep: {targets} with args: {args}")
        
        try:
            self.nm.scan(hosts=targets, arguments=args)
            result = self._parse_results(self.nm)
            print_status(f"Discovered {len(result.alive_hosts)} alive hosts", "success")
            return result
        except nmap.PortScannerError as e:
            raise ScanError(f"Ping sweep failed: {e}")
    
    def port_scan(self) -> ScanResult:
        """Perform port scan on targets."""
        targets = " ".join(self.options.targets)
        ports = self._get_port_string()
        args = self._build_arguments("port")
        
        print_status(f"Starting port scan on {targets}", "info")
        print_status(f"Scanning ports: {ports[:50]}{'...' if len(ports) > 50 else ''}", "info")
        logger.info(f"Port scan: {targets} ports={ports} args={args}")
        
        try:
            self.nm.scan(hosts=targets, ports=ports, arguments=args)
            result = self._parse_results(self.nm)
            
            total_open = sum(len(h.open_ports) for h in result.hosts.values())
            print_status(f"Found {total_open} open ports across {len(result.alive_hosts)} hosts", "success")
            
            return result
        except nmap.PortScannerError as e:
            raise ScanError(f"Port scan failed: {e}")
    
    def version_scan(self, previous_result: ScanResult) -> ScanResult:
        """Perform version detection on open ports."""
        # Build targets from previous scan
        targets = []
        for host, ports in previous_result.open_ports_by_host.items():
            targets.append(host)
        
        if not targets:
            print_status("No open ports to version scan", "warning")
            return previous_result
        
        target_str = " ".join(targets)
        ports = ",".join(str(p) for host_ports in previous_result.open_ports_by_host.values() 
                        for p in host_ports.keys())
        args = self._build_arguments("version")
        
        print_status(f"Running version detection", "info")
        
        try:
            self.nm.scan(hosts=target_str, ports=ports, arguments=args)
            result = self._parse_results(self.nm)
            
            # Merge with previous results
            for host, host_result in result.hosts.items():
                if host in previous_result.hosts:
                    previous_result.hosts[host].open_ports.update(host_result.open_ports)
            
            return previous_result
        except nmap.PortScannerError as e:
            raise ScanError(f"Version scan failed: {e}")
    
    def run_nse_script(
        self, 
        host: str, 
        port: int, 
        script: str, 
        args: str = ""
    ) -> Dict[str, str]:
        """Run a single NSE script against a host:port."""
        script_args = f"--script {script}"
        if args:
            script_args += f" --script-args {args}"
        
        scan_args = f"-sV {script_args}"
        
        try:
            self.nm.scan(hosts=host, ports=str(port), arguments=scan_args)
            
            results = {}
            if host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    if port in self.nm[host][proto]:
                        port_info = self.nm[host][proto][port]
                        if "script" in port_info:
                            for script_name, output in port_info["script"].items():
                                results[script_name] = output
            
            return results
        except nmap.PortScannerError as e:
            logger.error(f"NSE script {script} failed on {host}:{port}: {e}")
            return {}
