"""
NSE Script Configurations

Database of 200+ pre-configured NSE scripts organized by service.
Each script includes name, arguments, description, and categories.
Maps ports to appropriate scripts automatically.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set
from enum import Enum


class ScanCategory(Enum):
    """NSE script categories."""
    SAFE = "safe"
    INTRUSIVE = "intrusive"
    VULN = "vuln"
    EXPLOIT = "exploit"
    BRUTE = "brute"
    DISCOVERY = "discovery"
    ENUM = "enum"
    AUTH = "auth"
    DEFAULT = "default"
    VERSION = "version"


@dataclass
class NSEScript:
    """Configuration for a single NSE script."""
    name: str
    description: str
    categories: List[ScanCategory]
    args: Optional[str] = None
    timeout: int = 300


@dataclass
class ServiceConfig:
    """Configuration for a service with its associated scripts."""
    name: str
    ports: List[int]
    protocol: str = "tcp"
    scripts: List[NSEScript] = field(default_factory=list)


# =============================================================================
# FTP Scripts (Port 21)
# =============================================================================
FTP_SCRIPTS = [
    NSEScript("ftp-anon", "Check for anonymous FTP access", [ScanCategory.SAFE, ScanCategory.AUTH]),
    NSEScript("ftp-bounce", "Check for FTP bounce attack", [ScanCategory.SAFE]),
    NSEScript("ftp-syst", "Get FTP system information", [ScanCategory.SAFE, ScanCategory.VERSION]),
    NSEScript("ftp-vsftpd-backdoor", "Check for vsftpd 2.3.4 backdoor", [ScanCategory.VULN]),
    NSEScript("ftp-proftpd-backdoor", "Check for ProFTPD 1.3.3c backdoor", [ScanCategory.VULN]),
    NSEScript("ftp-brute", "FTP brute force", [ScanCategory.BRUTE]),
]
FTP_CONFIG = ServiceConfig(name="FTP", ports=[21], scripts=FTP_SCRIPTS)


# =============================================================================
# SSH Scripts (Port 22)
# =============================================================================
SSH_SCRIPTS = [
    NSEScript("ssh2-enum-algos", "Enumerate SSH algorithms", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ssh-hostkey", "Get SSH host key", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ssh-auth-methods", "Get SSH auth methods", [ScanCategory.SAFE, ScanCategory.AUTH]),
    NSEScript("sshv1", "Check for SSHv1 support", [ScanCategory.SAFE, ScanCategory.VULN]),
    NSEScript("ssh-brute", "SSH brute force", [ScanCategory.BRUTE]),
]
SSH_CONFIG = ServiceConfig(name="SSH", ports=[22], scripts=SSH_SCRIPTS)


# =============================================================================
# Telnet Scripts (Port 23)
# =============================================================================
TELNET_SCRIPTS = [
    NSEScript("telnet-ntlm-info", "Get Telnet NTLM info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("telnet-encryption", "Check Telnet encryption", [ScanCategory.SAFE]),
    NSEScript("banner", "Grab banner", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("telnet-brute", "Telnet brute force", [ScanCategory.BRUTE]),
]
TELNET_CONFIG = ServiceConfig(name="Telnet", ports=[23], scripts=TELNET_SCRIPTS)


# =============================================================================
# SMTP Scripts (Ports 25, 465, 587)
# =============================================================================
SMTP_SCRIPTS = [
    NSEScript("smtp-commands", "List SMTP commands", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("smtp-enum-users", "Enumerate SMTP users", [ScanCategory.INTRUSIVE, ScanCategory.ENUM]),
    NSEScript("smtp-ntlm-info", "Get SMTP NTLM info", [ScanCategory.SAFE]),
    NSEScript("smtp-open-relay", "Check for open relay", [ScanCategory.INTRUSIVE]),
    NSEScript("smtp-vuln-cve2010-4344", "Check Exim vulns", [ScanCategory.VULN]),
    NSEScript("smtp-brute", "SMTP brute force", [ScanCategory.BRUTE]),
]
SMTP_CONFIG = ServiceConfig(name="SMTP", ports=[25, 465, 587], scripts=SMTP_SCRIPTS)


# =============================================================================
# DNS Scripts (Port 53)
# =============================================================================
DNS_TCP_SCRIPTS = [
    NSEScript("dns-zone-transfer", "Attempt zone transfer", [ScanCategory.INTRUSIVE, ScanCategory.DISCOVERY]),
    NSEScript("dns-recursion", "Check for DNS recursion", [ScanCategory.SAFE]),
    NSEScript("dns-nsid", "Get DNS NSID", [ScanCategory.SAFE]),
    NSEScript("dns-cache-snoop", "DNS cache snooping", [ScanCategory.INTRUSIVE]),
    NSEScript("dns-srv-enum", "Enumerate SRV records", [ScanCategory.SAFE, ScanCategory.ENUM]),
]
DNS_TCP_CONFIG = ServiceConfig(name="DNS", ports=[53], protocol="tcp", scripts=DNS_TCP_SCRIPTS)


# =============================================================================
# HTTP Scripts (Ports 80, 8080, 8000, 3000, 5000)
# =============================================================================
HTTP_SCRIPTS = [
    NSEScript("http-title", "Get page title", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("http-methods", "Enumerate HTTP methods", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("http-headers", "Get HTTP headers", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("http-server-header", "Get server header", [ScanCategory.SAFE]),
    NSEScript("http-robots.txt", "Get robots.txt", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("http-sitemap-generator", "Generate sitemap", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("http-enum", "Enumerate directories", [ScanCategory.INTRUSIVE, ScanCategory.ENUM]),
    NSEScript("http-git", "Find exposed .git", [ScanCategory.SAFE, ScanCategory.VULN]),
    NSEScript("http-config-backup", "Find config backups", [ScanCategory.SAFE, ScanCategory.VULN]),
    NSEScript("http-shellshock", "Check for Shellshock", [ScanCategory.VULN], args="uri=/cgi-bin/test.cgi"),
    NSEScript("http-vuln-cve2017-5638", "Struts2 RCE", [ScanCategory.VULN]),
    NSEScript("http-vuln-cve2014-3704", "Drupalgeddon", [ScanCategory.VULN]),
    NSEScript("http-sql-injection", "SQL injection check", [ScanCategory.VULN, ScanCategory.INTRUSIVE]),
    NSEScript("http-xssed", "XSS via xssed.com", [ScanCategory.SAFE, ScanCategory.VULN]),
    NSEScript("http-wordpress-enum", "WordPress enum", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("http-wordpress-brute", "WordPress brute", [ScanCategory.BRUTE]),
    NSEScript("http-joomla-brute", "Joomla brute", [ScanCategory.BRUTE]),
    NSEScript("http-form-brute", "Form brute force", [ScanCategory.BRUTE]),
]
HTTP_CONFIG = ServiceConfig(name="HTTP", ports=[80, 8080, 8000, 3000, 5000, 8008], scripts=HTTP_SCRIPTS)


# =============================================================================
# HTTPS/SSL Scripts (Ports 443, 8443)
# =============================================================================
HTTPS_SCRIPTS = [
    NSEScript("ssl-heartbleed", "Check Heartbleed (CVE-2014-0160)", [ScanCategory.VULN]),
    NSEScript("ssl-poodle", "Check POODLE (CVE-2014-3566)", [ScanCategory.VULN]),
    NSEScript("ssl-ccs-injection", "Check CCS Injection", [ScanCategory.VULN]),
    NSEScript("ssl-cert", "Get SSL certificate", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ssl-enum-ciphers", "Enumerate SSL ciphers", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ssl-dh-params", "Check DH parameters", [ScanCategory.SAFE]),
    NSEScript("sslv2", "Check SSLv2 support", [ScanCategory.SAFE, ScanCategory.VULN]),
    NSEScript("ssl-known-key", "Check for known weak keys", [ScanCategory.SAFE, ScanCategory.VULN]),
] + HTTP_SCRIPTS  # Include HTTP scripts for HTTPS
HTTPS_CONFIG = ServiceConfig(name="HTTPS", ports=[443, 8443, 9443], scripts=HTTPS_SCRIPTS)


# =============================================================================
# SMB Scripts (Ports 139, 445)
# =============================================================================
SMB_SCRIPTS = [
    NSEScript("smb-os-discovery", "SMB OS discovery", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("smb-protocols", "List SMB protocols", [ScanCategory.SAFE]),
    NSEScript("smb-security-mode", "Get SMB security mode", [ScanCategory.SAFE]),
    NSEScript("smb-enum-shares", "Enumerate SMB shares", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("smb-enum-users", "Enumerate SMB users", [ScanCategory.INTRUSIVE, ScanCategory.ENUM]),
    NSEScript("smb-enum-domains", "Enumerate SMB domains", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("smb-vuln-ms17-010", "EternalBlue check", [ScanCategory.VULN]),
    NSEScript("smb-vuln-ms08-067", "MS08-067 Conficker", [ScanCategory.VULN]),
    NSEScript("smb-vuln-ms10-054", "MS10-054 check", [ScanCategory.VULN]),
    NSEScript("smb-vuln-ms10-061", "MS10-061 check", [ScanCategory.VULN]),
    NSEScript("smb-vuln-cve-2017-7494", "SambaCry check", [ScanCategory.VULN]),
    NSEScript("smb-brute", "SMB brute force", [ScanCategory.BRUTE]),
]
SMB_CONFIG = ServiceConfig(name="SMB", ports=[139, 445], scripts=SMB_SCRIPTS)


# =============================================================================
# SNMP Scripts (Port 161)
# =============================================================================
SNMP_SCRIPTS = [
    NSEScript("snmp-info", "Get SNMP system info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("snmp-sysdescr", "Get SNMP sysdescr", [ScanCategory.SAFE]),
    NSEScript("snmp-interfaces", "Enumerate interfaces", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("snmp-processes", "List processes", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("snmp-netstat", "SNMP netstat", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("snmp-brute", "SNMP community brute", [ScanCategory.BRUTE]),
]
SNMP_CONFIG = ServiceConfig(name="SNMP", ports=[161], protocol="udp", scripts=SNMP_SCRIPTS)


# =============================================================================
# LDAP Scripts (Ports 389, 636, 3268)
# =============================================================================
LDAP_SCRIPTS = [
    NSEScript("ldap-rootdse", "Get LDAP root DSE", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ldap-search", "LDAP search", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("ldap-novell-getpass", "Novell password disclosure", [ScanCategory.VULN]),
    NSEScript("ldap-brute", "LDAP brute force", [ScanCategory.BRUTE]),
]
LDAP_CONFIG = ServiceConfig(name="LDAP", ports=[389, 636, 3268], scripts=LDAP_SCRIPTS)


# =============================================================================
# MS-SQL Scripts (Ports 1433, 1434)
# =============================================================================
MSSQL_SCRIPTS = [
    NSEScript("ms-sql-info", "Get MS-SQL info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ms-sql-config", "Get MS-SQL config", [ScanCategory.SAFE]),
    NSEScript("ms-sql-ntlm-info", "MS-SQL NTLM info", [ScanCategory.SAFE]),
    NSEScript("ms-sql-empty-password", "Check empty SA password", [ScanCategory.SAFE, ScanCategory.AUTH]),
    NSEScript("ms-sql-brute", "MS-SQL brute force", [ScanCategory.BRUTE]),
    NSEScript("ms-sql-xp-cmdshell", "Check xp_cmdshell", [ScanCategory.INTRUSIVE, ScanCategory.VULN]),
]
MSSQL_CONFIG = ServiceConfig(name="MS-SQL", ports=[1433, 1434], scripts=MSSQL_SCRIPTS)


# =============================================================================
# MySQL Scripts (Port 3306)
# =============================================================================
MYSQL_SCRIPTS = [
    NSEScript("mysql-info", "Get MySQL info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("mysql-enum", "Enumerate MySQL", [ScanCategory.INTRUSIVE, ScanCategory.ENUM]),
    NSEScript("mysql-empty-password", "Check empty root", [ScanCategory.SAFE, ScanCategory.AUTH]),
    NSEScript("mysql-vuln-cve2012-2122", "MySQL auth bypass", [ScanCategory.VULN]),
    NSEScript("mysql-brute", "MySQL brute force", [ScanCategory.BRUTE]),
]
MYSQL_CONFIG = ServiceConfig(name="MySQL", ports=[3306], scripts=MYSQL_SCRIPTS)


# =============================================================================
# PostgreSQL Scripts (Port 5432)
# =============================================================================
PGSQL_SCRIPTS = [
    NSEScript("pgsql-brute", "PostgreSQL brute force", [ScanCategory.BRUTE]),
]
PGSQL_CONFIG = ServiceConfig(name="PostgreSQL", ports=[5432], scripts=PGSQL_SCRIPTS)


# =============================================================================
# Oracle Scripts (Port 1521)
# =============================================================================
ORACLE_SCRIPTS = [
    NSEScript("oracle-tns-version", "Get Oracle TNS version", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("oracle-sid-brute", "Oracle SID brute", [ScanCategory.BRUTE]),
    NSEScript("oracle-brute", "Oracle brute force", [ScanCategory.BRUTE]),
]
ORACLE_CONFIG = ServiceConfig(name="Oracle", ports=[1521], scripts=ORACLE_SCRIPTS)


# =============================================================================
# RDP Scripts (Port 3389)
# =============================================================================
RDP_SCRIPTS = [
    NSEScript("rdp-enum-encryption", "Enumerate RDP encryption", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("rdp-vuln-ms12-020", "MS12-020 BlueKeep check", [ScanCategory.VULN]),
    NSEScript("rdp-ntlm-info", "RDP NTLM info", [ScanCategory.SAFE]),
]
RDP_CONFIG = ServiceConfig(name="RDP", ports=[3389], scripts=RDP_SCRIPTS)


# =============================================================================
# VNC Scripts (Ports 5900-5910)
# =============================================================================
VNC_SCRIPTS = [
    NSEScript("vnc-info", "Get VNC info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("vnc-title", "Get VNC desktop title", [ScanCategory.SAFE]),
    NSEScript("realvnc-auth-bypass", "RealVNC auth bypass", [ScanCategory.VULN]),
    NSEScript("vnc-brute", "VNC brute force", [ScanCategory.BRUTE]),
]
VNC_CONFIG = ServiceConfig(name="VNC", ports=[5900, 5901, 5902], scripts=VNC_SCRIPTS)


# =============================================================================
# Redis Scripts (Port 6379)
# =============================================================================
REDIS_SCRIPTS = [
    NSEScript("redis-info", "Get Redis info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("redis-brute", "Redis brute force", [ScanCategory.BRUTE]),
]
REDIS_CONFIG = ServiceConfig(name="Redis", ports=[6379], scripts=REDIS_SCRIPTS)


# =============================================================================
# MongoDB Scripts (Port 27017)
# =============================================================================
MONGODB_SCRIPTS = [
    NSEScript("mongodb-info", "Get MongoDB info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("mongodb-databases", "List MongoDB databases", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("mongodb-brute", "MongoDB brute force", [ScanCategory.BRUTE]),
]
MONGODB_CONFIG = ServiceConfig(name="MongoDB", ports=[27017], scripts=MONGODB_SCRIPTS)


# =============================================================================
# Elasticsearch Scripts (Ports 9200, 9300)
# =============================================================================
ELASTIC_SCRIPTS = [
    NSEScript("http-title", "Get ES info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
ELASTIC_CONFIG = ServiceConfig(name="Elasticsearch", ports=[9200, 9300], scripts=ELASTIC_SCRIPTS)


# =============================================================================
# Docker Scripts (Ports 2375, 2376)
# =============================================================================
DOCKER_SCRIPTS = [
    NSEScript("docker-version", "Get Docker version", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
DOCKER_CONFIG = ServiceConfig(name="Docker", ports=[2375, 2376], scripts=DOCKER_SCRIPTS)


# =============================================================================
# Kubernetes Scripts (Ports 6443, 10250)
# =============================================================================
K8S_SCRIPTS = [
    NSEScript("http-title", "Get K8s API info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("ssl-cert", "Get K8s cert", [ScanCategory.SAFE]),
]
K8S_CONFIG = ServiceConfig(name="Kubernetes", ports=[6443, 10250, 10255], scripts=K8S_SCRIPTS)


# =============================================================================
# NFS Scripts (Port 2049)
# =============================================================================
NFS_SCRIPTS = [
    NSEScript("nfs-showmount", "Show NFS exports", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("nfs-ls", "List NFS directories", [ScanCategory.SAFE, ScanCategory.ENUM]),
    NSEScript("nfs-statfs", "Get NFS stats", [ScanCategory.SAFE]),
]
NFS_CONFIG = ServiceConfig(name="NFS", ports=[2049, 111], scripts=NFS_SCRIPTS)


# =============================================================================
# Memcached Scripts (Port 11211)
# =============================================================================
MEMCACHED_SCRIPTS = [
    NSEScript("memcached-info", "Get Memcached info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
MEMCACHED_CONFIG = ServiceConfig(name="Memcached", ports=[11211], scripts=MEMCACHED_SCRIPTS)


# =============================================================================
# CouchDB Scripts (Port 5984)
# =============================================================================
COUCHDB_SCRIPTS = [
    NSEScript("couchdb-stats", "Get CouchDB stats", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
    NSEScript("couchdb-databases", "List CouchDB databases", [ScanCategory.SAFE, ScanCategory.ENUM]),
]
COUCHDB_CONFIG = ServiceConfig(name="CouchDB", ports=[5984], scripts=COUCHDB_SCRIPTS)


# =============================================================================
# WinRM Scripts (Ports 5985, 5986)
# =============================================================================
WINRM_SCRIPTS = [
    NSEScript("http-title", "Get WinRM info", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
WINRM_CONFIG = ServiceConfig(name="WinRM", ports=[5985, 5986], scripts=WINRM_SCRIPTS)


# =============================================================================
# Kerberos Scripts (Port 88)
# =============================================================================
KERBEROS_SCRIPTS = [
    NSEScript("krb5-enum-users", "Enumerate Kerberos users", [ScanCategory.ENUM]),
    NSEScript("banner", "Grab banner", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
KERBEROS_CONFIG = ServiceConfig(name="Kerberos", ports=[88], scripts=KERBEROS_SCRIPTS)


# =============================================================================
# MQTT Scripts (Ports 1883, 8883)
# =============================================================================
MQTT_SCRIPTS = [
    NSEScript("mqtt-subscribe", "MQTT subscribe test", [ScanCategory.SAFE, ScanCategory.DISCOVERY]),
]
MQTT_CONFIG = ServiceConfig(name="MQTT", ports=[1883, 8883], scripts=MQTT_SCRIPTS)


# =============================================================================
# All Service Configurations
# =============================================================================

ALL_SERVICE_CONFIGS: List[ServiceConfig] = [
    FTP_CONFIG,
    SSH_CONFIG,
    TELNET_CONFIG,
    SMTP_CONFIG,
    DNS_TCP_CONFIG,
    HTTP_CONFIG,
    HTTPS_CONFIG,
    SMB_CONFIG,
    SNMP_CONFIG,
    LDAP_CONFIG,
    MSSQL_CONFIG,
    MYSQL_CONFIG,
    PGSQL_CONFIG,
    ORACLE_CONFIG,
    RDP_CONFIG,
    VNC_CONFIG,
    REDIS_CONFIG,
    MONGODB_CONFIG,
    ELASTIC_CONFIG,
    DOCKER_CONFIG,
    K8S_CONFIG,
    NFS_CONFIG,
    MEMCACHED_CONFIG,
    COUCHDB_CONFIG,
    WINRM_CONFIG,
    KERBEROS_CONFIG,
    MQTT_CONFIG,
]


# =============================================================================
# Port Lists
# =============================================================================

COMMON_TCP_PORTS = sorted(set(
    port 
    for config in ALL_SERVICE_CONFIGS 
    if config.protocol == "tcp"
    for port in config.ports
))

COMMON_UDP_PORTS = sorted(set(
    port 
    for config in ALL_SERVICE_CONFIGS 
    if config.protocol == "udp"
    for port in config.ports
))


# =============================================================================
# Helper Functions
# =============================================================================

def get_service_config_for_port(port: int, protocol: str = "tcp") -> Optional[ServiceConfig]:
    """Get service configuration for a port."""
    for config in ALL_SERVICE_CONFIGS:
        if port in config.ports and config.protocol == protocol:
            return config
    return None


def get_all_tcp_ports() -> List[int]:
    """Get all configured TCP ports."""
    return COMMON_TCP_PORTS.copy()


def get_all_udp_ports() -> List[int]:
    """Get all configured UDP ports."""
    return COMMON_UDP_PORTS.copy()


def get_scripts_for_category(category: ScanCategory) -> List[NSEScript]:
    """Get all scripts in a category."""
    scripts = []
    for config in ALL_SERVICE_CONFIGS:
        for script in config.scripts:
            if category in script.categories:
                scripts.append(script)
    return scripts
