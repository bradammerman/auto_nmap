"""
Remediation Recommendations Module

Provides modern, actionable remediation guidance for security findings.
Maps vulnerabilities, misconfigurations, and discovered services to
specific remediation steps with severity ratings.

╔══════════════════════════════════════════════════════════════════════════════╗
║                    IMPORTANT: SEVERITY RATING CONTEXT                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  The severity ratings in this module are BASELINE assessments derived from   ║
║  industry standards (CVSS scores, vendor advisories, NIST guidelines).       ║
║                                                                              ║
║  ACTUAL RISK depends on:                                                     ║
║    • Internal vs. external network exposure                                  ║
║    • Existing security controls (firewalls, IDS/IPS, WAF)                    ║
║    • Controls whitelisted to allow scanning                                  ║
║    • Business context and data sensitivity                                   ║
║                                                                              ║
║  ALWAYS adjust severity based on your specific environment.                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FindingCategory(Enum):
    """Categories of security findings."""
    VULNERABILITY = "Vulnerability"
    MISCONFIGURATION = "Misconfiguration"
    EXPOSURE = "Service Exposure"
    WEAK_CRYPTO = "Weak Cryptography"
    DEFAULT_CREDS = "Default Credentials"
    INFO_DISCLOSURE = "Information Disclosure"


@dataclass
class Remediation:
    """
    Remediation recommendation for a finding.
    
    IMPORTANT: The 'severity' field represents a BASELINE assessment.
    Actual severity may be lower if:
    - Service is internal-only
    - Compensating controls exist
    - Security controls were whitelisted for scanning
    """
    title: str
    severity: Severity
    category: FindingCategory
    description: str
    impact: str
    remediation_steps: List[str]
    references: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    cvss_score: Optional[float] = None


# =============================================================================
# SSL/TLS Remediations
# =============================================================================

SSL_REMEDIATIONS = {
    "ssl-heartbleed": Remediation(
        title="Heartbleed Vulnerability (CVE-2014-0160)",
        severity=Severity.CRITICAL,
        category=FindingCategory.VULNERABILITY,
        cve="CVE-2014-0160",
        cvss_score=9.8,
        description="The server is vulnerable to the Heartbleed bug in OpenSSL.",
        impact="Attackers can read sensitive memory contents including private keys and credentials.",
        remediation_steps=[
            "Update OpenSSL to version 1.0.1g or later immediately",
            "Regenerate all SSL/TLS certificates and private keys",
            "Revoke old certificates",
            "Force password resets for all users",
            "Review logs for potential exploitation",
        ],
        references=[
            "https://heartbleed.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        ],
    ),
    "ssl-poodle": Remediation(
        title="POODLE Vulnerability (CVE-2014-3566)",
        severity=Severity.MEDIUM,
        category=FindingCategory.WEAK_CRYPTO,
        cve="CVE-2014-3566",
        cvss_score=3.4,
        description="SSLv3 is enabled and vulnerable to the POODLE attack.",
        impact="Attackers can decrypt encrypted data by exploiting SSLv3 padding.",
        remediation_steps=[
            "Disable SSLv3 on all servers",
            "Enable TLS 1.2 and TLS 1.3 only",
            "Update server configuration: ssl_protocols TLSv1.2 TLSv1.3;",
        ],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2014-3566",
        ],
    ),
    "ssl-ccs-injection": Remediation(
        title="OpenSSL CCS Injection (CVE-2014-0224)",
        severity=Severity.HIGH,
        category=FindingCategory.VULNERABILITY,
        cve="CVE-2014-0224",
        cvss_score=7.4,
        description="Server vulnerable to ChangeCipherSpec injection attack.",
        impact="Allows man-in-the-middle attackers to decrypt and modify traffic.",
        remediation_steps=[
            "Update OpenSSL to the latest patched version",
            "Restart all services using OpenSSL",
        ],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0224",
        ],
    ),
}


# =============================================================================
# SMB Remediations
# =============================================================================

SMB_REMEDIATIONS = {
    "smb-vuln-ms17-010": Remediation(
        title="EternalBlue/MS17-010 Vulnerability",
        severity=Severity.CRITICAL,
        category=FindingCategory.VULNERABILITY,
        cve="CVE-2017-0144",
        cvss_score=9.8,
        description="System vulnerable to EternalBlue (MS17-010) remote code execution.",
        impact="Complete system compromise via remote code execution without authentication.",
        remediation_steps=[
            "Apply Microsoft security update MS17-010 immediately",
            "If patching not possible, disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "Block SMB ports (445, 139) at network perimeter",
            "Enable Windows Firewall",
            "Segment network to limit lateral movement",
        ],
        references=[
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        ],
    ),
    "smb-vuln-ms08-067": Remediation(
        title="MS08-067 Conficker Vulnerability",
        severity=Severity.CRITICAL,
        category=FindingCategory.VULNERABILITY,
        cve="CVE-2008-4250",
        cvss_score=10.0,
        description="System vulnerable to MS08-067 (Conficker worm vulnerability).",
        impact="Remote code execution allowing complete system compromise.",
        remediation_steps=[
            "Apply Microsoft security update MS08-067",
            "This system is severely outdated - plan for replacement",
            "Isolate from network until patched or replaced",
        ],
        references=[
            "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067",
        ],
    ),
}


# =============================================================================
# HTTP Remediations
# =============================================================================

HTTP_REMEDIATIONS = {
    "http-shellshock": Remediation(
        title="Shellshock Vulnerability (CVE-2014-6271)",
        severity=Severity.CRITICAL,
        category=FindingCategory.VULNERABILITY,
        cve="CVE-2014-6271",
        cvss_score=9.8,
        description="CGI scripts vulnerable to Shellshock bash injection.",
        impact="Remote code execution on the web server.",
        remediation_steps=[
            "Update bash to the latest patched version",
            "Audit and remove unnecessary CGI scripts",
            "Implement WAF rules to block Shellshock attempts",
        ],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        ],
    ),
    "http-git": Remediation(
        title="Exposed Git Repository",
        severity=Severity.HIGH,
        category=FindingCategory.INFO_DISCLOSURE,
        description="Git repository (.git directory) is publicly accessible.",
        impact="Source code, credentials, and sensitive configuration may be exposed.",
        remediation_steps=[
            "Block access to .git directory in web server config",
            "Apache: RedirectMatch 404 /\\.git",
            "Nginx: location ~ /\\.git { deny all; }",
            "Review exposed code for hardcoded secrets",
            "Rotate any exposed credentials",
        ],
        references=[],
    ),
}


# =============================================================================
# Service Exposure Remediations
# =============================================================================

SERVICE_REMEDIATIONS = {
    "telnet-exposure": Remediation(
        title="Telnet Service Enabled",
        severity=Severity.HIGH,
        category=FindingCategory.EXPOSURE,
        description="Telnet service is running and accessible.",
        impact="Credentials transmitted in cleartext; vulnerable to sniffing attacks.",
        remediation_steps=[
            "Disable Telnet service immediately",
            "Replace with SSH for secure remote access",
            "If Telnet required, restrict to specific IPs via firewall",
        ],
        references=[],
    ),
    "rdp-exposure": Remediation(
        title="RDP Exposed to Network",
        severity=Severity.HIGH,
        category=FindingCategory.EXPOSURE,
        description="Remote Desktop Protocol is accessible.",
        impact="Target for brute force and exploitation (BlueKeep, etc.)",
        remediation_steps=[
            "Enable Network Level Authentication (NLA)",
            "Restrict RDP access via firewall to specific IPs",
            "Use RDP Gateway or VPN for remote access",
            "Enable account lockout policies",
            "Apply all Windows security updates",
        ],
        references=[],
    ),
    "ftp-anon": Remediation(
        title="Anonymous FTP Access Enabled",
        severity=Severity.MEDIUM,
        category=FindingCategory.MISCONFIGURATION,
        description="FTP server allows anonymous login.",
        impact="Unauthorized access to files; potential data exfiltration.",
        remediation_steps=[
            "Disable anonymous FTP access",
            "Require authentication for all users",
            "Consider replacing FTP with SFTP",
            "Review files accessible via anonymous access",
        ],
        references=[],
    ),
}


# =============================================================================
# Database Remediations
# =============================================================================

DATABASE_REMEDIATIONS = {
    "mysql-empty-password": Remediation(
        title="MySQL Root Without Password",
        severity=Severity.CRITICAL,
        category=FindingCategory.DEFAULT_CREDS,
        description="MySQL root account has no password.",
        impact="Complete database compromise; data theft and manipulation.",
        remediation_steps=[
            "Set a strong password: ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword';",
            "Remove anonymous users: DELETE FROM mysql.user WHERE User='';",
            "Restrict root to localhost only",
            "Enable audit logging",
        ],
        references=[],
    ),
    "ms-sql-empty-password": Remediation(
        title="MS-SQL SA Account Without Password",
        severity=Severity.CRITICAL,
        category=FindingCategory.DEFAULT_CREDS,
        description="SQL Server SA account has no password.",
        impact="Complete database and potentially OS compromise via xp_cmdshell.",
        remediation_steps=[
            "Set a strong SA password immediately",
            "Disable SA account if not needed",
            "Use Windows Authentication when possible",
            "Disable xp_cmdshell if not required",
        ],
        references=[],
    ),
}


# =============================================================================
# All Remediations Combined
# =============================================================================

ALL_REMEDIATIONS = {
    **SSL_REMEDIATIONS,
    **SMB_REMEDIATIONS,
    **HTTP_REMEDIATIONS,
    **SERVICE_REMEDIATIONS,
    **DATABASE_REMEDIATIONS,
}


# Port-based remediations
PORT_REMEDIATIONS = {
    23: SERVICE_REMEDIATIONS["telnet-exposure"],
    3389: SERVICE_REMEDIATIONS["rdp-exposure"],
}


# =============================================================================
# Helper Functions
# =============================================================================

def get_remediation(script_name: str) -> Optional[Remediation]:
    """Get remediation for a script name."""
    return ALL_REMEDIATIONS.get(script_name)


def get_remediation_by_port(port: int, protocol: str = "tcp") -> Optional[Remediation]:
    """Get remediation for an exposed port."""
    return PORT_REMEDIATIONS.get(port)


def get_all_remediations_for_finding(
    script_outputs: Dict[str, str],
    open_ports: Dict[int, str]
) -> List[Tuple[str, Remediation]]:
    """Get all applicable remediations for scan findings."""
    results = []
    
    # Check script outputs
    for script_key, output in script_outputs.items():
        parts = script_key.split(":")
        if len(parts) >= 3:
            script_name = parts[-1]
            remediation = get_remediation(script_name)
            if remediation:
                results.append((script_key, remediation))
    
    # Check port exposures
    for port, protocol in open_ports.items():
        remediation = get_remediation_by_port(port, protocol)
        if remediation:
            results.append((f"port_{port}_{protocol}", remediation))
    
    return results


def get_severity_color(severity: Severity) -> str:
    """Get color code for severity level."""
    colors = {
        Severity.CRITICAL: "#dc2626",
        Severity.HIGH: "#ea580c",
        Severity.MEDIUM: "#d97706",
        Severity.LOW: "#2563eb",
        Severity.INFO: "#6b7280",
    }
    return colors.get(severity, "#6b7280")


def get_severity_badge_class(severity: Severity) -> str:
    """Get CSS class for severity badge."""
    classes = {
        Severity.CRITICAL: "badge-critical",
        Severity.HIGH: "badge-high",
        Severity.MEDIUM: "badge-medium",
        Severity.LOW: "badge-low",
        Severity.INFO: "badge-info",
    }
    return classes.get(severity, "badge-info")
