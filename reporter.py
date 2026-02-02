"""
Output and Reporting Module

Generates formatted reports from scan results in multiple formats (TXT, JSON, CSV, HTML).
CSV output enables easy import into Excel, SIEM tools, and ticketing systems.
Includes remediation recommendations and important disclaimers about baseline severity ratings.

IMPORTANT DISCLAIMER:
Severity ratings are BASELINE assessments. Actual risk depends on:
- Network location (internal vs. external)
- Existing security controls (firewalls, IDS/IPS, WAF)
- Controls whitelisted to allow scanning
- Business context and data sensitivity
"""

import csv
import json
import logging
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict

from scanner import ScanResult, HostResult
from remediations import (
    get_remediation,
    get_remediation_by_port,
    get_all_remediations_for_finding,
    Remediation,
    Severity,
    FindingCategory,
)
from utils import print_status, get_timestamp

logger = logging.getLogger("auto_nmap.reporter")


# =============================================================================
# Finding Analysis
# =============================================================================

def analyze_findings(scan_result: ScanResult) -> Dict[str, Any]:
    """Analyze scan results to extract findings with remediations."""
    findings = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": [],
        "summary": {
            "total_hosts": len(scan_result.hosts),
            "hosts_with_issues": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        }
    }

    hosts_with_issues = set()

    for host, host_result in scan_result.hosts.items():
        script_outputs = host_result.scripts_output
        open_ports = {port: info.get("protocol", "tcp")
                     for port, info in host_result.open_ports.items()}

        host_remediations = get_all_remediations_for_finding(script_outputs, open_ports)

        for finding_key, remediation in host_remediations:
            finding = {
                "host": host,
                "hostname": host_result.hostname,
                "finding_key": finding_key,
                "remediation": remediation,
                "script_output": script_outputs.get(finding_key, ""),
            }

            if remediation.severity == Severity.CRITICAL:
                findings["critical"].append(finding)
                findings["summary"]["critical_count"] += 1
            elif remediation.severity == Severity.HIGH:
                findings["high"].append(finding)
                findings["summary"]["high_count"] += 1
            elif remediation.severity == Severity.MEDIUM:
                findings["medium"].append(finding)
                findings["summary"]["medium_count"] += 1
            elif remediation.severity == Severity.LOW:
                findings["low"].append(finding)
                findings["summary"]["low_count"] += 1
            else:
                findings["info"].append(finding)
                findings["summary"]["info_count"] += 1

            hosts_with_issues.add(host)

    findings["summary"]["hosts_with_issues"] = len(hosts_with_issues)
    return findings


# =============================================================================
# Report Generator Class
# =============================================================================

class ReportGenerator:
    """Generates reports from scan results in various formats."""

    def __init__(
        self,
        scan_result: ScanResult,
        nse_results: Optional[Dict[str, Any]] = None,
        output_dir: str = "reports"
    ):
        self.scan_result = scan_result
        self.nse_results = nse_results or {}
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = get_timestamp()
        self.findings = analyze_findings(scan_result)

    def generate_all_reports(self) -> Dict[str, str]:
        """Generate all report formats."""
        reports = {}

        reports["html"] = self.generate_html_report()
        reports["txt"] = self.generate_text_report()
        reports["json"] = self.generate_json_report()
        
        csv_reports = self.generate_csv_reports()
        reports.update(csv_reports)

        print_status(f"Generated {len(reports)} report file(s)", "success")
        return reports

    def generate_text_report(self) -> str:
        """Generate plain text report with disclaimer."""
        report_file = self.output_dir / f"scan_report_{self.timestamp}.txt"
        summary = self.findings["summary"]

        lines = [
            "=" * 70,
            "AUTO NMAP SECURITY SCAN REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 70,
            "",
            "┌────────────────────────────────────────────────────────────────────┐",
            "│           ⚠️  IMPORTANT: SEVERITY RATING CONTEXT                  │",
            "├────────────────────────────────────────────────────────────────────┤",
            "│  Severity ratings are BASELINE assessments that MUST be adjusted  │",
            "│  based on your specific environment:                              │",
            "│    • Internal vs. external network exposure                       │",
            "│    • Existing security controls (firewalls, IDS/IPS, WAF)         │",
            "│    • Controls whitelisted to allow this scan                      │",
            "│    • Business context and data sensitivity                        │",
            "└────────────────────────────────────────────────────────────────────┘",
            "",
            "SUMMARY",
            "-" * 40,
            f"Total hosts discovered: {len(self.scan_result.alive_hosts)}",
            f"Hosts with open ports: {len(self.scan_result.open_ports_by_host)}",
            f"Critical findings (baseline): {summary['critical_count']}",
            f"High findings (baseline): {summary['high_count']}",
            f"Medium findings (baseline): {summary['medium_count']}",
            "",
        ]

        # Add findings
        for severity, findings_list in [
            ("CRITICAL", self.findings["critical"]),
            ("HIGH", self.findings["high"]),
            ("MEDIUM", self.findings["medium"]),
        ]:
            if findings_list:
                lines.extend([f"\n{severity} FINDINGS", "-" * 40])
                seen = set()
                for finding in findings_list:
                    key = (finding["remediation"].title, finding["host"])
                    if key not in seen:
                        lines.append(f"\n[{finding['host']}] {finding['remediation'].title}")
                        lines.append(f"  {finding['remediation'].description[:150]}...")
                        seen.add(key)

        # Add host details
        lines.extend(["\n", "HOST DETAILS", "-" * 40])
        for host, host_result in sorted(self.scan_result.hosts.items()):
            hostname = host_result.hostname
            host_header = f"{host} ({hostname})" if hostname else host
            lines.append(f"\n[{host_header}]")
            lines.append(f"  State: {host_result.state}")
            if host_result.open_ports:
                lines.append("  Open Ports:")
                for port, info in sorted(host_result.open_ports.items()):
                    service = info.get("service", "unknown")
                    lines.append(f"    {port}/{info.get('protocol', 'tcp')}: {service}")

        lines.extend(["", "=" * 70, "END OF REPORT", "=" * 70])

        with open(report_file, "w") as f:
            f.write("\n".join(lines))

        logger.info(f"Generated text report: {report_file}")
        return str(report_file)

    def generate_json_report(self) -> str:
        """Generate JSON report with severity context."""
        report_file = self.output_dir / f"scan_report_{self.timestamp}.json"

        def remediation_to_dict(r: Remediation) -> dict:
            return {
                "title": r.title,
                "severity": r.severity.value,
                "category": r.category.value,
                "description": r.description,
                "impact": r.impact,
                "remediation_steps": r.remediation_steps,
                "references": r.references,
                "cve": r.cve,
                "cvss_score": r.cvss_score,
            }

        report_data = {
            "metadata": {
                "generated": datetime.now().isoformat(),
                "tool": "Auto Nmap v3.0",
                "disclaimer": "Severity ratings are BASELINE assessments. Adjust based on your environment.",
            },
            "severity_context": {
                "notice": "These ratings MUST be adjusted based on your specific environment",
                "factors_to_consider": [
                    "Internal vs external network exposure",
                    "Existing controls (firewalls, IDS/IPS, WAF)",
                    "Security controls whitelisted for scanning",
                    "Business context and data sensitivity",
                ],
            },
            "summary": self.findings["summary"],
            "findings": {
                severity: [
                    {
                        "host": f["host"],
                        "hostname": f["hostname"],
                        "finding_key": f["finding_key"],
                        "remediation": remediation_to_dict(f["remediation"]),
                    }
                    for f in self.findings[severity]
                ]
                for severity in ["critical", "high", "medium", "low"]
            },
            "hosts": {
                host: {
                    "hostname": hr.hostname,
                    "state": hr.state,
                    "open_ports": hr.open_ports,
                }
                for host, hr in self.scan_result.hosts.items()
            },
        }

        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=2, default=str)

        logger.info(f"Generated JSON report: {report_file}")
        return str(report_file)

    def generate_csv_reports(self) -> Dict[str, str]:
        """Generate CSV reports for Excel/SIEM import."""
        reports = {}

        # Findings CSV
        findings_file = self.output_dir / f"findings_{self.timestamp}.csv"
        findings_rows = []

        for severity_level in ["critical", "high", "medium", "low", "info"]:
            for finding in self.findings.get(severity_level, []):
                rem = finding["remediation"]
                findings_rows.append({
                    "Host": finding["host"],
                    "Hostname": finding["hostname"] or "",
                    "Finding": rem.title,
                    "Severity": rem.severity.value,
                    "Category": rem.category.value,
                    "CVE": rem.cve or "",
                    "CVSS": rem.cvss_score or "",
                    "Description": rem.description.replace("\n", " ")[:500],
                    "Impact": rem.impact.replace("\n", " ")[:300],
                    "Remediation": " | ".join(rem.remediation_steps[:3]),
                    "References": " | ".join(rem.references[:3]) if rem.references else "",
                })

        if findings_rows:
            fieldnames = ["Host", "Hostname", "Finding", "Severity", "Category",
                         "CVE", "CVSS", "Description", "Impact", "Remediation", "References"]
            with open(findings_file, "w", newline="", encoding="utf-8") as f:
                f.write("# IMPORTANT: Severity ratings are BASELINE assessments. Adjust for your environment.\n")
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(findings_rows)
        else:
            with open(findings_file, "w", newline="", encoding="utf-8") as f:
                f.write("# No findings detected\n")

        reports["csv_findings"] = str(findings_file)

        # Hosts/Ports CSV
        hosts_file = self.output_dir / f"hosts_ports_{self.timestamp}.csv"
        hosts_rows = []

        for host, host_result in sorted(self.scan_result.hosts.items()):
            if host_result.open_ports:
                for port, port_info in sorted(host_result.open_ports.items()):
                    hosts_rows.append({
                        "Host": host,
                        "Hostname": host_result.hostname or "",
                        "State": host_result.state,
                        "Port": port,
                        "Protocol": port_info.get("protocol", "tcp"),
                        "Service": port_info.get("service", "unknown"),
                        "Product": port_info.get("product", ""),
                        "Version": port_info.get("version", ""),
                    })

        fieldnames = ["Host", "Hostname", "State", "Port", "Protocol", "Service", "Product", "Version"]
        with open(hosts_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(hosts_rows)

        reports["csv_hosts"] = str(hosts_file)

        # Summary CSV
        summary_file = self.output_dir / f"summary_{self.timestamp}.csv"
        summary = self.findings["summary"]

        with open(summary_file, "w", newline="", encoding="utf-8") as f:
            f.write("# Scan Summary - BASELINE severity ratings\n")
            writer = csv.writer(f)
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Scan Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
            writer.writerow(["Total Hosts", summary["total_hosts"]])
            writer.writerow(["Hosts with Issues", summary["hosts_with_issues"]])
            writer.writerow(["Critical (Baseline)", summary["critical_count"]])
            writer.writerow(["High (Baseline)", summary["high_count"]])
            writer.writerow(["Medium (Baseline)", summary["medium_count"]])
            writer.writerow(["Low (Baseline)", summary["low_count"]])

        reports["csv_summary"] = str(summary_file)

        logger.info(f"Generated CSV reports")
        return reports

    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report."""
        report_file = self.output_dir / f"security_report_{self.timestamp}.html"
        summary = self.findings["summary"]

        risk_score = min(100, summary["critical_count"] * 40 + summary["high_count"] * 20 + summary["medium_count"] * 10)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {datetime.now().strftime('%Y-%m-%d')}</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e40af, #3b82f6); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; }}
        .disclaimer {{ background: #fffbeb; border: 2px solid #f59e0b; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .disclaimer h3 {{ color: #b45309; margin-top: 0; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }}
        .stat {{ text-align: center; padding: 20px; border-radius: 8px; color: white; }}
        .stat.critical {{ background: #dc2626; }}
        .stat.high {{ background: #ea580c; }}
        .stat.medium {{ background: #d97706; }}
        .stat.low {{ background: #2563eb; }}
        .stat .number {{ font-size: 2em; font-weight: bold; }}
        .finding {{ border: 1px solid #e5e7eb; border-radius: 8px; margin-bottom: 15px; overflow: hidden; }}
        .finding-header {{ background: #f9fafb; padding: 15px; cursor: pointer; }}
        .finding-header:hover {{ background: #f3f4f6; }}
        .finding-body {{ padding: 15px; display: none; border-top: 1px solid #e5e7eb; }}
        .finding.active .finding-body {{ display: block; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 0.8em; margin-right: 5px; }}
        .badge-critical {{ background: #fee2e2; color: #dc2626; }}
        .badge-high {{ background: #ffedd5; color: #ea580c; }}
        .steps {{ background: #f0fdf4; padding: 15px; border-radius: 8px; margin-top: 10px; }}
        .steps ol {{ margin: 0; padding-left: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Hosts Scanned: {summary['total_hosts']} | Issues Found: {summary['hosts_with_issues']}</p>
        </div>

        <div class="disclaimer">
            <h3>⚠️ Important: Severity Rating Context</h3>
            <p><strong>These severity ratings are BASELINE assessments</strong> based on industry standards. 
            Actual risk depends on your specific environment:</p>
            <ul>
                <li><strong>Network Context:</strong> Internal-only services have reduced risk vs. internet-facing</li>
                <li><strong>Security Controls:</strong> Firewalls, IDS/IPS, WAF may block exploitation</li>
                <li><strong>Scanning Notes:</strong> Security controls may have been whitelisted for this scan</li>
                <li><strong>Business Context:</strong> Data sensitivity and system criticality vary</li>
            </ul>
            <p><strong>Recommended:</strong> Review each finding with your security team and adjust severity based on YOUR compensating controls.</p>
        </div>

        <div class="card">
            <h2>Summary</h2>
            <div class="stats">
                <div class="stat critical">
                    <div class="number">{summary['critical_count']}</div>
                    <div>Critical</div>
                </div>
                <div class="stat high">
                    <div class="number">{summary['high_count']}</div>
                    <div>High</div>
                </div>
                <div class="stat medium">
                    <div class="number">{summary['medium_count']}</div>
                    <div>Medium</div>
                </div>
                <div class="stat low">
                    <div class="number">{summary['low_count']}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
"""

        # Add findings sections
        for severity, title, badge_class in [
            ("critical", "Critical Findings", "badge-critical"),
            ("high", "High Findings", "badge-high"),
        ]:
            findings_list = self.findings[severity]
            if findings_list:
                html += f'<div class="card"><h2>{title} ({len(findings_list)})</h2>'
                for finding in findings_list:
                    rem = finding["remediation"]
                    html += f'''
                    <div class="finding" onclick="this.classList.toggle('active')">
                        <div class="finding-header">
                            <span class="badge {badge_class}">{rem.severity.value}</span>
                            {rem.cve or ""} <strong>{rem.title}</strong>
                            <br><small>Host: {finding["host"]}</small>
                        </div>
                        <div class="finding-body">
                            <p><strong>Description:</strong> {rem.description}</p>
                            <p><strong>Impact:</strong> {rem.impact}</p>
                            <div class="steps">
                                <strong>Remediation Steps:</strong>
                                <ol>{"".join(f"<li>{step}</li>" for step in rem.remediation_steps[:5])}</ol>
                            </div>
                        </div>
                    </div>'''
                html += '</div>'

        # Add hosts table
        html += '''
        <div class="card">
            <h2>Discovered Hosts</h2>
            <table>
                <tr><th>Host</th><th>Hostname</th><th>State</th><th>Open Ports</th></tr>
'''
        for host, hr in sorted(self.scan_result.hosts.items()):
            ports = ", ".join(str(p) for p in sorted(hr.open_ports.keys())[:10])
            if len(hr.open_ports) > 10:
                ports += f" (+{len(hr.open_ports)-10} more)"
            html += f'<tr><td>{host}</td><td>{hr.hostname or "-"}</td><td>{hr.state}</td><td>{ports or "-"}</td></tr>'

        html += '''
            </table>
        </div>
        <div style="text-align: center; padding: 20px; color: #6b7280;">
            Generated by Auto Nmap v3.0 | For authorized security testing only
        </div>
    </div>
</body>
</html>'''

        with open(report_file, "w") as f:
            f.write(html)

        logger.info(f"Generated HTML report: {report_file}")
        return str(report_file)


def generate_report(scan_result: ScanResult, output_dir: str = "reports") -> Dict[str, str]:
    """Convenience function to generate all reports."""
    generator = ReportGenerator(scan_result, output_dir=output_dir)
    return generator.generate_all_reports()
