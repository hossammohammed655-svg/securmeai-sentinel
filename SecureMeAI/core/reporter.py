"""
SENTINEL - Report Generator
Produces formatted text and JSON reports
"""

from datetime import datetime
from typing import Optional
import json
import os


def format_bytes(b: int) -> str:
    if b >= 1_073_741_824:
        return f"{b/1_073_741_824:.2f} GB"
    if b >= 1_048_576:
        return f"{b/1_048_576:.2f} MB"
    if b >= 1_024:
        return f"{b/1_024:.2f} KB"
    return f"{b} B"


def generate_text_report(report: dict, output_path: Optional[str] = None) -> str:
    """Generate a human-readable incident report."""
    lines = []
    sep = "═" * 72
    thin = "─" * 72

    def h1(title):
        lines.append("")
        lines.append(sep)
        lines.append(f"  {title}")
        lines.append(sep)

    def h2(title):
        lines.append("")
        lines.append(f"  ▶  {title}")
        lines.append(f"  {thin}")

    def row(label, value, width=30):
        lines.append(f"  {label:<{width}} {value}")

    # Header
    lines.append("")
    lines.append("╔" + "═" * 70 + "╗")
    lines.append("║" + "  SENTINEL — CYBERSECURITY INCIDENT RESPONSE REPORT".center(70) + "║")
    lines.append("║" + f"  Report ID: {report['report_id']}".ljust(70) + "║")
    lines.append("║" + f"  Generated: {report['generated_at']}".ljust(70) + "║")
    lines.append("║" + f"  Scan Duration: {report['scan_duration']}".ljust(70) + "║")
    lines.append("╚" + "═" * 70 + "╝")

    # Executive Summary
    h1("EXECUTIVE SUMMARY")
    es = report["executive_summary"]
    row("Total Events Detected:", f"{es['total_events']:,}")
    row("  ► CRITICAL:", str(es["critical"]))
    row("  ► HIGH:", str(es["high"]))
    row("  ► MEDIUM:", str(es["medium"]))
    row("  ► LOW:", str(es["low"]))
    lines.append("")
    row("IPs Blocked:", str(es["blocked_ips"]))
    row("IPs Isolated:", str(es["isolated_ips"]))
    row("Events Escalated:", str(es["escalated_events"]))
    row("Packets Analyzed:", es["packets_analyzed"])
    row("Data Volume Analyzed:", es["data_analyzed_mb"])

    # Top Threats
    h1("TOP THREATS DETECTED")
    for i, t in enumerate(report["top_threats"], 1):
        lines.append(f"  {i}. [{t['level']:<8}] {t['label']:<35} {t['count']} events")

    # Top Attackers
    h1("TOP SOURCE IPs (Attackers)")
    for i, a in enumerate(report["top_attackers"], 1):
        lines.append(f"  {i}. {a['ip']:<20} → {a['event_count']} events")

    # Blocked/Isolated
    h1("RESPONSE ACTIONS TAKEN")
    if report["blocked_ips"]:
        h2("Blocked IPs")
        for ip in report["blocked_ips"]:
            lines.append(f"  [BLOCKED]  {ip}")
    if report["isolated_ips"]:
        h2("Isolated IPs")
        for ip in report["isolated_ips"]:
            lines.append(f"  [ISOLATED] {ip}")

    # Critical Events
    if report["critical_events"]:
        h1("CRITICAL EVENTS (Last 10)")
        for ev in report["critical_events"]:
            lines.append(f"  ┌─ {ev['event_id']} [{ev['timestamp']}]")
            lines.append(f"  │  Threat  : {ev['threat_label']}")
            lines.append(f"  │  Source  : {ev['source_ip']}:{ev['source_port']} ({ev['country']})")
            lines.append(f"  │  Target  : {ev['dest_ip']}:{ev['dest_port']}")
            lines.append(f"  │  Protocol: {ev['protocol']}")
            lines.append(f"  │  MITRE   : {ev['mitre_tactic']}")
            lines.append(f"  │  Status  : {ev['status']}")
            lines.append(f"  └─ Confidence: {ev['confidence']*100:.0f}%")
            lines.append("")

    # Recommendations
    h1("SECURITY RECOMMENDATIONS")
    for i, rec in enumerate(report["recommendations"], 1):
        lines.append(f"  {i}. [{rec['priority']}] {rec['action']}")
        lines.append(f"     {rec['detail']}")
        lines.append("")

    # Footer
    lines.append(sep)
    lines.append("  SENTINEL — Automated Threat Intelligence Platform")
    lines.append(f"  Report generated automatically on {report['generated_at']}")
    lines.append(sep)
    lines.append("")

    text = "\n".join(lines)

    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(text)

    return text


def save_json_report(report: dict, output_path: str):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
