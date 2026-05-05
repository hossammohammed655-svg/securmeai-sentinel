"""
SENTINEL - Network Threat Scanner Engine
Simulates real network scanning with realistic threat detection
"""

import threading
import random
import time
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import json

# ─── Threat Types ────────────────────────────────────────────────────────────

THREAT_SIGNATURES = {
    "BRUTE_FORCE": {
        "label": "Brute Force Attack",
        "level": "CRITICAL",
        "color": "#FF2D55",
        "description": "Multiple failed authentication attempts detected",
        "ports": [22, 3389, 21, 23, 5900],
    },
    "PORT_SCAN": {
        "label": "Port Scan",
        "level": "HIGH",
        "color": "#FF9500",
        "description": "Sequential port probing detected from single source",
        "ports": [80, 443, 8080, 8443],
    },
    "DOS_ATTACK": {
        "label": "DoS / DDoS Attack",
        "level": "CRITICAL",
        "color": "#FF2D55",
        "description": "Abnormal traffic volume suggesting denial-of-service",
        "ports": [80, 443, 53],
    },
    "SQL_INJECTION": {
        "label": "SQL Injection Attempt",
        "level": "HIGH",
        "color": "#FF9500",
        "description": "Malicious SQL patterns detected in HTTP traffic",
        "ports": [80, 443, 8080, 3306],
    },
    "MALWARE_BEACON": {
        "label": "Malware C2 Beacon",
        "level": "CRITICAL",
        "color": "#FF2D55",
        "description": "Periodic outbound connections matching C2 patterns",
        "ports": [4444, 1337, 8888, 9999, 6666],
    },
    "DATA_EXFIL": {
        "label": "Data Exfiltration",
        "level": "CRITICAL",
        "color": "#FF2D55",
        "description": "Unusually large outbound data transfer detected",
        "ports": [443, 21, 22, 25],
    },
    "LATERAL_MOVEMENT": {
        "label": "Lateral Movement",
        "level": "HIGH",
        "color": "#FF9500",
        "description": "Internal host attempting to access multiple systems",
        "ports": [445, 135, 139, 3389],
    },
    "PRIVILEGE_ESCALATION": {
        "label": "Privilege Escalation",
        "level": "HIGH",
        "color": "#FF9500",
        "description": "Abnormal privilege elevation activity detected",
        "ports": [22, 139, 445],
    },
    "ANOMALOUS_TRAFFIC": {
        "label": "Anomalous Traffic",
        "level": "MEDIUM",
        "color": "#FFCC00",
        "description": "Traffic patterns deviating from baseline behavior",
        "ports": [80, 443, 8080],
    },
    "RECON_ACTIVITY": {
        "label": "Reconnaissance Activity",
        "level": "LOW",
        "color": "#34C759",
        "description": "ICMP sweeping or DNS enumeration detected",
        "ports": [53, 161, 389],
    },
}

THREAT_LEVELS = {
    "CRITICAL": {"score": 100, "color": "#FF2D55", "icon": "☠"},
    "HIGH":     {"score": 75,  "color": "#FF9500", "icon": "⚠"},
    "MEDIUM":   {"score": 50,  "color": "#FFCC00", "icon": "⚡"},
    "LOW":      {"score": 25,  "color": "#34C759", "icon": "ℹ"},
    "CLEAN":    {"score": 0,   "color": "#00D4AA", "icon": "✓"},
}

COUNTRIES = ["US", "RU", "CN", "DE", "BR", "KR", "IR", "UA", "IN", "NL", "FR", "GB"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP", "SMB", "DNS", "RDP"]
HOSTNAMES = [
    "smtp.internal", "web01.corp", "db-primary", "api-gateway",
    "file-server", "dc01.local", "backup-01", "dev-workstation",
    "printer-03", "iot-sensor-12", "vpn-gateway", "proxy-01"
]

# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ThreatEvent:
    event_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str
    threat_type: str
    threat_label: str
    level: str
    description: str
    country: str
    packets: int
    bytes_transferred: int
    duration_ms: int
    status: str = "ACTIVE"  # ACTIVE, ISOLATED, BLOCKED, ESCALATED
    hostname: str = ""
    confidence: float = 0.0
    mitre_tactic: str = ""

    def to_dict(self):
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "threat_type": self.threat_type,
            "threat_label": self.threat_label,
            "level": self.level,
            "description": self.description,
            "country": self.country,
            "packets": self.packets,
            "bytes_transferred": self.bytes_transferred,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "hostname": self.hostname,
            "confidence": self.confidence,
            "mitre_tactic": self.mitre_tactic,
        }


MITRE_TACTICS = {
    "BRUTE_FORCE":         "T1110 - Brute Force",
    "PORT_SCAN":           "T1046 - Network Service Scanning",
    "DOS_ATTACK":          "T1498 - Network DoS",
    "SQL_INJECTION":       "T1190 - Exploit Public-Facing App",
    "MALWARE_BEACON":      "T1071 - App Layer Protocol C2",
    "DATA_EXFIL":          "T1041 - Exfiltration Over C2",
    "LATERAL_MOVEMENT":    "T1021 - Remote Services",
    "PRIVILEGE_ESCALATION":"T1068 - Exploitation for Priv Esc",
    "ANOMALOUS_TRAFFIC":   "T1205 - Traffic Signaling",
    "RECON_ACTIVITY":      "T1595 - Active Scanning",
}

# ─── Scanner Engine ───────────────────────────────────────────────────────────

class SentinelScanner:
    def __init__(self):
        self.events: list[ThreatEvent] = []
        self.blocked_ips: set[str] = set()
        self.isolated_ips: set[str] = set()
        self.escalated_ids: set[str] = set()
        self.running = False
        self.scan_thread: Optional[threading.Thread] = None
        self.callbacks: list = []
        self.stats = {
            "total_events": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "blocked": 0,
            "isolated": 0,
            "packets_analyzed": 0,
            "bytes_analyzed": 0,
            "scan_start": None,
        }
        self._event_counter = 0
        self._ip_pool = self._generate_ip_pool()

    def _generate_ip_pool(self):
        """Generate a realistic mix of internal and external IPs."""
        internal = [f"192.168.{r}.{h}" for r in range(1, 5) for h in range(10, 60)]
        external = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    for _ in range(200)]
        return internal + external

    def register_callback(self, cb):
        self.callbacks.append(cb)

    def _fire(self, event_type, data):
        for cb in self.callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def start_scan(self):
        if self.running:
            return
        self.running = True
        self.stats["scan_start"] = datetime.now()
        self.scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.scan_thread.start()
        self._fire("SCAN_STARTED", {})

    def stop_scan(self):
        self.running = False
        self._fire("SCAN_STOPPED", {})

    def _scan_loop(self):
        while self.running:
            # Vary frequency for realism
            sleep_time = random.uniform(0.3, 2.5)
            time.sleep(sleep_time)

            if not self.running:
                break

            # Occasionally generate a burst of events (attack campaign)
            count = random.choices([1, 2, 3], weights=[70, 20, 10])[0]
            for _ in range(count):
                event = self._generate_event()
                if event:
                    self.events.append(event)
                    self._update_stats(event)
                    self._fire("NEW_EVENT", event)

    def _generate_event(self) -> Optional[ThreatEvent]:
        # Weighted threat type selection
        weights = {
            "RECON_ACTIVITY":      15,
            "PORT_SCAN":           12,
            "ANOMALOUS_TRAFFIC":   12,
            "BRUTE_FORCE":         10,
            "SQL_INJECTION":       10,
            "LATERAL_MOVEMENT":    8,
            "PRIVILEGE_ESCALATION":8,
            "DOS_ATTACK":          7,
            "MALWARE_BEACON":      10,
            "DATA_EXFIL":          8,
        }
        threat_types = list(weights.keys())
        threat_weights = list(weights.values())
        threat_type = random.choices(threat_types, weights=threat_weights)[0]
        sig = THREAT_SIGNATURES[threat_type]

        self._event_counter += 1
        event_id = f"EVT-{self._event_counter:06d}"

        src_ip = random.choice(self._ip_pool)
        dst_ip = random.choice(self._ip_pool)
        while dst_ip == src_ip:
            dst_ip = random.choice(self._ip_pool)

        # Skip if blocked
        if src_ip in self.blocked_ips:
            return None

        confidence = round(random.uniform(0.55, 0.99), 2)
        hostname = random.choice(HOSTNAMES) if dst_ip.startswith("192.168") else ""

        packets = random.randint(10, 50000)
        bytes_t = packets * random.randint(64, 1500)

        return ThreatEvent(
            event_id=event_id,
            timestamp=datetime.now(),
            source_ip=src_ip,
            dest_ip=dst_ip,
            source_port=random.randint(1024, 65535),
            dest_port=random.choice(sig["ports"]),
            protocol=random.choice(PROTOCOLS),
            threat_type=threat_type,
            threat_label=sig["label"],
            level=sig["level"],
            description=sig["description"],
            country=random.choice(COUNTRIES),
            packets=packets,
            bytes_transferred=bytes_t,
            duration_ms=random.randint(50, 30000),
            status="ACTIVE",
            hostname=hostname,
            confidence=confidence,
            mitre_tactic=MITRE_TACTICS.get(threat_type, "Unknown"),
        )

    def _update_stats(self, event: ThreatEvent):
        s = self.stats
        s["total_events"] += 1
        s[event.level.lower()] = s.get(event.level.lower(), 0) + 1
        s["packets_analyzed"] += event.packets
        s["bytes_analyzed"] += event.bytes_transferred

    # ─── Actions ───────────────────────────────────────────────────────────────

    def block_ip(self, ip: str) -> dict:
        self.blocked_ips.add(ip)
        self.stats["blocked"] += 1
        for ev in self.events:
            if ev.source_ip == ip and ev.status == "ACTIVE":
                ev.status = "BLOCKED"
        self._fire("IP_BLOCKED", {"ip": ip})
        return {"success": True, "ip": ip, "action": "BLOCKED", "timestamp": datetime.now().isoformat()}

    def isolate_ip(self, ip: str) -> dict:
        self.isolated_ips.add(ip)
        self.stats["isolated"] += 1
        for ev in self.events:
            if ev.source_ip == ip and ev.status == "ACTIVE":
                ev.status = "ISOLATED"
        self._fire("IP_ISOLATED", {"ip": ip})
        return {"success": True, "ip": ip, "action": "ISOLATED", "timestamp": datetime.now().isoformat()}

    def escalate_event(self, event_id: str) -> dict:
        self.escalated_ids.add(event_id)
        for ev in self.events:
            if ev.event_id == event_id:
                ev.status = "ESCALATED"
                self._fire("EVENT_ESCALATED", ev)
                return {"success": True, "event_id": event_id, "event": ev.to_dict()}
        return {"success": False, "error": "Event not found"}

    def unblock_ip(self, ip: str) -> dict:
        self.blocked_ips.discard(ip)
        for ev in self.events:
            if ev.source_ip == ip and ev.status == "BLOCKED":
                ev.status = "ACTIVE"
        self._fire("IP_UNBLOCKED", {"ip": ip})
        return {"success": True, "ip": ip, "action": "UNBLOCKED"}

    def get_events(self, level_filter=None, status_filter=None, limit=200):
        evs = self.events
        if level_filter:
            evs = [e for e in evs if e.level == level_filter]
        if status_filter:
            evs = [e for e in evs if e.status == status_filter]
        return evs[-limit:]

    def get_top_attackers(self, n=10):
        counter = defaultdict(int)
        for ev in self.events:
            counter[ev.source_ip] += 1
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_threat_distribution(self):
        dist = defaultdict(int)
        for ev in self.events:
            dist[ev.level] += 1
        return dict(dist)

    def generate_report(self, report_type="FULL") -> dict:
        """Generate a comprehensive incident report."""
        now = datetime.now()
        duration = ""
        if self.stats["scan_start"]:
            delta = now - self.stats["scan_start"]
            mins = int(delta.total_seconds() // 60)
            secs = int(delta.total_seconds() % 60)
            duration = f"{mins}m {secs}s"

        critical_events = [e for e in self.events if e.level == "CRITICAL"]
        high_events = [e for e in self.events if e.level == "HIGH"]

        top_attackers = self.get_top_attackers(5)
        threat_dist = self.get_threat_distribution()

        # Threat summary by type
        type_counts = defaultdict(int)
        for ev in self.events:
            type_counts[ev.threat_type] += 1

        report = {
            "report_id": f"RPT-{int(time.time())}",
            "generated_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "report_type": report_type,
            "scan_duration": duration,
            "executive_summary": {
                "total_events": self.stats["total_events"],
                "critical": self.stats.get("critical", 0),
                "high": self.stats.get("high", 0),
                "medium": self.stats.get("medium", 0),
                "low": self.stats.get("low", 0),
                "blocked_ips": len(self.blocked_ips),
                "isolated_ips": len(self.isolated_ips),
                "escalated_events": len(self.escalated_ids),
                "packets_analyzed": f"{self.stats['packets_analyzed']:,}",
                "data_analyzed_mb": f"{self.stats['bytes_analyzed'] / 1_048_576:.2f} MB",
            },
            "top_threats": [
                {
                    "threat_type": k,
                    "label": THREAT_SIGNATURES[k]["label"],
                    "count": v,
                    "level": THREAT_SIGNATURES[k]["level"],
                }
                for k, v in sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ],
            "top_attackers": [{"ip": ip, "event_count": cnt} for ip, cnt in top_attackers],
            "blocked_ips": list(self.blocked_ips),
            "isolated_ips": list(self.isolated_ips),
            "critical_events": [e.to_dict() for e in critical_events[-10:]],
            "high_events": [e.to_dict() for e in high_events[-10:]],
            "recommendations": self._generate_recommendations(),
        }
        return report

    def _generate_recommendations(self) -> list:
        recs = []
        stats = self.stats

        if stats.get("critical", 0) > 0:
            recs.append({
                "priority": "CRITICAL",
                "action": "Immediately review all critical events and engage IR team",
                "detail": f"{stats.get('critical',0)} critical events require immediate attention"
            })
        if len(self.blocked_ips) > 0:
            recs.append({
                "priority": "HIGH",
                "action": "Review firewall rules for blocked IPs",
                "detail": f"Verify {len(self.blocked_ips)} IP block(s) are permanent where needed"
            })
        if stats.get("brute_force", 0) or any(e.threat_type == "BRUTE_FORCE" for e in self.events):
            recs.append({
                "priority": "HIGH",
                "action": "Enable account lockout policies and MFA",
                "detail": "Brute force detected — enforce lockout after 5 failed attempts"
            })
        recs.append({
            "priority": "MEDIUM",
            "action": "Update IDS/IPS signatures",
            "detail": "Ensure signature databases are current to improve detection accuracy"
        })
        recs.append({
            "priority": "LOW",
            "action": "Schedule next vulnerability assessment",
            "detail": "Routine scans should occur every 72 hours minimum"
        })
        return recs
