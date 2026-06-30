"""
Huawei Cloud Security Scanner - Data Models

Defines the core data structures for findings, checks, and scan results.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class Status(str, Enum):
    """Status of a security check."""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_AVAILABLE = "not_available"


class ServiceCategory(str, Enum):
    """Service categories for grouping findings."""
    IAM = "IAM"
    NETWORK = "Network"
    COMPUTE = "Compute"
    STORAGE = "Storage"
    LOGGING = "Logging"
    LOAD_BALANCER = "Load Balancer"


@dataclass
class Finding:
    """Represents a single security finding from a check."""
    check_id: str
    check_title: str
    service: str
    category: ServiceCategory
    severity: Severity
    status: Status
    description: str
    resource_id: str = ""
    resource_name: str = ""
    region: str = ""
    account_id: str = ""
    account_name: str = ""
    remediation: str = ""
    reference_url: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "check_id": self.check_id,
            "check_title": self.check_title,
            "service": self.service,
            "category": self.category.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "region": self.region,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "remediation": self.remediation,
            "reference_url": self.reference_url,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanSummary:
    """Summary statistics for a scan run."""
    account_name: str
    account_id: str
    region: str
    scan_start: str = ""
    scan_end: str = ""
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0
    services_scanned: list = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert summary to dictionary."""
        return {
            "account_name": self.account_name,
            "account_id": self.account_id,
            "region": self.region,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "informational_count": self.informational_count,
            "services_scanned": self.services_scanned,
        }

    def calculate_from_findings(self, findings: list[Finding]) -> None:
        """Compute summary statistics from a list of findings."""
        self.total_checks = len(findings)
        self.passed = sum(1 for f in findings if f.status == Status.PASS)
        self.failed = sum(1 for f in findings if f.status == Status.FAIL)
        self.errors = sum(1 for f in findings if f.status == Status.ERROR)
        self.critical_count = sum(
            1 for f in findings if f.severity == Severity.CRITICAL and f.status == Status.FAIL
        )
        self.high_count = sum(
            1 for f in findings if f.severity == Severity.HIGH and f.status == Status.FAIL
        )
        self.medium_count = sum(
            1 for f in findings if f.severity == Severity.MEDIUM and f.status == Status.FAIL
        )
        self.low_count = sum(
            1 for f in findings if f.severity == Severity.LOW and f.status == Status.FAIL
        )
        self.informational_count = sum(
            1 for f in findings if f.severity == Severity.INFORMATIONAL and f.status == Status.FAIL
        )
        self.services_scanned = list(set(f.service for f in findings))


@dataclass
class ScanResult:
    """Complete scan result for one account."""
    summary: ScanSummary
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "summary": self.summary.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
