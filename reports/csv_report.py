"""
Huawei Cloud Security Scanner - CSV Report Exporter

Exports scan findings to CSV for spreadsheet analysis.
"""

import csv
import logging
from pathlib import Path
from datetime import datetime

from core.models import ScanResult

logger = logging.getLogger(__name__)


class CSVReportGenerator:
    """Generates CSV report files from scan results."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list[ScanResult]) -> str:
        """
        Generate CSV report file with all findings.
        Returns path to the CSV file.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        csv_path = self.output_dir / f"scan_findings_{timestamp}.csv"

        # Collect all findings from all results
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        # Define CSV columns
        fieldnames = [
            "account_name",
            "account_id",
            "region",
            "service",
            "category",
            "check_id",
            "check_title",
            "severity",
            "status",
            "description",
            "resource_id",
            "resource_name",
            "remediation",
            "reference_url",
            "timestamp",
        ]

        with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for finding in all_findings:
                row = finding.to_dict()
                # Ensure only defined columns are written
                filtered_row = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(filtered_row)

        logger.info(f"CSV report generated: {csv_path} ({len(all_findings)} findings)")
        return str(csv_path)
