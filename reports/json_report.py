"""
Huawei Cloud Security Scanner - JSON Report Exporter

Exports scan results to structured JSON files.
"""

import json
import logging
from pathlib import Path
from datetime import datetime

from core.models import ScanResult

logger = logging.getLogger(__name__)


class JSONReportGenerator:
    """Generates JSON report files from scan results."""

    def __init__(self, output_dir: str = "./output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, results: list[ScanResult]) -> str:
        """
        Generate JSON report files.
        Returns path to the main JSON report.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Full report
        full_report = {
            "scanner": "Huawei Cloud Security Scanner",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat(),
            "results": [r.to_dict() for r in results],
        }

        report_path = self.output_dir / f"scan_report_{timestamp}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(full_report, f, indent=2, ensure_ascii=False)

        # Also write a summary-only file
        summary_report = {
            "scanner": "Huawei Cloud Security Scanner",
            "generated_at": datetime.utcnow().isoformat(),
            "summaries": [r.summary.to_dict() for r in results],
        }

        summary_path = self.output_dir / f"scan_summary_{timestamp}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_report, f, indent=2, ensure_ascii=False)

        logger.info(f"JSON report generated: {report_path}")
        logger.info(f"JSON summary generated: {summary_path}")

        return str(report_path)
