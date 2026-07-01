"""
Huawei Cloud Security Scanner - CTS Scanner

Checks for Cloud Trace Service (audit logging) best practices:
- CTS-01: System tracker not enabled
- CTS-02: Tracker not logging to OBS bucket
- CTS-03: Tracker in error state
"""

import logging

from huaweicloudsdkcts.v3 import (
    CtsClient,
    ListTrackersRequest,
)
from huaweicloudsdkcts.v3.region.cts_region import CtsRegion

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)


class CTSScanner(BaseScanner):
    """Scanner for CTS (Cloud Trace Service) security checks."""

    service_name = "cts"
    service_category = ServiceCategory.LOGGING

    def _init_client(self) -> None:
        """Initialize CTS client."""
        credentials = self._get_basic_credentials()
        self.client = self._build_client(CtsClient, CtsRegion, credentials)

    def _get_checks(self) -> list:
        """Return list of CTS checks to run."""
        return [
            self._check_tracker_enabled,
        ]

    def _check_tracker_enabled(self) -> None:
        """CTS-01/02/03: Check if CTS trackers are enabled and healthy."""
        request = ListTrackersRequest()
        response = self.client.list_trackers(request)
        trackers = response.trackers or []

        if not trackers:
            self._add_finding(
                check_id="CTS-01",
                check_title="No CTS Trackers Configured",
                severity=Severity.HIGH,
                status=Status.FAIL,
                description=(
                    "No Cloud Trace Service trackers are configured. "
                    "API operations are not being audited. "
                    "This is a critical security and compliance gap."
                ),
                resource_id="cts",
                resource_name="Cloud Trace Service",
                remediation=(
                    "Enable CTS system tracker to record all management "
                    "operations on cloud resources."
                ),
                reference_url="https://support.huaweicloud.com/usermanual-cts/cts_03_0001.html",
            )
            return

        for tracker in trackers:
            tracker_name = tracker.tracker_name or "unknown"
            tracker_status = tracker.status if hasattr(tracker, 'status') else None
            bucket_name = tracker.obs_info.bucket_name if hasattr(tracker, 'obs_info') and tracker.obs_info else None

            # Check if tracker is enabled
            if tracker_status and tracker_status == "disabled":
                self._add_finding(
                    check_id="CTS-01",
                    check_title="CTS Tracker Disabled",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Tracker '{tracker_name}' is disabled. "
                        f"Operations are not being logged."
                    ),
                    resource_id=tracker_name,
                    resource_name=tracker_name,
                    remediation="Enable the CTS tracker to resume audit logging.",
                    reference_url="https://support.huaweicloud.com/usermanual-cts/cts_03_0001.html",
                )
            else:
                self._add_finding(
                    check_id="CTS-01",
                    check_title="CTS Tracker Enabled",
                    severity=Severity.HIGH,
                    status=Status.PASS,
                    description=f"Tracker '{tracker_name}' is enabled and logging.",
                    resource_id=tracker_name,
                    resource_name=tracker_name,
                )

            # Check if logging to OBS
            if not bucket_name:
                self._add_finding(
                    check_id="CTS-02",
                    check_title="Tracker Not Logging to OBS",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Tracker '{tracker_name}' is not configured to store "
                        f"traces in an OBS bucket for long-term retention."
                    ),
                    resource_id=tracker_name,
                    resource_name=tracker_name,
                    remediation=(
                        "Configure an OBS bucket for the tracker to ensure "
                        "long-term retention of audit logs beyond 7 days."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-cts/cts_03_0001.html",
                )
            else:
                self._add_finding(
                    check_id="CTS-02",
                    check_title="Tracker Logging to OBS",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    description=(
                        f"Tracker '{tracker_name}' stores logs in OBS bucket '{bucket_name}'."
                    ),
                    resource_id=tracker_name,
                    resource_name=tracker_name,
                )

            # Check tracker health/error state
            if tracker_status and tracker_status == "error":
                self._add_finding(
                    check_id="CTS-03",
                    check_title="Tracker in Error State",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    description=(
                        f"Tracker '{tracker_name}' is in error state. "
                        f"Audit logging may not be functioning correctly."
                    ),
                    resource_id=tracker_name,
                    resource_name=tracker_name,
                    remediation="Check the tracker configuration and fix the error.",
                    reference_url="https://support.huaweicloud.com/usermanual-cts/cts_03_0001.html",
                )
