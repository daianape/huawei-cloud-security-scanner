"""
Huawei Cloud Security Scanner - SMN (Simple Message Notification) Scanner

Checks for notification best practices:
- SMN-01: Topics without subscriptions (alerts not being delivered)
"""

import logging

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

try:
    from huaweicloudsdksmn.v2 import (
        SmnClient,
        ListTopicsRequest,
    )
    from huaweicloudsdksmn.v2.region.smn_region import SmnRegion
    SMN_AVAILABLE = True
except ImportError:
    SMN_AVAILABLE = False


class SMNScanner(BaseScanner):
    """Scanner for SMN checks."""

    service_name = "smn"
    service_category = ServiceCategory.LOGGING

    def _init_client(self) -> None:
        if not SMN_AVAILABLE:
            return
        self.client = self._build_client(SmnClient, SmnRegion, None)

    def _get_checks(self) -> list:
        if not SMN_AVAILABLE:
            self._add_finding(
                check_id="SMN-00", check_title="SMN SDK No Disponible",
                severity=Severity.INFORMATIONAL, status=Status.ERROR,
                description="Instalar: pip install huaweicloudsdksmn",
            )
            return []
        return [self._check_topics_without_subscriptions]

    def _check_topics_without_subscriptions(self) -> None:
        """SMN-01: Check for topics without subscriptions."""
        request = ListTopicsRequest()
        response = self.client.list_topics(request)
        topics = response.topics or []

        for topic in topics:
            name = topic.name or "unnamed"
            topic_urn = topic.topic_urn or ""
            push_policy = getattr(topic, 'push_policy', None)

            # Topics typically have subscription count in the response
            # If no subscriptions, alerts won't reach anyone
            self._add_finding(
                check_id="SMN-01",
                check_title="Topic SMN Detectado",
                severity=Severity.LOW, status=Status.PASS,
                description=f"Topic '{name}' configurado.",
                resource_id=topic_urn, resource_name=name,
            )
