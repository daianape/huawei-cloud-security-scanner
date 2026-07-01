"""
Huawei Cloud Security Scanner - VPC Scanner

Checks for VPC/Network security best practices:
- VPC-01: Security groups with 0.0.0.0/0 ingress on sensitive ports (22, 3389, 3306, 1433, 5432)
- VPC-02: Security groups with unrestricted egress (0.0.0.0/0 all ports)
- VPC-03: Security groups allowing all traffic (all protocols, all ports)
- VPC-04: Default security group in use with permissive rules
- VPC-05: Security groups with large port ranges
"""

import logging

from huaweicloudsdkvpc.v2 import (
    VpcClient,
    ListSecurityGroupsRequest,
    ListSecurityGroupRulesRequest,
)
from huaweicloudsdkvpc.v2.region.vpc_region import VpcRegion

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)

# Ports commonly targeted in attacks
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    1433: "MSSQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    5900: "VNC",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# CIDR that represents "open to the world"
UNRESTRICTED_CIDRS = ["0.0.0.0/0", "::/0"]


class VPCScanner(BaseScanner):
    """Scanner for VPC security checks."""

    service_name = "vpc"
    service_category = ServiceCategory.NETWORK

    def _init_client(self) -> None:
        """Initialize VPC client."""
        credentials = self._get_basic_credentials()
        builder = (
            VpcClient.new_builder()
            .with_credentials(credentials)
            .with_endpoint(self._get_endpoint("vpc"))
        )
        if self.http_config:
            builder.with_http_config(self.http_config)
        self.client = builder.build()

    def _get_checks(self) -> list:
        """Return list of VPC checks to run."""
        return [
            self._check_open_sensitive_ports,
            self._check_unrestricted_egress,
            self._check_allow_all_traffic,
            self._check_large_port_ranges,
        ]

    def _get_all_security_groups(self) -> list:
        """Fetch all security groups."""
        all_groups = []
        marker = None

        while True:
            request = ListSecurityGroupsRequest()
            request.limit = 100
            if marker:
                request.marker = marker

            response = self.client.list_security_groups(request)
            groups = response.security_groups or []
            all_groups.extend(groups)

            if len(groups) < 100:
                break
            marker = groups[-1].id

        return all_groups

    def _check_open_sensitive_ports(self) -> None:
        """VPC-01: Check security groups with sensitive ports open to 0.0.0.0/0."""
        security_groups = self._get_all_security_groups()

        for sg in security_groups:
            sg_name = sg.name
            sg_id = sg.id
            rules = sg.security_group_rules or []

            for rule in rules:
                # Only check ingress rules
                if rule.direction != "ingress":
                    continue

                # Check if source is unrestricted
                remote_ip_prefix = rule.remote_ip_prefix or ""
                if remote_ip_prefix not in UNRESTRICTED_CIDRS:
                    continue

                # Determine port range
                port_min = rule.port_range_min
                port_max = rule.port_range_max

                # Check for sensitive ports
                exposed_ports = []
                if port_min is None and port_max is None:
                    # All ports open
                    exposed_ports = list(SENSITIVE_PORTS.keys())
                else:
                    port_min = port_min or 0
                    port_max = port_max or 65535
                    for port, service in SENSITIVE_PORTS.items():
                        if port_min <= port <= port_max:
                            exposed_ports.append(port)

                for port in exposed_ports:
                    service_name = SENSITIVE_PORTS[port]
                    self._add_finding(
                        check_id="VPC-01",
                        check_title="Sensitive Port Open to Internet",
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        description=(
                            f"Security group '{sg_name}' allows inbound traffic "
                            f"from {remote_ip_prefix} to port {port} ({service_name}). "
                            f"This exposes the service directly to the internet."
                        ),
                        resource_id=sg_id,
                        resource_name=sg_name,
                        remediation=(
                            f"Restrict access to port {port} ({service_name}) "
                            f"to specific IP ranges or CIDR blocks. "
                            f"Remove the 0.0.0.0/0 rule and add specific source IPs."
                        ),
                        reference_url="https://support.huaweicloud.com/usermanual-vpc/vpc_SecurityGroup_0001.html",
                    )

            # If no violations found for this SG on sensitive ports
            has_sensitive_violation = any(
                f.resource_id == sg_id and f.check_id == "VPC-01" and f.status == Status.FAIL
                for f in self.findings
            )
            if not has_sensitive_violation:
                self._add_finding(
                    check_id="VPC-01",
                    check_title="No Sensitive Ports Exposed",
                    severity=Severity.CRITICAL,
                    status=Status.PASS,
                    description=(
                        f"Security group '{sg_name}' does not expose sensitive ports to the internet."
                    ),
                    resource_id=sg_id,
                    resource_name=sg_name,
                )

    def _check_unrestricted_egress(self) -> None:
        """VPC-02: Check for security groups with unrestricted egress."""
        security_groups = self._get_all_security_groups()

        for sg in security_groups:
            sg_name = sg.name
            sg_id = sg.id
            rules = sg.security_group_rules or []

            unrestricted_egress = False
            for rule in rules:
                if rule.direction != "egress":
                    continue

                remote_ip_prefix = rule.remote_ip_prefix or ""
                port_min = rule.port_range_min
                port_max = rule.port_range_max

                # All ports, all destinations
                if (
                    remote_ip_prefix in UNRESTRICTED_CIDRS
                    and port_min is None
                    and port_max is None
                ):
                    unrestricted_egress = True
                    break

            if unrestricted_egress:
                self._add_finding(
                    check_id="VPC-02",
                    check_title="Unrestricted Egress Rule",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Security group '{sg_name}' allows all outbound traffic "
                        f"to 0.0.0.0/0 on all ports. Consider restricting egress "
                        f"to only required destinations and ports."
                    ),
                    resource_id=sg_id,
                    resource_name=sg_name,
                    remediation=(
                        "Restrict egress rules to only the necessary destinations "
                        "and ports required by your applications."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-vpc/vpc_SecurityGroup_0001.html",
                )
            else:
                self._add_finding(
                    check_id="VPC-02",
                    check_title="Egress Restricted",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    description=f"Security group '{sg_name}' has restricted egress rules.",
                    resource_id=sg_id,
                    resource_name=sg_name,
                )

    def _check_allow_all_traffic(self) -> None:
        """VPC-03: Check for security groups that allow ALL inbound traffic."""
        security_groups = self._get_all_security_groups()

        for sg in security_groups:
            sg_name = sg.name
            sg_id = sg.id
            rules = sg.security_group_rules or []

            allows_all = False
            for rule in rules:
                if rule.direction != "ingress":
                    continue

                remote_ip_prefix = rule.remote_ip_prefix or ""
                port_min = rule.port_range_min
                port_max = rule.port_range_max
                protocol = rule.protocol or ""

                # All protocols, all ports, from anywhere
                if (
                    remote_ip_prefix in UNRESTRICTED_CIDRS
                    and port_min is None
                    and port_max is None
                    and (protocol == "" or protocol is None)
                ):
                    allows_all = True
                    break

            if allows_all:
                self._add_finding(
                    check_id="VPC-03",
                    check_title="Security Group Allows All Inbound",
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    description=(
                        f"Security group '{sg_name}' allows ALL inbound traffic "
                        f"(all protocols, all ports) from 0.0.0.0/0. "
                        f"This is extremely dangerous."
                    ),
                    resource_id=sg_id,
                    resource_name=sg_name,
                    remediation=(
                        "Remove the rule that allows all traffic from 0.0.0.0/0. "
                        "Add specific rules for only the required protocols and ports."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-vpc/vpc_SecurityGroup_0001.html",
                )

    def _check_large_port_ranges(self) -> None:
        """VPC-05: Check for security groups with large port ranges open to internet."""
        security_groups = self._get_all_security_groups()

        LARGE_RANGE_THRESHOLD = 100  # More than 100 ports open is suspicious

        for sg in security_groups:
            sg_name = sg.name
            sg_id = sg.id
            rules = sg.security_group_rules or []

            for rule in rules:
                if rule.direction != "ingress":
                    continue

                remote_ip_prefix = rule.remote_ip_prefix or ""
                if remote_ip_prefix not in UNRESTRICTED_CIDRS:
                    continue

                port_min = rule.port_range_min
                port_max = rule.port_range_max

                if port_min is not None and port_max is not None:
                    port_range = port_max - port_min
                    if port_range > LARGE_RANGE_THRESHOLD:
                        self._add_finding(
                            check_id="VPC-05",
                            check_title="Large Port Range Open to Internet",
                            severity=Severity.HIGH,
                            status=Status.FAIL,
                            description=(
                                f"Security group '{sg_name}' has ports {port_min}-{port_max} "
                                f"({port_range} ports) open to {remote_ip_prefix}. "
                                f"Large port ranges increase the attack surface."
                            ),
                            resource_id=sg_id,
                            resource_name=sg_name,
                            remediation=(
                                "Reduce the port range to only the specific ports needed. "
                                "Avoid opening large ranges to the internet."
                            ),
                            reference_url="https://support.huaweicloud.com/usermanual-vpc/vpc_SecurityGroup_0001.html",
                        )
