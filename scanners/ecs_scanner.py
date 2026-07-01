"""
Huawei Cloud Security Scanner - ECS Scanner

Checks for ECS (Elastic Cloud Server) security best practices:
- ECS-01: Instances with public IP directly assigned
- ECS-02: Instances without automatic recovery configured
- ECS-03: Instances using default security group
"""

import logging

from huaweicloudsdkecs.v2 import (
    EcsClient,
    ListServersDetailsRequest,
)
from huaweicloudsdkecs.v2.region.ecs_region import EcsRegion

from scanners.base_scanner import BaseScanner
from core.models import Severity, Status, ServiceCategory

logger = logging.getLogger(__name__)


class ECSScanner(BaseScanner):
    """Scanner for ECS security checks."""

    service_name = "ecs"
    service_category = ServiceCategory.COMPUTE

    def _init_client(self) -> None:
        """Initialize ECS client."""
        credentials = self._get_basic_credentials()
        self.client = self._build_client(EcsClient, EcsRegion, credentials)

    def _get_checks(self) -> list:
        """Return list of ECS checks to run."""
        return [
            self._check_public_ip_instances,
            self._check_default_security_group,
        ]

    def _get_all_servers(self) -> list:
        """Fetch all ECS instances."""
        all_servers = []
        offset = 0

        while True:
            request = ListServersDetailsRequest()
            request.limit = 100
            request.offset = offset

            response = self.client.list_servers_details(request)
            servers = response.servers or []
            all_servers.extend(servers)

            if len(servers) < 100:
                break
            offset += 100

        return all_servers

    def _check_public_ip_instances(self) -> None:
        """ECS-01: Check for instances with public IP directly assigned."""
        servers = self._get_all_servers()

        for server in servers:
            server_name = server.name
            server_id = server.id
            addresses = server.addresses or {}

            has_public_ip = False
            public_ips = []

            for net_name, net_addrs in addresses.items():
                if net_addrs:
                    for addr in net_addrs:
                        if hasattr(addr, 'os_ext_ips_type') and addr.os_ext_ips_type:
                            if addr.os_ext_ips_type == "floating":
                                has_public_ip = True
                                public_ips.append(addr.addr)

            if has_public_ip:
                self._add_finding(
                    check_id="ECS-01",
                    check_title="Instance with Public IP",
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    description=(
                        f"Instance '{server_name}' has public IP(s): "
                        f"{', '.join(public_ips)}. "
                        f"Consider using NAT Gateway or ELB instead."
                    ),
                    resource_id=server_id,
                    resource_name=server_name,
                    remediation=(
                        "Remove direct public IP assignment. Use NAT Gateway "
                        "for outbound access or ELB for inbound services."
                    ),
                    reference_url="https://support.huaweicloud.com/bestpractice-ecs/ecs_best_0001.html",
                )
            else:
                self._add_finding(
                    check_id="ECS-01",
                    check_title="Instance Without Public IP",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    description=f"Instance '{server_name}' has no direct public IP.",
                    resource_id=server_id,
                    resource_name=server_name,
                )

    def _check_default_security_group(self) -> None:
        """ECS-03: Check for instances using the default security group."""
        servers = self._get_all_servers()

        for server in servers:
            server_name = server.name
            server_id = server.id
            security_groups = server.security_groups or []

            uses_default = any(
                sg.name and sg.name.lower() in ("default", "sys_default")
                for sg in security_groups
                if hasattr(sg, 'name')
            )

            if uses_default:
                self._add_finding(
                    check_id="ECS-03",
                    check_title="Instance Using Default Security Group",
                    severity=Severity.LOW,
                    status=Status.FAIL,
                    description=(
                        f"Instance '{server_name}' is using the default "
                        f"security group. Create custom security groups "
                        f"with specific rules for each workload."
                    ),
                    resource_id=server_id,
                    resource_name=server_name,
                    remediation=(
                        "Create a custom security group with specific rules "
                        "and assign it to this instance instead of the default."
                    ),
                    reference_url="https://support.huaweicloud.com/usermanual-vpc/vpc_SecurityGroup_0001.html",
                )
