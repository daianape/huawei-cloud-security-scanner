"""
Huawei Cloud Security Scanner - Authentication Module

Supports two modes:
- Single Account: Direct AK/SK authentication
- Multi Account: Agency-based cross-account delegation (similar to AWS AssumeRole)
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from huaweicloudsdkcore.auth.credentials import BasicCredentials, GlobalCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkiam.v3 import (
    IamClient,
    KeystoneListProjectsRequest,
    CreateTemporaryAccessKeyByAgencyRequest,
    CreateTemporaryAccessKeyByAgencyRequestBody,
    AgencyAuth,
    AgencyAuthIdentity,
    IdentityAssumerole,
)
from huaweicloudsdkiam.v3.region.iam_region import IamRegion

logger = logging.getLogger(__name__)


@dataclass
class AccountCredentials:
    """Holds resolved credentials for a single account scan."""
    access_key: str
    secret_key: str
    security_token: Optional[str] = None
    project_id: Optional[str] = None
    domain_id: Optional[str] = None
    region: str = "la-south-2"
    account_name: str = "default"


@dataclass
class ScanTarget:
    """Represents a target account to be scanned."""
    account_name: str
    credentials: AccountCredentials
    region: str
    project_id: str
    domain_id: Optional[str] = None


class HuaweiCloudAuth:
    """
    Manages authentication for Huawei Cloud Security Scanner.
    
    Single Account Mode:
        Uses AK/SK directly from config.
        
    Multi Account Mode:
        Uses a management account's credentials to assume agencies
        in target accounts, obtaining temporary credentials for each.
    """

    def __init__(self, config: dict):
        self.config = config
        self.mode = config.get("mode", "single")
        self.region = config.get("region", "la-south-2")
        self.targets: list[ScanTarget] = []

    def authenticate(self) -> list[ScanTarget]:
        """
        Resolves authentication and returns a list of ScanTargets.
        In single mode, returns one target.
        In multi mode, returns one target per configured account.
        """
        if self.mode == "single":
            return self._authenticate_single()
        elif self.mode == "multi":
            return self._authenticate_multi()
        else:
            raise ValueError(f"Unknown authentication mode: {self.mode}")

    def _authenticate_single(self) -> list[ScanTarget]:
        """Authenticate using direct AK/SK for a single account."""
        creds_config = self.config.get("credentials", {})
        ak = creds_config.get("access_key")
        sk = creds_config.get("secret_key")
        project_id = self.config.get("project_id")

        if not ak or not sk:
            raise ValueError(
                "Single account mode requires 'access_key' and 'secret_key' in credentials config"
            )

        if not project_id:
            raise ValueError("Single account mode requires 'project_id' in config")

        credentials = AccountCredentials(
            access_key=ak,
            secret_key=sk,
            project_id=project_id,
            region=self.region,
            account_name="single-account",
        )

        # Validate credentials by making a test API call
        if self._validate_credentials(credentials):
            logger.info("Single account authentication successful")
        else:
            raise ConnectionError("Failed to validate credentials against Huawei Cloud API")

        target = ScanTarget(
            account_name=credentials.account_name,
            credentials=credentials,
            region=self.region,
            project_id=project_id,
        )

        self.targets = [target]
        return self.targets

    def _authenticate_multi(self) -> list[ScanTarget]:
        """
        Authenticate using management account, then assume agency
        in each target account to obtain temporary credentials.
        """
        multi_config = self.config.get("multi_account", {})
        mgmt_config = multi_config.get("management_account", {})
        targets_config = multi_config.get("target_accounts", [])

        mgmt_ak = mgmt_config.get("access_key")
        mgmt_sk = mgmt_config.get("secret_key")
        mgmt_domain_id = mgmt_config.get("domain_id")

        if not mgmt_ak or not mgmt_sk or not mgmt_domain_id:
            raise ValueError(
                "Multi account mode requires management_account with "
                "'access_key', 'secret_key', and 'domain_id'"
            )

        if not targets_config:
            raise ValueError("Multi account mode requires at least one target_account configured")

        logger.info(f"Multi-account mode: scanning {len(targets_config)} target accounts")

        targets = []
        for account_cfg in targets_config:
            account_name = account_cfg.get("account_name", "unnamed")
            target_domain_id = account_cfg.get("domain_id")
            agency_name = account_cfg.get("agency_name", "security-scanner-agency")
            project_id = account_cfg.get("project_id")
            region = account_cfg.get("region", self.region)

            try:
                temp_creds = self._assume_agency(
                    mgmt_ak=mgmt_ak,
                    mgmt_sk=mgmt_sk,
                    mgmt_domain_id=mgmt_domain_id,
                    target_domain_id=target_domain_id,
                    agency_name=agency_name,
                )

                credentials = AccountCredentials(
                    access_key=temp_creds["access_key"],
                    secret_key=temp_creds["secret_key"],
                    security_token=temp_creds["security_token"],
                    project_id=project_id,
                    domain_id=target_domain_id,
                    region=region,
                    account_name=account_name,
                )

                target = ScanTarget(
                    account_name=account_name,
                    credentials=credentials,
                    region=region,
                    project_id=project_id,
                    domain_id=target_domain_id,
                )

                targets.append(target)
                logger.info(f"Successfully assumed agency for account: {account_name}")

            except Exception as e:
                logger.error(f"Failed to assume agency for account '{account_name}': {e}")
                continue

        if not targets:
            raise ConnectionError("Failed to authenticate to any target account")

        self.targets = targets
        return self.targets

    def _assume_agency(
        self,
        mgmt_ak: str,
        mgmt_sk: str,
        mgmt_domain_id: str,
        target_domain_id: str,
        agency_name: str,
    ) -> dict:
        """
        Assume an agency in a target account to get temporary credentials.
        This is analogous to AWS STS AssumeRole.

        The agency must be pre-created in the target account with:
        - Trust: the management account's domain_id
        - Permissions: read-only access to the services being scanned
        """
        global_credentials = GlobalCredentials(mgmt_ak, mgmt_sk, mgmt_domain_id)

        iam_client = (
            IamClient.new_builder()
            .with_credentials(global_credentials)
            .with_region(IamRegion.value_of("cn-north-4"))  # IAM is global, use any region
            .build()
        )

        # Build the assume agency request
        assume_role = IdentityAssumerole(
            agency_name=agency_name,
            domain_id=target_domain_id,
        )

        identity = AgencyAuthIdentity(
            methods=["assume_role"],
            assume_role=assume_role,
        )

        auth = AgencyAuth(identity=identity)

        request_body = CreateTemporaryAccessKeyByAgencyRequestBody(auth=auth)

        request = CreateTemporaryAccessKeyByAgencyRequest()
        request.body = request_body

        response = iam_client.create_temporary_access_key_by_agency(request)

        credential = response.credential
        return {
            "access_key": credential.access,
            "secret_key": credential.secret,
            "security_token": credential.securitytoken,
        }

    def _validate_credentials(self, creds: AccountCredentials) -> bool:
        """Validate credentials by listing projects (lightweight API call)."""
        try:
            credentials = BasicCredentials(
                creds.access_key,
                creds.secret_key,
                creds.project_id,
            )

            if creds.security_token:
                credentials.with_security_token(creds.security_token)

            iam_client = (
                IamClient.new_builder()
                .with_credentials(credentials)
                .with_region(IamRegion.value_of(creds.region))
                .build()
            )

            request = KeystoneListProjectsRequest()
            response = iam_client.keystone_list_projects(request)
            return response.projects is not None

        except Exception as e:
            logger.warning(f"Credential validation failed: {e}")
            return False

    @staticmethod
    def get_basic_credentials(target: ScanTarget) -> BasicCredentials:
        """
        Build BasicCredentials object from a ScanTarget.
        Used by scanners to create service clients.
        """
        creds = BasicCredentials(
            target.credentials.access_key,
            target.credentials.secret_key,
            target.project_id,
        )

        if target.credentials.security_token:
            creds.with_security_token(target.credentials.security_token)

        return creds

    @staticmethod
    def get_global_credentials(target: ScanTarget) -> GlobalCredentials:
        """
        Build GlobalCredentials object from a ScanTarget.
        Used for global services like IAM.
        """
        creds = GlobalCredentials(
            target.credentials.access_key,
            target.credentials.secret_key,
            target.credentials.domain_id or "",
        )

        if target.credentials.security_token:
            creds.with_security_token(target.credentials.security_token)

        return creds
