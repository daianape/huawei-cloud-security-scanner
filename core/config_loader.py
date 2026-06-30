"""
Huawei Cloud Security Scanner - Configuration Loader

Loads and validates the scanner configuration from YAML files.
Supports environment variable override for sensitive values.
"""

import os
import logging
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load configuration from YAML file.
    
    Priority:
    1. Explicit path passed as argument
    2. Environment variable HWCLOUD_SCANNER_CONFIG
    3. Default: ./config/config.yaml
    
    Environment variables can override credentials:
    - HWCLOUD_AK: Access Key
    - HWCLOUD_SK: Secret Key
    - HWCLOUD_PROJECT_ID: Project ID
    - HWCLOUD_DOMAIN_ID: Domain ID
    - HWCLOUD_REGION: Region
    """
    # Resolve config file path
    if config_path:
        path = Path(config_path)
    elif os.environ.get("HWCLOUD_SCANNER_CONFIG"):
        path = Path(os.environ["HWCLOUD_SCANNER_CONFIG"])
    else:
        path = DEFAULT_CONFIG_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {path}\n"
            f"Copy config.yaml.example to config.yaml and fill in your credentials."
        )

    logger.info(f"Loading configuration from: {path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Override with environment variables if present
    config = _apply_env_overrides(config)

    # Validate configuration
    _validate_config(config)

    return config


def _apply_env_overrides(config: dict) -> dict:
    """Apply environment variable overrides to config."""
    env_ak = os.environ.get("HWCLOUD_AK")
    env_sk = os.environ.get("HWCLOUD_SK")
    env_project = os.environ.get("HWCLOUD_PROJECT_ID")
    env_domain = os.environ.get("HWCLOUD_DOMAIN_ID")
    env_region = os.environ.get("HWCLOUD_REGION")

    if env_ak or env_sk:
        if "credentials" not in config:
            config["credentials"] = {}
        if env_ak:
            config["credentials"]["access_key"] = env_ak
        if env_sk:
            config["credentials"]["secret_key"] = env_sk

    if env_project:
        config["project_id"] = env_project

    if env_domain:
        if "credentials" not in config:
            config["credentials"] = {}
        config["credentials"]["domain_id"] = env_domain

    if env_region:
        config["region"] = env_region

    return config


def _validate_config(config: dict) -> None:
    """Validate that required configuration fields are present."""
    mode = config.get("mode", "single")

    if mode == "single":
        creds = config.get("credentials", {})
        if not creds.get("access_key"):
            raise ValueError("Missing 'credentials.access_key' in config (or set HWCLOUD_AK)")
        if not creds.get("secret_key"):
            raise ValueError("Missing 'credentials.secret_key' in config (or set HWCLOUD_SK)")
        if not config.get("project_id"):
            raise ValueError("Missing 'project_id' in config (or set HWCLOUD_PROJECT_ID)")

    elif mode == "multi":
        multi = config.get("multi_account", {})
        mgmt = multi.get("management_account", {})
        if not mgmt.get("access_key") or not mgmt.get("secret_key"):
            raise ValueError("Multi-account mode requires management_account credentials")
        if not mgmt.get("domain_id"):
            raise ValueError("Multi-account mode requires management_account.domain_id")
        targets = multi.get("target_accounts", [])
        if not targets:
            raise ValueError("Multi-account mode requires at least one target_account")
        for i, target in enumerate(targets):
            if not target.get("domain_id"):
                raise ValueError(f"target_accounts[{i}] missing 'domain_id'")
            if not target.get("project_id"):
                raise ValueError(f"target_accounts[{i}] missing 'project_id'")

    else:
        raise ValueError(f"Unknown mode: '{mode}'. Use 'single' or 'multi'.")

    # Validate region
    if not config.get("region"):
        raise ValueError("Missing 'region' in config (or set HWCLOUD_REGION)")

    logger.info(f"Configuration validated. Mode: {mode}")
