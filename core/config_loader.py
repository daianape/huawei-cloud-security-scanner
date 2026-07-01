"""
Huawei Cloud Security Scanner - Configuration Loader

Loads scanner configuration from YAML file (regions, services, output).
Credentials (AK/SK) MUST be provided via environment variables for security.

Environment variables (REQUIRED):
  - HWCLOUD_AK: Access Key
  - HWCLOUD_SK: Secret Key

Environment variables (OPTIONAL - override config file):
  - HWCLOUD_DOMAIN_ID: Domain ID (Account ID)
  - HWCLOUD_PROJECT_ID: Project ID (overrides config file)
  - HWCLOUD_REGION: Region (overrides config file)
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
    Load configuration from YAML file and environment variables.

    - Config file: regions, project_ids, scanners, output settings
    - Environment variables: credentials (AK/SK), domain_id

    Priority for credentials: Environment variables (required)
    Priority for other settings: ENV > config file
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
            f"Copy config.yaml.example to config.yaml and configure your regions."
        )

    logger.info(f"Loading configuration from: {path}")

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    # Load credentials from environment variables
    config = _load_credentials_from_env(config)

    # Apply optional env overrides for region/project
    config = _apply_env_overrides(config)

    # Validate configuration
    _validate_config(config)

    return config


def _load_credentials_from_env(config: dict) -> dict:
    """
    Load AK/SK from environment variables.
    These are REQUIRED and must be set before running the scanner.
    """
    ak = os.environ.get("HWCLOUD_AK", "")
    sk = os.environ.get("HWCLOUD_SK", "")

    if "credentials" not in config:
        config["credentials"] = {}

    if ak:
        config["credentials"]["access_key"] = ak
    if sk:
        config["credentials"]["secret_key"] = sk

    # Domain ID: from config file (not env var)
    domain_id = config.get("domain_id", "")
    config["credentials"]["domain_id"] = domain_id

    # Resolve region and project_id from regions list
    # Use the first region with a non-empty project_id as default
    if not config.get("region") or not config.get("project_id"):
        regions = config.get("regions", [])
        for r in regions:
            if r.get("project_id"):
                if not config.get("region"):
                    config["region"] = r["region"]
                if not config.get("project_id"):
                    config["project_id"] = r["project_id"]
                break

    return config


def _apply_env_overrides(config: dict) -> dict:
    """Apply optional environment variable overrides for region/project."""
    env_project = os.environ.get("HWCLOUD_PROJECT_ID")
    env_region = os.environ.get("HWCLOUD_REGION")
    env_domain = os.environ.get("HWCLOUD_DOMAIN_ID")

    if env_project:
        config["project_id"] = env_project
    if env_region:
        config["region"] = env_region
    if env_domain:
        config["credentials"]["domain_id"] = env_domain

    return config


def _validate_config(config: dict) -> None:
    """Validate that required configuration fields are present."""
    mode = config.get("mode", "single")

    if mode == "single":
        creds = config.get("credentials", {})
        if not creds.get("access_key"):
            raise ValueError(
                "Credenciales no configuradas.\n\n"
                "Configurar variables de entorno antes de ejecutar:\n"
                "  Windows CMD:        set HWCLOUD_AK=tu_access_key\n"
                "                      set HWCLOUD_SK=tu_secret_key\n"
                "  Windows PowerShell: $env:HWCLOUD_AK=\"tu_access_key\"\n"
                "                      $env:HWCLOUD_SK=\"tu_secret_key\"\n"
                "  Linux/Mac:          export HWCLOUD_AK=tu_access_key\n"
                "                      export HWCLOUD_SK=tu_secret_key"
            )
        if not creds.get("secret_key"):
            raise ValueError(
                "Falta el Secret Key (SK).\n"
                "Configurar: set HWCLOUD_SK=tu_secret_key"
            )
        if not config.get("project_id"):
            raise ValueError(
                "Falta 'project_id' en config.yaml.\n"
                "Obtener desde: Huawei Console > My Credentials > API Credentials"
            )

    elif mode == "multi":
        multi = config.get("multi_account", {})
        mgmt = multi.get("management_account", {})
        if not mgmt.get("access_key") or not mgmt.get("secret_key"):
            raise ValueError("Multi-account mode requires management_account credentials via env vars")
        if not mgmt.get("domain_id"):
            raise ValueError("Multi-account mode requires management_account.domain_id")
        targets = multi.get("target_accounts", [])
        if not targets:
            raise ValueError("Multi-account mode requires at least one target_account")

    else:
        raise ValueError(f"Unknown mode: '{mode}'. Use 'single' or 'multi'.")

    # Validate region
    if not config.get("region"):
        raise ValueError("Falta 'region' en config.yaml (o set HWCLOUD_REGION)")

    logger.info(f"Configuration validated. Mode: {mode}")
