"""
Huawei Cloud Security Scanner - Available Regions

List of all Huawei Cloud regions available for scanning.
"""

# All known Huawei Cloud public regions
HUAWEI_CLOUD_REGIONS = [
    {"region": "cn-north-1", "name": "China North - Beijing 1"},
    {"region": "cn-north-4", "name": "China North - Beijing 4"},
    {"region": "cn-east-2", "name": "China East - Shanghai 2"},
    {"region": "cn-east-3", "name": "China East - Shanghai 3"},
    {"region": "cn-south-1", "name": "China South - Guangzhou"},
    {"region": "cn-south-2", "name": "China South - Shenzhen"},
    {"region": "cn-southwest-2", "name": "China Southwest - Guiyang"},
    {"region": "ap-southeast-1", "name": "Asia Pacific - Hong Kong"},
    {"region": "ap-southeast-2", "name": "Asia Pacific - Bangkok"},
    {"region": "ap-southeast-3", "name": "Asia Pacific - Singapore"},
    {"region": "ap-southeast-4", "name": "Asia Pacific - Jakarta"},
    {"region": "af-south-1", "name": "Africa - Johannesburg"},
    {"region": "sa-brazil-1", "name": "South America - Sao Paulo"},
    {"region": "la-south-2", "name": "Latin America - Santiago"},
    {"region": "la-north-2", "name": "Latin America - Mexico City"},
    {"region": "na-mexico-1", "name": "North America - Mexico"},
    {"region": "eu-west-0", "name": "Europe - Paris"},
    {"region": "eu-west-101", "name": "Europe - Dublin"},
    {"region": "tr-west-1", "name": "Middle East - Istanbul"},
    {"region": "me-east-1", "name": "Middle East - Riyadh"},
    {"region": "my-kualalumpur-1", "name": "Asia Pacific - Kuala Lumpur"},
]

# Just the region codes
ALL_REGION_CODES = [r["region"] for r in HUAWEI_CLOUD_REGIONS]


def get_region_name(region_code: str) -> str:
    """Get the friendly name for a region code."""
    for r in HUAWEI_CLOUD_REGIONS:
        if r["region"] == region_code:
            return r["name"]
    return region_code


def list_regions() -> list[dict]:
    """Return all available regions."""
    return HUAWEI_CLOUD_REGIONS
