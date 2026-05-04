"""
Tier 0 Configuration Models for AEGIS
Location: backend/models/tier0_models.py

Defines the data structures for Tier 0 asset configuration.
T0 assets are privileged assets (DA, EA, DC, etc.) where
paths between them are expected administrative privileges,
not actionable vulnerabilities.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Optional
from enum import Enum


class Tier0AssetType(str, Enum):
    """Types of Tier 0 assets"""
    USER = "User"
    GROUP = "Group"
    COMPUTER = "Computer"


class Tier0Asset(BaseModel):
    """Individual Tier 0 asset"""
    name: str = Field(..., description="Asset name (e.g., ADMINISTRATOR@DOMAIN.LOCAL)")
    type: Tier0AssetType = Field(..., description="Asset type (User, Group, Computer)")

    class Config:
        extra = 'ignore'  # Ignore extra fields from frontend (domain, autoDetected, reason, etc.)
        json_schema_extra = {
            "example": {
                "name": "DOMAIN ADMINS@CONTOSO.LOCAL",
                "type": "Group"
            }
        }


class Tier0DomainConfig(BaseModel):
    """T0 configuration for a single domain"""
    assets: List[Tier0Asset] = Field(default_factory=list, description="List of T0 assets in this domain")
    excludedMembers: List[str] = Field(default_factory=list, description="Excluded members (frontend compatibility)")

    class Config:
        extra = 'ignore'  # Ignore extra fields from frontend


class Tier0Config(BaseModel):
    """
    Complete Tier 0 configuration for a project.

    This configuration defines which assets are considered Tier 0.
    Paths between T0 assets are classified as "T0 Lateral Movement"
    (expected administrative privileges) rather than actionable findings.
    """
    enabled: bool = Field(default=True, description="Whether T0 classification is enabled")
    skipped: bool = Field(default=False, description="Whether user skipped config (using auto-detected)")
    domains: Dict[str, Tier0DomainConfig] = Field(
        default_factory=dict,
        description="T0 configuration per domain"
    )

    def get_all_asset_names(self) -> List[str]:
        """Get all T0 asset names across all domains (lowercase for comparison)"""
        names = []
        for domain_config in self.domains.values():
            for asset in domain_config.assets:
                names.append(asset.name.upper())
        return names

    def is_t0_asset(self, entity_name: str) -> bool:
        """
        Check if an entity is a T0 asset.

        Uses exact matching including domain to avoid cross-domain false positives.
        For example, ADMINISTRATOR@DOMAIN_A.LOCAL and ADMINISTRATOR@DOMAIN_B.LOCAL
        are treated as different entities.
        """
        if not self.enabled or not entity_name:
            return False

        entity_upper = entity_name.upper().strip()
        t0_names = self.get_all_asset_names()

        # Direct exact match (including domain)
        if entity_upper in t0_names:
            return True

        # Also check without domain suffix for assets that might be referenced differently
        # But ONLY if the entity has no domain AND a T0 asset base name matches
        if '@' not in entity_upper:
            # Entity has no domain - check if any T0 asset's base name matches
            for t0_name in t0_names:
                t0_base = t0_name.split('@')[0] if '@' in t0_name else t0_name
                if entity_upper == t0_base:
                    return True

        return False

    def get_asset_count(self) -> int:
        """Get total count of T0 assets"""
        count = 0
        for domain_config in self.domains.values():
            count += len(domain_config.assets)
        return count

    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "skipped": False,
                "domains": {
                    "CONTOSO.LOCAL": {
                        "assets": [
                            {"name": "DOMAIN ADMINS@CONTOSO.LOCAL", "type": "Group"},
                            {"name": "ENTERPRISE ADMINS@CONTOSO.LOCAL", "type": "Group"},
                            {"name": "DC01@CONTOSO.LOCAL", "type": "Computer"},
                            {"name": "ADMINISTRATOR@CONTOSO.LOCAL", "type": "User"}
                        ]
                    }
                }
            }
        }


class FindingClassification(str, Enum):
    """Classification of a finding"""
    ACTIONABLE = "actionable"  # Real vulnerability requiring remediation
    T0_LATERAL = "t0_lateral"  # Expected T0 privilege, not actionable


class ClassifiedFinding(BaseModel):
    """A finding with T0 classification"""
    classification: FindingClassification = Field(..., description="Whether this is actionable or T0 lateral movement")
    source: str = Field(..., description="Source entity")
    target: str = Field(..., description="Target entity")
    edge_type: str = Field(..., description="Relationship type")
    risk_level: str = Field(default="Medium", description="Risk level")
    source_type: Optional[str] = Field(default=None, description="Source entity type")
    target_type: Optional[str] = Field(default=None, description="Target entity type")
    # Original finding data
    original_finding: Dict = Field(default_factory=dict, description="Original finding data")

    @property
    def is_actionable(self) -> bool:
        return self.classification == FindingClassification.ACTIONABLE

    @property
    def is_t0_lateral(self) -> bool:
        return self.classification == FindingClassification.T0_LATERAL
