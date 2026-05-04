"""
Remediation Models
Pydantic schemas for remediation endpoints
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class RemediationRequest(BaseModel):
    """Request model for generating remediation for a single finding"""
    
    edge_type: str = Field(
        ...,
        description="BloodHound edge type (e.g., AdminTo, WriteDacl)"
    )
    
    source: str = Field(
        ...,
        description="Source principal (e.g., JOHN.DOE@DOMAIN.LOCAL)"
    )
    
    target: str = Field(
        ...,
        description="Target object (e.g., DC01.DOMAIN.LOCAL)"
    )
    
    source_type: Optional[str] = Field(
        "User",
        description="Type of source (User, Group, Computer)"
    )
    
    target_type: Optional[str] = Field(
        "Computer",
        description="Type of target (Computer, User, Group, Domain)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "edge_type": "AdminTo",
                "source": "JOHN.DOE@DOMAIN.LOCAL",
                "target": "DC01.DOMAIN.LOCAL",
                "source_type": "User",
                "target_type": "Computer"
            }
        }


class BatchRemediationRequest(BaseModel):
    """Request model for generating remediation for multiple findings"""
    
    findings: List[RemediationRequest] = Field(
        ...,
        description="List of findings to generate remediation for"
    )
    
    priority: Optional[str] = Field(
        "high_first",
        description="Priority order: high_first, low_first, as_provided"
    )


class RemediationResponse(BaseModel):
    """Response model for a single remediation"""
    
    finding: dict = Field(
        ...,
        description="Original finding details"
    )
    
    risk_level: str = Field(
        ...,
        description="Risk level: High, Medium, or Low"
    )
    
    explanation: str = Field(
        ...,
        description="Plain English explanation of the vulnerability"
    )
    
    remediation_steps: List[str] = Field(
        ...,
        description="Step-by-step remediation instructions"
    )
    
    powershell_script: str = Field(
        ...,
        description="PowerShell script to fix the issue"
    )
    
    rollback_script: Optional[str] = Field(
        None,
        description="PowerShell script to undo the fix if needed"
    )
    
    mitre_mapping: List[str] = Field(
        ...,
        description="Related MITRE ATT&CK techniques"
    )
    
    detection_methods: List[str] = Field(
        ...,
        description="How to detect if this is being exploited"
    )
    
    warnings: List[str] = Field(
        default=[],
        description="Warnings about potential impact"
    )


class BatchRemediationResponse(BaseModel):
    """Response model for batch remediation"""
    
    total: int = Field(
        ...,
        description="Total number of findings processed"
    )
    
    successful: int = Field(
        ...,
        description="Number of successful remediations generated"
    )
    
    failed: int = Field(
        ...,
        description="Number of failed generations"
    )
    
    remediations: List[RemediationResponse] = Field(
        ...,
        description="List of generated remediations"
    )


class ScriptValidationRequest(BaseModel):
    """Request model for validating a PowerShell script"""
    
    script: str = Field(
        ...,
        description="PowerShell script to validate"
    )


class ScriptValidationResponse(BaseModel):
    """Response model for script validation"""
    
    is_valid: bool = Field(
        ...,
        description="Whether the script syntax is valid"
    )
    
    is_safe: bool = Field(
        ...,
        description="Whether the script is considered safe"
    )
    
    dangerous_commands: List[str] = Field(
        default=[],
        description="List of potentially dangerous commands found"
    )
    
    warnings: List[str] = Field(
        default=[],
        description="Warnings about the script"
    )
    
    suggestions: List[str] = Field(
        default=[],
        description="Suggestions for improvement"
    )