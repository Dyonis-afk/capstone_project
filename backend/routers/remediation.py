"""
Remediation Router
Handles remediation generation endpoints
"""

from fastapi import APIRouter, HTTPException
from typing import Optional
from models.remediation_models import (
    RemediationRequest,
    RemediationResponse,
    BatchRemediationRequest,
    BatchRemediationResponse,
    ScriptValidationRequest,
    ScriptValidationResponse
)
from services.remediation_service import RemediationService

router = APIRouter()

# Initialize remediation service
try:
    remediation_service = RemediationService()
except Exception as e:
    print(f"ERROR: Failed to initialize Remediation service: {e}")
    remediation_service = None


@router.post("/generate", response_model=RemediationResponse)
async def generate_remediation(request: RemediationRequest):
    """
    Generate remediation for a single BloodHound finding.
    
    Produces:
    - Plain English explanation
    - Step-by-step remediation instructions
    - PowerShell script to fix the issue
    - Rollback script to undo changes
    - MITRE ATT&CK mapping
    - Detection methods
    - Safety warnings
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    try:
        result = remediation_service.generate_remediation(
            edge_type=request.edge_type,
            source=request.source,
            target=request.target,
            source_type=request.source_type,
            target_type=request.target_type
        )
        
        return RemediationResponse(
            finding=result['finding'],
            risk_level=result['risk_level'],
            explanation=result['explanation'],
            remediation_steps=result['remediation_steps'],
            powershell_script=result['powershell_script'],
            rollback_script=result.get('rollback_script'),
            mitre_mapping=result['mitre_mapping'],
            detection_methods=result['detection_methods'],
            warnings=result['warnings']
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating remediation: {str(e)}"
        )


@router.post("/batch", response_model=BatchRemediationResponse)
async def generate_batch_remediation(request: BatchRemediationRequest):
    """
    Generate remediation for multiple BloodHound findings.
    
    Supports prioritization:
    - high_first: Process high-risk findings first
    - low_first: Process low-risk findings first
    - as_provided: Process in the order provided
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    try:
        # Convert request findings to dictionary format
        findings = [
            {
                "edge_type": f.edge_type,
                "source": f.source,
                "target": f.target,
                "source_type": f.source_type,
                "target_type": f.target_type
            }
            for f in request.findings
        ]
        
        result = remediation_service.generate_batch_remediation(
            findings=findings,
            priority=request.priority
        )
        
        # Convert results to response model
        remediations = []
        for r in result['remediations']:
            if 'error' not in r:
                remediations.append(RemediationResponse(
                    finding=r['finding'],
                    risk_level=r['risk_level'],
                    explanation=r['explanation'],
                    remediation_steps=r['remediation_steps'],
                    powershell_script=r['powershell_script'],
                    rollback_script=r.get('rollback_script'),
                    mitre_mapping=r['mitre_mapping'],
                    detection_methods=r['detection_methods'],
                    warnings=r['warnings']
                ))
        
        return BatchRemediationResponse(
            total=result['total'],
            successful=result['successful'],
            failed=result['failed'],
            remediations=remediations
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error generating batch remediation: {str(e)}"
        )


@router.post("/validate", response_model=ScriptValidationResponse)
async def validate_script(request: ScriptValidationRequest):
    """
    Validate a PowerShell script for safety.
    
    Checks for:
    - Dangerous commands (Remove-ADObject, Format-, etc.)
    - Risky patterns (-Force, -Confirm:$false)
    - Missing best practices (no -WhatIf, no try/catch)
    
    Returns validation results and suggestions.
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    try:
        result = remediation_service.validate_script(request.script)
        
        return ScriptValidationResponse(**result)
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error validating script: {str(e)}"
        )


@router.get("/quick/{edge_type}")
async def get_quick_remediation(edge_type: str):
    """
    Get quick remediation info for an edge type.
    
    Returns a brief overview without full script generation.
    Useful for quick reference or tooltips.
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    try:
        result = remediation_service.get_quick_remediation(edge_type)
        return result
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error getting quick remediation: {str(e)}"
        )


@router.get("/risk/{edge_type}")
async def get_risk_level(edge_type: str):
    """
    Get the risk level for an edge type.
    
    Returns: High, Medium, or Low
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    risk = remediation_service.assess_risk(edge_type)
    
    return {
        "edge_type": edge_type,
        "risk_level": risk
    }


@router.get("/edge-types")
async def get_edge_type_risks():
    """
    Get risk classification for all known edge types.
    
    Returns lists of high-risk and medium-risk edge types.
    Edge types not in these lists are considered low risk.
    """
    
    if remediation_service is None:
        raise HTTPException(
            status_code=503,
            detail="Remediation service not available"
        )
    
    return {
        "high_risk": list(remediation_service.high_risk_edges),
        "medium_risk": list(remediation_service.medium_risk_edges),
        "note": "Edge types not in these lists are classified as Low risk"
    }
