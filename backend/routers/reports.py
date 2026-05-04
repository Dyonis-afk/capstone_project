"""HTTP endpoints for generating and retrieving structured JSON attack-path reports."""

import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import re
import json

# ✅ FIXED: Import the ReportService CLASS and BloodHoundParser properly
from services.report_service import ReportService
from services.bloodhound_parser import BloodHoundParser
from models.tier0_models import Tier0Config, Tier0DomainConfig, Tier0Asset

logger = logging.getLogger(__name__)

# Initialize router (following your pattern)
router = APIRouter()

# ✅ FIXED: Create instances of the service classes
report_service = ReportService()
bloodhound_parser = BloodHoundParser()

# Progress tracking
class ProgressTracker:
    def __init__(self):
        self.progress = {}
    
    def update(self, report_id: str, step: str, percentage: int, message: str = ""):
        self.progress[report_id] = {
            "step": step,
            "percentage": percentage,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        logger.info(f"📊 {report_id}: {step} ({percentage}%) - {message}")
    
    def get(self, report_id: str) -> Dict[str, Any]:
        return self.progress.get(report_id, {})
    
    def complete(self, report_id: str, result: Dict[str, Any]):
        self.progress[report_id] = {
            "step": "completed",
            "percentage": 100,
            "message": "Report generation complete",
            "result": result,
            "timestamp": datetime.now().isoformat()
        }
        logger.info(f"✅ {report_id}: Report generation completed successfully")

# Global progress tracker
progress_tracker = ProgressTracker()

# Request model
class BloodHoundData(BaseModel):
    meta: Optional[Dict[str, Any]] = {}
    nodes: Optional[List[Dict[str, Any]]] = []
    edges: Optional[List[Dict[str, Any]]] = []
    findings: Optional[List[Dict[str, Any]]] = []
    raw_json: Optional[str] = None  # ✅ ADDED: Allow raw JSON for proper parsing
    tier0_config: Optional[Dict[str, Any]] = None  # T0 configuration for classifying findings

@router.post("/generate-report")
async def generate_structured_report(
    background_tasks: BackgroundTasks,
    bloodhound_data: BloodHoundData
):
    """Generate structured security report - JSON-first approach"""
    try:
        # Generate unique report ID
        report_id = f"AEGIS-{uuid.uuid4().hex[:8].upper()}"

        # Parse T0 config if provided
        tier0_config = None
        if bloodhound_data.tier0_config:
            try:
                tier0_config = Tier0Config(**bloodhound_data.tier0_config)
                logger.info(f"🛡️ T0 Config enabled: {tier0_config.get_asset_count()} assets defined")
            except Exception as e:
                logger.warning(f"⚠️ Failed to parse T0 config: {e}")

        logger.info(f"🛡️ Starting structured report generation: {report_id}")

        # Start background task
        background_tasks.add_task(
            generate_report_background,
            report_id,
            bloodhound_data.dict(),
            tier0_config
        )

        # Return immediately with task info
        return {
            "success": True,
            "report_id": report_id,
            "status": "started",
            "message": "Report generation started in background",
            "tier0_enabled": tier0_config is not None and tier0_config.enabled
        }

    except Exception as e:
        logger.error(f"❌ Error starting report generation: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start report generation: {str(e)}")

async def generate_report_background(report_id: str, bloodhound_data: dict, tier0_config: Optional[Tier0Config] = None):
    """Background task for report generation with progress tracking"""

    try:
        # Step 1: Initialize (10%)
        progress_tracker.update(report_id, "initializing", 10, "Initializing report generation...")

        # Log T0 config status
        if tier0_config and tier0_config.enabled:
            t0_count = tier0_config.get_asset_count()
            progress_tracker.update(report_id, "initializing", 15, f"T0 config active: {t0_count} privileged assets defined")
            logger.info(f"🛡️ {report_id}: T0 classification enabled with {t0_count} assets")

        # Step 2: Parse BloodHound data (30%)
        progress_tracker.update(report_id, "parsing", 30, "Parsing BloodHound data...")
        
        # ✅ FIXED: Use your ACTUAL BloodHound parser correctly
        findings = []
        
        if bloodhound_data.get('raw_json'):
            # If we have raw JSON content, parse it properly using your BloodHound parser
            logger.info(f"📊 {report_id}: Using raw JSON content for proper parsing")
            try:
                bloodhound_parser.reset_sid_cache()
                bloodhound_parser.build_sid_map(bloodhound_data['raw_json'])
                parsed_data = bloodhound_parser.parse_json(bloodhound_data['raw_json'])
                
                # Extract findings from parsed data with proper edge types
                findings.extend(parsed_data.get('high_risk', []))
                findings.extend(parsed_data.get('medium_risk', []))
                findings.extend(parsed_data.get('low_risk', []))
                
                logger.info(f"📊 {report_id}: Parsed {len(findings)} findings with edge types: {[f.get('edge_type', 'Missing') for f in findings[:5]]}")
                
            except Exception as e:
                logger.error(f"❌ {report_id}: BloodHound parser failed: {str(e)}")
                # Fallback to direct findings
                findings = bloodhound_data.get('findings', [])
        
        else:
            # Use pre-parsed findings from frontend
            logger.info(f"📊 {report_id}: Using pre-parsed findings from frontend")
            findings = bloodhound_data.get('findings', [])
            
            # Clean up the findings data mapping
            for finding in findings:
                # Map camelCase to snake_case
                if 'edgeType' in finding and 'edge_type' not in finding:
                    finding['edge_type'] = finding['edgeType']
                if 'riskLevel' in finding and 'risk_level' not in finding:
                    finding['risk_level'] = finding['riskLevel']
                if 'sourceType' in finding and 'source_type' not in finding:
                    finding['source_type'] = finding['sourceType']
                if 'targetType' in finding and 'target_type' not in finding:
                    finding['target_type'] = finding['targetType']
        
        # ✅ ADDED: Log what edge types we actually have
        edge_types = [f.get('edge_type', 'Unknown') for f in findings]
        unique_edge_types = list(set(edge_types))
        logger.info(f"📊 {report_id}: Found edge types: {unique_edge_types}")
        
        # Create summary from BloodHound data
        summary = {
            'report_id': report_id,
            'timestamp': datetime.now().isoformat(),
            'domain': extract_domain_name(bloodhound_data),
            'total_findings': len(findings),
            'total_nodes': bloodhound_data.get('meta', {}).get('count', len(bloodhound_data.get('nodes', []))),
            'total_edges': len(bloodhound_data.get('edges', []))
        }

        logger.info(f"📊 {report_id}: Processing {len(findings)} findings for domain {summary['domain']}")

        # Step 3: Generate structured report with T0 classification (90%)
        if tier0_config and tier0_config.enabled:
            progress_tracker.update(report_id, "generating", 50, "Classifying findings and generating analysis (T0 enabled)...")
        else:
            progress_tracker.update(report_id, "generating", 50, "Generating comprehensive security analysis...")

        # ✅ Pass T0 config to report service for classification
        structured_report = report_service.generate_structured_report(summary, findings, tier0_config)

        # Step 4: Convert to professional format (95%)
        progress_tracker.update(report_id, "formatting", 95, "Formatting professional report...")

        # ✅ FIXED: Use the instance, not the module
        professional_report = report_service.convert_to_professional_format(structured_report)

        # Extract T0 stats from structured report
        t0_stats = structured_report.get('tier0_statistics', {})

        # Step 5: Complete (100%)
        progress_tracker.complete(report_id, {
            "structured_report": structured_report,  # New JSON format
            "professional_report": professional_report,  # Compatible format
            "metadata": {
                "generation_time": datetime.now().isoformat(),
                "findings_processed": len(structured_report.get('findings', [])),
                "report_format": "json_structured",
                "domain_extracted": summary['domain'],
                "edge_types_found": unique_edge_types,
                "tier0_enabled": tier0_config is not None and tier0_config.enabled,
                "tier0_assets_count": tier0_config.get_asset_count() if tier0_config else 0,
                "actionable_findings": t0_stats.get('actionable_count', len(structured_report.get('findings', []))),
                "t0_lateral_findings": t0_stats.get('t0_lateral_count', 0)
            }
        })
        
        # ✅ ADDED: Log final report summary for debugging
        logger.info("================================================================================")
        logger.info(f"📄 REPORT GENERATION COMPLETE: {report_id}")
        logger.info("================================================================================")
        logger.info(f"📊 Report Summary:")
        logger.info(f"   - Domain: {summary['domain']}")
        logger.info(f"   - Total Findings: {len(findings)}")
        logger.info(f"   - Processed Findings: {len(structured_report.get('findings', []))}")
        logger.info(f"   - Edge Types: {unique_edge_types}")
        
        stats = structured_report.get('statistics', {})
        logger.info(f"   - High Risk: {stats.get('high_risk', 0)}")
        logger.info(f"   - Medium Risk: {stats.get('medium_risk', 0)}")
        logger.info(f"   - Low Risk: {stats.get('low_risk', 0)}")
        logger.info(f"")
        logger.info(f"📋 Professional Report (JSON):")
        logger.info(json.dumps(professional_report, indent=2))
        logger.info("================================================================================")
        
    except Exception as e:
        logger.error(f"❌ {report_id}: Error in background generation: {str(e)}", exc_info=True)
        progress_tracker.update(report_id, "error", 0, f"Error: {str(e)}")

@router.get("/report-progress/{report_id}")
async def get_report_progress(report_id: str):
    """Get progress status of report generation"""
    
    progress = progress_tracker.get(report_id)
    
    if not progress:
        raise HTTPException(status_code=404, detail="Report ID not found")
    
    return {
        "success": True,
        "report_id": report_id,
        "progress": progress
    }

@router.get("/report/{report_id}")
async def get_generated_report(report_id: str, format: str = "professional"):
    """Get completed report in specified format"""
    
    progress = progress_tracker.get(report_id)
    
    if not progress or progress.get("step") != "completed":
        raise HTTPException(status_code=404, detail="Report not found or not completed")
    
    try:
        result = progress.get("result", {})
        
        if format == "structured":
            # Return raw structured JSON
            return {
                "success": True,
                "report_id": report_id,
                "format": "structured",
                "data": result.get("structured_report", {}),
                "metadata": result.get("metadata", {})
            }
            
        elif format == "markdown":
            # Generate markdown from structured data
            markdown_content = convert_to_markdown(result.get("structured_report", {}))
            return {
                "success": True,
                "report_id": report_id,
                "format": "markdown",
                "content": markdown_content,
                "filename": f"{report_id}_security_report.md"
            }
            
        else:  # format == "professional" (default)
            # Return format compatible with React component
            return {
                "success": True,
                "report_id": report_id,
                "format": "professional",
                "data": result.get("professional_report", {}),
                "metadata": result.get("metadata", {})
            }
            
    except Exception as e:
        logger.error(f"❌ Error retrieving report {report_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error retrieving report: {str(e)}")

def extract_domain_name(bloodhound_data: dict) -> str:
    """Extract domain name from BloodHound data with multiple fallback methods"""
    
    # Method 1: Check if domain is in data directly
    if 'domain' in bloodhound_data:
        return bloodhound_data['domain']
    
    # Method 2: Check meta information
    meta = bloodhound_data.get('meta', {})
    if 'domain' in meta:
        return meta['domain']
    
    # Method 3: Extract from nodes/edges (look for @DOMAIN.LOCAL patterns)
    try:
        # Check nodes
        nodes = bloodhound_data.get('nodes', [])
        for node in nodes[:10]:  # Check first 10 nodes
            name = node.get('name', '')
            if '@' in name:
                domain_match = re.search(r'@([A-Z0-9.-]+)$', name.upper())
                if domain_match:
                    return domain_match.group(1)
        
        # Check edges
        edges = bloodhound_data.get('edges', [])
        for edge in edges[:10]:  # Check first 10 edges
            for key in ['source', 'target']:
                name = edge.get(key, '')
                if '@' in name:
                    domain_match = re.search(r'@([A-Z0-9.-]+)$', name.upper())
                    if domain_match:
                        return domain_match.group(1)
                        
        # Check findings
        findings = bloodhound_data.get('findings', [])
        for finding in findings[:10]:  # Check first 10 findings
            for key in ['source', 'target']:
                name = finding.get(key, '')
                if isinstance(name, str) and '@' in name:
                    domain_match = re.search(r'@([A-Z0-9.-]+)$', name.upper())
                    if domain_match:
                        return domain_match.group(1)
        
    except Exception as e:
        logger.warning(f"Error extracting domain from BloodHound data: {str(e)}")
    
    # Method 4: Default fallback
    logger.warning("Could not extract domain name, using default")
    return "DOMAIN.LOCAL"

def convert_to_markdown(structured_report: Dict[str, Any]) -> str:
    """Convert structured JSON report to markdown format"""
    
    try:
        markdown_parts = []
        metadata = structured_report.get('report_metadata', {})
        
        # Title and metadata
        markdown_parts.append(f"# AEGIS Security Assessment Report")
        markdown_parts.append(f"**Report ID:** {metadata.get('report_id', 'Unknown')}")
        markdown_parts.append(f"**Domain:** {metadata.get('domain_name', 'Unknown')}")
        markdown_parts.append(f"**Generated:** {metadata.get('generated_at', 'Unknown')}")
        markdown_parts.append("")
        
        # Statistics
        stats = structured_report.get('statistics', {})
        markdown_parts.append("## Assessment Statistics")
        markdown_parts.append(f"- **Total Findings:** {stats.get('total_findings', 0)}")
        markdown_parts.append(f"- **High Risk:** {stats.get('high_risk', 0)}")
        markdown_parts.append(f"- **Medium Risk:** {stats.get('medium_risk', 0)}")
        markdown_parts.append(f"- **Low Risk:** {stats.get('low_risk', 0)}")
        markdown_parts.append("")
        
        # Executive Summary
        exec_summary = structured_report.get('executive_summary', {})
        markdown_parts.append("# Executive Summary")
        markdown_parts.append("")
        
        markdown_parts.append("## Overall Security Posture")
        markdown_parts.append(exec_summary.get('overview', 'No overview available'))
        markdown_parts.append("")
        
        # Key Findings
        key_findings = exec_summary.get('key_findings', [])
        if key_findings:
            markdown_parts.append("## Key Findings")
            for i, finding in enumerate(key_findings, 1):
                markdown_parts.append(f"{i}. {finding}")
            markdown_parts.append("")
        
        # Risk Assessment
        risk_data = exec_summary.get('risk_assessment', {})
        markdown_parts.append("## Risk Assessment")
        markdown_parts.append(f"**Overall Risk Level:** {risk_data.get('overall_risk_level', 'Unknown')}")
        markdown_parts.append("")
        markdown_parts.append(risk_data.get('risk_explanation', 'No risk explanation available'))
        markdown_parts.append("")
        
        # Immediate Actions
        actions = exec_summary.get('immediate_actions', [])
        if actions:
            markdown_parts.append("## Immediate Actions Required")
            for i, action in enumerate(actions, 1):
                markdown_parts.append(f"{i}. {action}")
            markdown_parts.append("")
        
        # Detailed Findings
        findings = structured_report.get('findings', [])
        if findings:
            markdown_parts.append("# Detailed Security Findings")
            markdown_parts.append("")
            
            for finding in findings:
                markdown_parts.append(f"## Finding #{finding.get('finding_number', 'Unknown')}: {finding.get('title', 'Unknown')}")
                markdown_parts.append("")
                markdown_parts.append(f"**Risk Level:** {finding.get('risk_level', 'Unknown')}")
                markdown_parts.append(f"**Source:** {finding.get('source', 'Unknown')}")
                markdown_parts.append(f"**Target:** {finding.get('target', 'Unknown')}")
                markdown_parts.append("")
                
                # Explanation
                markdown_parts.append("### Technical Analysis")
                markdown_parts.append(finding.get('explanation', 'No analysis available'))
                markdown_parts.append("")
                
                # Remediation Steps
                remediation_steps = finding.get('remediation_steps', [])
                if remediation_steps:
                    markdown_parts.append("### Remediation Steps")
                    for i, step in enumerate(remediation_steps, 1):
                        markdown_parts.append(f"{i}. {step}")
                    markdown_parts.append("")
                
                # PowerShell Script
                if finding.get('powershell_script'):
                    markdown_parts.append("### PowerShell Remediation Script")
                    markdown_parts.append("```powershell")
                    markdown_parts.append(finding.get('powershell_script'))
                    markdown_parts.append("```")
                    markdown_parts.append("")
                
                # MITRE ATT&CK
                mitre_mapping = finding.get('mitre_mapping', [])
                if mitre_mapping:
                    markdown_parts.append("### MITRE ATT&CK Mapping")
                    for technique in mitre_mapping:
                        markdown_parts.append(f"- {technique}")
                    markdown_parts.append("")
                
                markdown_parts.append("---")
                markdown_parts.append("")
        
        return "\n".join(markdown_parts)
        
    except Exception as e:
        logger.error(f"Error converting to markdown: {str(e)}")
        return f"# Error Generating Markdown Report\n\nError: {str(e)}"