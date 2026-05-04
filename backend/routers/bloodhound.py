"""
BloodHound Router
Handles BloodHound file upload and analysis endpoints
"""

import logging
import zipfile
import io
from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from typing import Dict, Any, Optional, List
from models.bloodhound_models import BloodHoundAnalyzeRequest, FindingQueryRequest
from services.bloodhound_parser import BloodHoundParser
from services.neo4j_service import Neo4jService

logger = logging.getLogger(__name__)
router = APIRouter()
parser = BloodHoundParser()

# Store latest analysis results (in-memory for now)
latest_findings: Optional[Dict[str, Any]] = None


def merge_findings(all_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge findings from multiple JSON files into a single result."""
    merged = {
        'high_risk': [],
        'medium_risk': [],
        'low_risk': [],
        'summary': {
            'total_nodes': 0,
            'total_edges': 0,
            'high_risk_count': 0,
            'medium_risk_count': 0,
            'low_risk_count': 0,
            'files_processed': 0
        }
    }

    for findings in all_findings:
        merged['high_risk'].extend(findings.get('high_risk', []))
        merged['medium_risk'].extend(findings.get('medium_risk', []))
        merged['low_risk'].extend(findings.get('low_risk', []))

        summary = findings.get('summary', {})
        merged['summary']['total_nodes'] += summary.get('total_nodes', 0)
        merged['summary']['total_edges'] += summary.get('total_edges', 0)
        merged['summary']['files_processed'] += 1

    # Update counts
    merged['summary']['high_risk_count'] = len(merged['high_risk'])
    merged['summary']['medium_risk_count'] = len(merged['medium_risk'])
    merged['summary']['low_risk_count'] = len(merged['low_risk'])

    return merged


@router.post("/upload")
async def upload_bloodhound_file(
    file: UploadFile = File(...),
    project_id: str = Query(None, description="Project ID for data isolation")
):
    """
    Upload and parse a BloodHound JSON or ZIP file.

    Accepts BloodHound collector JSON output or SharpHound ZIP archive
    and extracts security findings.
    """
    logger.info(f"BloodHound file upload received: {file.filename} (project: {project_id or 'NONE'})")

    filename = file.filename.lower()

    if not filename.endswith('.json') and not filename.endswith('.zip'):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a .json or .zip file from BloodHound/SharpHound."
        )

    try:
        content = await file.read()
        global latest_findings

        # Reset SID cache for new parsing session
        parser.reset_sid_cache()

        if filename.endswith('.zip'):
            logger.info("Processing ZIP file")
            # Extract and parse all JSON files from the ZIP
            all_findings = []
            json_contents = []

            with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
                json_files = [f for f in zip_ref.namelist() if f.lower().endswith('.json')]
                logger.info(f"Found {len(json_files)} JSON files in ZIP")

                if not json_files:
                    logger.error("No JSON files found in ZIP")
                    raise HTTPException(
                        status_code=400,
                        detail="No JSON files found in the ZIP archive."
                    )

                # First pass: read all files and build complete SID map
                logger.info("Building SID map from all files...")
                for json_file in json_files:
                    with zip_ref.open(json_file) as f:
                        json_content = f.read().decode('utf-8')
                        json_contents.append(json_content)
                        try:
                            # Build SID map from this file
                            parser.build_sid_map(json_content)
                        except Exception as e:
                            logger.warning(f"Failed to build SID map from {json_file}: {e}")
                            continue

                # Second pass: parse all files with complete SID map
                logger.info(f"Parsing {len(json_contents)} JSON files...")
                for i, json_content in enumerate(json_contents):
                    try:
                        findings = parser.parse_json(json_content)
                        all_findings.append(findings)
                        logger.info(f"Parsed file {i+1}/{len(json_contents)}: {findings['summary'].get('total_edges', 0)} edges found")
                    except ValueError as e:
                        logger.warning(f"Skipped file {i+1} due to parse error: {e}")
                        continue

            if not all_findings:
                logger.error("No valid findings extracted from ZIP")
                raise HTTPException(
                    status_code=400,
                    detail="No valid BloodHound JSON files found in the ZIP archive."
                )

            # Merge all findings
            logger.info("Merging findings from all files...")
            latest_findings = merge_findings(all_findings)
            
            # ✅ ADD: Store the first JSON file content as raw_json
            raw_json_content = json_contents[0] if json_contents else None
            
            summary = latest_findings['summary']
            logger.info(f"Upload complete! Summary: {summary.get('high_risk_count', 0)} high, "
                       f"{summary.get('medium_risk_count', 0)} medium, "
                       f"{summary.get('low_risk_count', 0)} low risk findings")

            return {
                "message": f"BloodHound ZIP processed successfully ({len(all_findings)} files parsed)",
                "filename": file.filename,
                "project_id": project_id,
                "files_processed": len(all_findings),
                "summary": latest_findings['summary'],
                "high_risk_findings": latest_findings['high_risk'],  # ✅ FIXED: Return all findings, not just 5
                "medium_risk_findings": latest_findings['medium_risk'],  # ✅ ADDED: Include medium risk findings
                "low_risk_findings": latest_findings['low_risk'],  # ✅ ADDED: Include low risk findings
                "raw_json": raw_json_content,
                "note": "Use /api/bloodhound/findings to get detailed results"
            }

        else:
            # Single JSON file
            logger.info("Processing single JSON file")
            json_content = content.decode('utf-8')
            # Build SID map first, then parse
            parser.build_sid_map(json_content)
            latest_findings = parser.parse_json(json_content)
            
            summary = latest_findings['summary']
            logger.info(f"JSON file parsed successfully! Summary: {summary.get('high_risk_count', 0)} high, "
                       f"{summary.get('medium_risk_count', 0)} medium, "
                       f"{summary.get('low_risk_count', 0)} low risk findings")

            return {
                "message": "BloodHound file parsed successfully",
                "filename": file.filename,
                "project_id": project_id,
                "summary": latest_findings['summary'],
                "high_risk_findings": latest_findings['high_risk'],  # ✅ FIXED: Return all findings, not just 5
                "medium_risk_findings": latest_findings['medium_risk'],  # ✅ ADDED: Include medium risk findings
                "low_risk_findings": latest_findings['low_risk'],  # ✅ ADDED: Include low risk findings
                "raw_json": json_content,
                "note": "Use /api/bloodhound/findings to get detailed results"
            }

    except zipfile.BadZipFile as e:
        logger.error(f"Invalid ZIP file: {e}")
        raise HTTPException(
            status_code=400,
            detail="Invalid ZIP file. Please upload a valid SharpHound ZIP archive."
        )
    except ValueError as e:
        logger.error(f"ValueError processing file: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error processing BloodHound file: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Error parsing file: {str(e)}"
        )

# ==================== PROJECT DATA MANAGEMENT ENDPOINTS ====================

@router.get("/project/{project_id}/status")
async def get_project_data_status(project_id: str):
    """
    Check if a project has existing BloodHound data in Neo4j.
    
    Returns data status and statistics for the specified project.
    """
    try:
        neo4j_service = Neo4jService()
        status = neo4j_service.check_project_data(project_id)
        neo4j_service.close()
        return status
    except Exception as e:
        logger.error(f"Error checking project data status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/project/{project_id}/clear")
async def clear_project_data(project_id: str, confirm: bool = Query(False)):
    """
    Clear all BloodHound data for a specific project.
    
    This only deletes data tagged with the specified project_id.
    Other projects' data remains untouched.
    
    Args:
        project_id: Project ID to clear
        confirm: Must be True to confirm deletion
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Must set confirm=true to clear project data"
        )
    
    try:
        neo4j_service = Neo4jService()
        result = neo4j_service.clear_project_data(project_id)
        neo4j_service.close()
        
        if result["success"]:
            return {
                "message": f"Project {project_id} data cleared successfully",
                **result
            }
        else:
            raise HTTPException(status_code=500, detail=result.get("error", "Unknown error"))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing project data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze")
async def analyze_bloodhound_json(
    request: BloodHoundAnalyzeRequest,
    project_id: str = Query(None, description="Project ID for data isolation")
):
    """
    Analyze BloodHound JSON content directly.
    
    Accepts JSON as string in request body instead of file upload.
    """
    
    try:
        global latest_findings
        latest_findings = parser.parse_json(request.json_content)
        
        # Apply filter if requested
        if request.filter_edge_type:
            filtered = parser.get_findings_by_edge_type(
                latest_findings,
                request.filter_edge_type
            )
            return {
                "message": "Analysis complete",
                "filter_applied": request.filter_edge_type,
                "project_id": project_id,
                "filtered_findings": filtered,
                "summary": latest_findings['summary']
            }
        
        return {
            "message": "Analysis complete",
            "project_id": project_id,
            "summary": latest_findings['summary'],
            "findings": latest_findings
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error analyzing JSON: {str(e)}"
        )


@router.get("/findings")
async def get_findings(
    risk_level: Optional[str] = None,
    edge_type: Optional[str] = None,
    target: Optional[str] = None
):
    """
    Get findings from the most recent BloodHound analysis.
    
    Query parameters:
    - risk_level: Filter by High, Medium, or Low
    - edge_type: Filter by specific edge type (e.g., AdminTo)
    - target: Filter by target name (partial match)
    """
    
    if latest_findings is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis data available. Upload a BloodHound file first."
        )
    
    results = latest_findings.copy()
    
    # Filter by risk level
    if risk_level:
        risk_key = f"{risk_level.lower()}_risk"
        if risk_key in results:
            results = {
                risk_key: results[risk_key],
                'summary': results['summary']
            }
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid risk level. Use 'High', 'Medium', or 'Low'"
            )
    
    # Filter by edge type
    if edge_type:
        filtered = parser.get_findings_by_edge_type(latest_findings, edge_type)
        return {
            "filter": {"edge_type": edge_type},
            "count": len(filtered),
            "findings": filtered
        }
    
    # Filter by target
    if target:
        filtered = parser.get_attack_paths_to_target(latest_findings, target)
        return {
            "filter": {"target": target},
            "count": len(filtered),
            "findings": filtered
        }
    
    return results


@router.get("/summary")
async def get_summary():
    """
    Get summary statistics from the most recent BloodHound analysis.
    
    Returns counts of nodes, edges, and findings by risk level.
    """
    
    if latest_findings is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis data available. Upload a BloodHound file first."
        )
    
    return {
        "summary": latest_findings['summary'],
        "high_risk_preview": latest_findings['high_risk'][:3]
    }


@router.get("/edge-types")
async def get_edge_types():
    """
    Get list of all edge types found in the most recent analysis.
    
    Returns unique edge types across all risk levels.
    """
    
    if latest_findings is None:
        raise HTTPException(
            status_code=404,
            detail="No analysis data available. Upload a BloodHound file first."
        )
    
    edge_types = set()
    for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
        for finding in latest_findings.get(risk_level, []):
            edge_types.add(finding['edge_type'])
    
    return {
        "edge_types": sorted(list(edge_types)),
        "count": len(edge_types)
    }


@router.delete("/clear")
async def clear_findings():
    """
    Clear the stored findings from memory.
    
    Useful for resetting state between different BloodHound scans.
    """
    
    global latest_findings
    latest_findings = None
    
    return {"message": "Findings cleared successfully"}
