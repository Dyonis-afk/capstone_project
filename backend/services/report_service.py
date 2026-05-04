"""Builds structured JSON reports from BloodHound findings.

Classifies findings as `actionable` (real misconfigurations) or `t0_lateral`
(expected paths between Tier 0 assets), and generates per-finding explanations
appropriate to each class.
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from .rag_service import RAGService

# Import T0 models - use try/except for backwards compatibility
try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from models.tier0_models import Tier0Config, FindingClassification, ClassifiedFinding
except ImportError:
    Tier0Config = None
    FindingClassification = None
    ClassifiedFinding = None

logger = logging.getLogger(__name__)

class ReportService:
    def __init__(self):
        self.rag_service = RAGService()

    def _classify_finding(self, finding: dict, tier0_config) -> str:
        """
        Classify a finding as 'actionable' or 't0_lateral'.

        T0 lateral movement = both source AND target are Tier 0 assets.
        This represents expected administrative privileges, not vulnerabilities.
        """
        if not tier0_config or not tier0_config.enabled:
            return 'actionable'

        source = finding.get('source', '')
        target = finding.get('target', '')

        source_is_t0 = tier0_config.is_t0_asset(source)
        target_is_t0 = tier0_config.is_t0_asset(target)

        # T0 lateral movement only if BOTH source and target are T0
        if source_is_t0 and target_is_t0:
            return 't0_lateral'

        return 'actionable'

    def _separate_findings(self, findings: List[dict], tier0_config) -> Tuple[List[dict], List[dict]]:
        """
        Separate findings into actionable and T0 lateral movement lists.

        Returns: (actionable_findings, t0_lateral_findings)
        """
        if not tier0_config or not tier0_config.enabled:
            return findings, []

        actionable = []
        t0_lateral = []

        for finding in findings:
            classification = self._classify_finding(finding, tier0_config)
            finding_copy = finding.copy()
            finding_copy['classification'] = classification

            if classification == 't0_lateral':
                t0_lateral.append(finding_copy)
            else:
                actionable.append(finding_copy)

        logger.info(f"🔍 T0 Classification: {len(actionable)} actionable, {len(t0_lateral)} T0 lateral movement")
        return actionable, t0_lateral

    def generate_structured_report(self, summary: dict, findings: List[dict], tier0_config=None) -> Dict[str, Any]:
        """
        Generate a structured security report using JSON-first approach.
        Similar to FarmSafe pattern for clean, reliable data.

        Args:
            summary: Report summary data
            findings: List of findings from BloodHound analysis
            tier0_config: Optional Tier0Config for classifying findings
        """
        try:
            logger.info("🛡️ AEGIS: Starting structured report generation...")

            # Separate findings into actionable and T0 lateral movement
            actionable_findings, t0_lateral_findings = self._separate_findings(findings, tier0_config)

            # Log T0 stats
            t0_enabled = tier0_config is not None and tier0_config.enabled
            if t0_enabled:
                logger.info(f"🛡️ T0 Classification enabled:")
                logger.info(f"   - T0 Assets defined: {tier0_config.get_asset_count()}")
                logger.info(f"   - Actionable findings: {len(actionable_findings)}")
                logger.info(f"   - T0 Lateral Movement: {len(t0_lateral_findings)}")

            # Generate executive summary (only for actionable findings)
            executive_summary = self._generate_executive_summary(
                summary, actionable_findings, t0_lateral_findings, tier0_config
            )

            # Generate detailed findings for ACTIONABLE findings only
            detailed_findings = []
            for i, finding in enumerate(actionable_findings[:10], 1):  # Limit to 10 actionable findings
                logger.info(f"🔍 Processing actionable finding {i}/{min(len(actionable_findings), 10)}: {finding.get('edge_type', 'Unknown')}")
                detailed_finding = self._generate_detailed_finding(finding, i, is_t0_lateral=False)
                if detailed_finding:
                    detailed_findings.append(detailed_finding)

            # Generate simplified findings for T0 lateral movement (if any)
            t0_findings = []
            for i, finding in enumerate(t0_lateral_findings[:10], 1):  # Limit to 10 T0 findings
                logger.info(f"🔍 Processing T0 lateral finding {i}/{min(len(t0_lateral_findings), 10)}: {finding.get('edge_type', 'Unknown')}")
                t0_finding = self._generate_t0_lateral_finding(finding, i)
                if t0_finding:
                    t0_findings.append(t0_finding)

            # Build structured report
            structured_report = {
                "report_metadata": {
                    "report_id": summary.get('report_id', 'AEGIS-UNKNOWN'),
                    "generated_at": summary.get('timestamp', ''),
                    "domain_name": summary.get('domain', 'DOMAIN.LOCAL'),
                    "total_findings": len(findings),
                    "processed_findings": len(detailed_findings),
                    "tier0_enabled": t0_enabled,
                    "tier0_assets_count": tier0_config.get_asset_count() if tier0_config else 0
                },
                "statistics": {
                    "total_findings": len(findings),
                    "actionable_findings": len(actionable_findings),
                    "t0_lateral_findings": len(t0_lateral_findings),
                    "high_risk": sum(1 for f in actionable_findings if f.get('risk_level') == 'High'),
                    "medium_risk": sum(1 for f in actionable_findings if f.get('risk_level') == 'Medium'),
                    "low_risk": sum(1 for f in actionable_findings if f.get('risk_level') == 'Low'),
                    "total_nodes": summary.get('total_nodes', 0),
                    "total_edges": summary.get('total_edges', 0)
                },
                "tier0_statistics": {
                    "enabled": t0_enabled,
                    "assets_count": tier0_config.get_asset_count() if tier0_config else 0,
                    "actionable_count": len(actionable_findings),
                    "t0_lateral_count": len(t0_lateral_findings)
                },
                "executive_summary": executive_summary,
                "findings": detailed_findings,  # Actionable findings only
                "t0_lateral_movement": t0_findings  # T0 lateral movement (expected privileges)
            }

            logger.info(f"✅ AEGIS: Report generation complete")
            logger.info(f"   - Actionable findings processed: {len(detailed_findings)}")
            logger.info(f"   - T0 lateral findings processed: {len(t0_findings)}")
            return structured_report

        except Exception as e:
            logger.error(f"❌ Error generating structured report: {str(e)}")
            return self._get_error_report_structure()

    def _generate_t0_lateral_finding(self, finding: dict, finding_number: int) -> Optional[Dict[str, Any]]:
        """
        Generate a simplified finding for T0 lateral movement.

        T0 lateral movement findings don't need detailed remediation
        because they represent expected administrative privileges.
        """
        edge_type = finding.get('edge_type', 'Unknown')
        source = finding.get('source', 'Unknown')
        target = finding.get('target', 'Unknown')

        # Generate simple explanation without remediation urgency
        query = f"""This is a Tier 0 lateral movement path - an expected administrative privilege between two high-privilege assets.

Source: {source}
Target: {target}
Relationship: {edge_type}

Provide a brief JSON response explaining why this is expected and NOT a vulnerability:
{{
    "title": "T0 Lateral Movement: {edge_type}",
    "explanation": "Brief explanation of why this relationship between T0 assets is expected (2-3 sentences, 50-80 words)",
    "blast_radius_note": "Brief note about blast radius if this path were compromised (1-2 sentences, 30-50 words)"
}}

IMPORTANT: This is NOT a vulnerability. Frame it as expected administrative privilege.
Return ONLY valid JSON, no markdown."""

        try:
            raw_result = self.rag_service.query_fast(query)['result']
            json_text = self._extract_json_from_response(raw_result)

            if json_text:
                finding_data = json.loads(json_text)
                return {
                    'finding_number': finding_number,
                    'classification': 't0_lateral',
                    'edge_type': edge_type,
                    'source': source,
                    'target': target,
                    'risk_level': 'T0 Expected',
                    'title': finding_data.get('title', f"T0 Lateral Movement: {edge_type}"),
                    'explanation': finding_data.get('explanation', f"This {edge_type} relationship between {source} and {target} represents expected administrative privilege within the Tier 0 boundary."),
                    'blast_radius_note': finding_data.get('blast_radius_note', 'If compromised, attacker would have access to other T0 assets.')
                }
        except Exception as e:
            logger.warning(f"⚠️ Error generating T0 finding {finding_number}: {e}")

        # Return minimal finding on error
        return {
            'finding_number': finding_number,
            'classification': 't0_lateral',
            'edge_type': edge_type,
            'source': source,
            'target': target,
            'risk_level': 'T0 Expected',
            'title': f"T0 Lateral Movement: {edge_type}",
            'explanation': f"This {edge_type} relationship between {source} and {target} represents expected administrative privilege within the Tier 0 boundary.",
            'blast_radius_note': 'If compromised, attacker would have access to other T0 assets.'
        }

    def _generate_executive_summary(self, summary: dict, actionable_findings: List[dict],
                                     t0_lateral_findings: List[dict] = None, tier0_config=None) -> Dict[str, Any]:
        """Generate structured executive summary using RAG.

        Args:
            summary: Report summary data
            actionable_findings: Findings that require remediation
            t0_lateral_findings: T0 lateral movement findings (expected privileges)
            tier0_config: Tier 0 configuration object
        """

        # Build context for RAG (only actionable findings)
        t0_lateral_findings = t0_lateral_findings or []
        high_risk_findings = [f for f in actionable_findings if f.get('risk_level') == 'High']
        edge_types = list(set(f.get('edge_type', 'Unknown') for f in actionable_findings))

        # T0 context for the summary
        t0_context = ""
        if tier0_config and tier0_config.enabled and t0_lateral_findings:
            t0_count = len(t0_lateral_findings)
            t0_assets = tier0_config.get_asset_count()
            t0_context = f"""
        TIER 0 CLASSIFICATION ACTIVE:
        - {t0_assets} privileged assets defined as Tier 0 (Domain Admins, Enterprise Admins, DCs, etc.)
        - {t0_count} paths between T0 assets classified as expected administrative privileges
        - These T0 paths are shown separately and NOT counted as actionable findings
        - Focus on the {len(actionable_findings)} ACTIONABLE findings requiring remediation"""

        # Get GraphRAG global context for strategic overview
        graph_strategic_context = ""
        if hasattr(self.rag_service, 'graphrag') and self.rag_service.graphrag:
            try:
                import asyncio
                # Run async global query synchronously
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    global_result = loop.run_until_complete(
                        self.rag_service.graphrag.global_query(
                            f"Provide a strategic security assessment for an Active Directory environment "
                            f"with these attack vectors: {', '.join(edge_types[:5])}"
                        )
                    )
                    if global_result.get('result'):
                        graph_strategic_context = f"""
        STRATEGIC CONTEXT (from knowledge graph):
        {global_result['result'][:1500]}"""
                        logger.info("Added GraphRAG strategic context to executive summary")
                finally:
                    loop.close()
            except Exception as e:
                logger.debug(f"GraphRAG executive context failed: {e}")

        query = f"""Generate an executive summary for Active Directory security assessment in the following JSON format:
        {{
            "overview": "Comprehensive security assessment overview for {summary.get('domain', 'the domain')} environment. Explain overall security posture, critical vulnerabilities discovered, and business impact. Use clear, executive-friendly language. (300-400 words)",
            "key_findings": [
                "Critical finding 1 with business context (50-80 words)",
                "Critical finding 2 with business context (50-80 words)",
                "Critical finding 3 with business context (50-80 words)"
            ],
            "risk_assessment": {{
                "overall_risk_level": "Critical/High/Medium/Low",
                "risk_explanation": "Clear explanation of why this risk level was assigned (100-150 words)",
                "business_impact": "Specific business impacts and potential losses (100-150 words)"
            }},
            "immediate_actions": [
                "Action 1 - highest priority remediation (50-80 words)",
                "Action 2 - critical security measure (50-80 words)",
                "Action 3 - essential safeguard (50-80 words)"
            ],
            "recommendations": [
                "Strategic recommendation 1 (50-80 words)",
                "Strategic recommendation 2 (50-80 words)",
                "Strategic recommendation 3 (50-80 words)"
            ]
        }}

        CONTEXT:
        - Domain: {summary.get('domain', 'Unknown')}
        - Actionable findings requiring remediation: {len(actionable_findings)}
        - High-risk findings: {len(high_risk_findings)}
        - Attack vectors found: {', '.join(edge_types[:5])}{t0_context}{graph_strategic_context}

        CRITICAL FORMATTING:
        - Keep inline permissions together: "Owns, WriteDacl, WriteOwner" (NOT on separate lines)
        - Use executive-friendly language, not technical jargon
        - Focus on business impact and risk, not just technical details
        - Provide actionable guidance for leadership
        
        CRITICAL: Return ONLY valid JSON. Do NOT wrap in markdown code blocks. Do NOT include any markdown formatting. Return pure JSON that can be parsed directly with json.loads()."""

        try:
            raw_result = self.rag_service.query(query)['result']
            logger.info(f"📊 Generated executive summary ({len(raw_result)} characters)")
            logger.debug(f"Raw response preview: {raw_result[:500]}...")
            
            # Extract JSON from response (might be wrapped in markdown code blocks)
            json_text = self._extract_json_from_response(raw_result)
            
            if not json_text:
                logger.error("❌ No JSON found in executive summary response")
                logger.error(f"Response preview: {raw_result[:1000]}")
                raise ValueError("No valid JSON found in response")
            
            # Parse and validate JSON
            summary_data = json.loads(json_text)
            logger.info("✅ Successfully parsed executive summary JSON")
            
            # Clean and validate structure
            validated_summary = {
                'overview': summary_data.get('overview', 'Unable to generate overview'),
                'key_findings': summary_data.get('key_findings', [])[:3],
                'risk_assessment': {
                    'overall_risk_level': summary_data.get('risk_assessment', {}).get('overall_risk_level', 'Medium'),
                    'risk_explanation': summary_data.get('risk_assessment', {}).get('risk_explanation', 'Risk assessment unavailable'),
                    'business_impact': summary_data.get('risk_assessment', {}).get('business_impact', 'Impact assessment unavailable')
                },
                'immediate_actions': summary_data.get('immediate_actions', [])[:3],
                'recommendations': summary_data.get('recommendations', [])[:3]
            }
            
            return validated_summary
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error in executive summary: {str(e)}")
            logger.error(f"Response that failed to parse: {raw_result[:2000] if 'raw_result' in locals() else 'N/A'}")
            # Try to extract some useful information from the raw response even if JSON parsing fails
            if 'raw_result' in locals() and raw_result:
                logger.info("🔄 Attempting to extract content from failed JSON response...")
                fallback_summary = self._extract_fallback_summary(raw_result, summary, findings)
                if fallback_summary:
                    logger.info("✅ Successfully extracted fallback summary")
                    return fallback_summary
        except Exception as e:
            logger.error(f"❌ Error generating executive summary: {str(e)}", exc_info=True)
            # Try fallback extraction if we have raw_result
            if 'raw_result' in locals() and raw_result:
                logger.info("🔄 Attempting fallback extraction after exception...")
                fallback_summary = self._extract_fallback_summary(raw_result, summary, findings)
                if fallback_summary:
                    logger.info("✅ Successfully extracted fallback summary")
                    return fallback_summary
        
        # Return default structure only if all else fails
        logger.warning("⚠️ Using default executive summary structure")
        t0_note = ""
        if tier0_config and tier0_config.enabled and t0_lateral_findings:
            t0_note = f" Additionally, {len(t0_lateral_findings)} paths between Tier 0 assets were identified as expected administrative privileges and are shown separately."
        return {
            'overview': f"Security assessment for {summary.get('domain', 'the domain')} identified {len(actionable_findings)} actionable security findings, including {len([f for f in actionable_findings if f.get('risk_level') == 'High'])} high-risk vulnerabilities. Immediate remediation is recommended to reduce attack surface and prevent potential domain compromise.{t0_note}",
            'key_findings': [
                f"Found {len([f for f in actionable_findings if f.get('risk_level') == 'High'])} high-risk vulnerabilities requiring immediate attention",
                f"Identified {len(set(f.get('edge_type', 'Unknown') for f in actionable_findings))} different attack vector types",
                "Active Directory security posture requires improvement to prevent lateral movement and privilege escalation"
            ][:3],
            'risk_assessment': {
                'overall_risk_level': 'High' if len([f for f in actionable_findings if f.get('risk_level') == 'High']) > 0 else 'Medium',
                'risk_explanation': f"Assessment identified {len(actionable_findings)} actionable security findings across the domain. High-risk vulnerabilities pose immediate threats to domain security and should be addressed promptly.",
                'business_impact': 'Unauthorized access could lead to data breaches, compliance violations, and operational disruption. Immediate action is required to secure critical infrastructure.'
            },
            'immediate_actions': [
                "Review and remediate all high-risk findings identified in this assessment",
                "Implement monitoring and detection for identified attack vectors",
                "Conduct regular security assessments to maintain security posture"
            ][:3],
            'recommendations': [
                "Establish a regular security assessment schedule",
                "Implement automated monitoring for Active Directory changes",
                "Provide security awareness training for IT staff"
            ][:3]
        }
    
    def _extract_fallback_summary(self, raw_response: str, summary: dict, findings: List[dict]) -> Optional[Dict[str, Any]]:
        """Extract useful information from raw response even if JSON parsing fails."""
        import re
        
        try:
            # Try to extract key information using regex patterns
            overview_match = re.search(r'(?:overview|summary|assessment)[":\s]*([^,}]+)', raw_response, re.IGNORECASE)
            risk_match = re.search(r'(?:risk_level|overall_risk)[":\s]*["\']?([^,"\']+)["\']?', raw_response, re.IGNORECASE)
            
            # Build a basic summary from extracted data
            extracted_overview = overview_match.group(1).strip() if overview_match else None
            
            # Count findings by risk level
            high_risk_count = len([f for f in findings if f.get('risk_level') == 'High'])
            medium_risk_count = len([f for f in findings if f.get('risk_level') == 'Medium'])
            low_risk_count = len([f for f in findings if f.get('risk_level') == 'Low'])
            
            # Determine risk level
            if high_risk_count > 0:
                overall_risk = 'High'
            elif medium_risk_count > 0:
                overall_risk = 'Medium'
            else:
                overall_risk = 'Low'
            
            # Use extracted risk level if found, otherwise use calculated
            if risk_match:
                risk_text = risk_match.group(1).strip()
                if risk_text.lower() in ['critical', 'high', 'medium', 'low']:
                    overall_risk = risk_text.capitalize()
            
            return {
                'overview': extracted_overview or f"Security assessment for {summary.get('domain', 'the domain')} identified {len(findings)} security findings requiring attention.",
                'key_findings': [
                    f"Identified {high_risk_count} high-risk vulnerabilities",
                    f"Found {medium_risk_count} medium-risk findings",
                    f"Discovered {low_risk_count} low-risk issues"
                ][:3],
                'risk_assessment': {
                    'overall_risk_level': overall_risk,
                    'risk_explanation': f"Assessment identified {len(findings)} security findings. {high_risk_count} high-risk vulnerabilities require immediate remediation.",
                    'business_impact': 'Security vulnerabilities pose risks to data integrity, compliance, and operational continuity.'
                },
                'immediate_actions': [
                    "Prioritize remediation of high-risk findings",
                    "Implement security monitoring",
                    "Review and update security policies"
                ][:3],
                'recommendations': [
                    "Regular security assessments",
                    "Enhanced monitoring and detection",
                    "Security awareness training"
                ][:3]
            }
        except Exception as e:
            logger.warning(f"⚠️ Fallback extraction also failed: {str(e)}")
            return None

    def _generate_detailed_finding(self, finding: dict, finding_number: int, is_t0_lateral: bool = False) -> Optional[Dict[str, Any]]:
        """Generate detailed finding analysis using RAG.

        Args:
            finding: The finding data
            finding_number: Finding number for the report
            is_t0_lateral: Whether this is a T0 lateral movement finding (not used here, T0 uses _generate_t0_lateral_finding)
        """
        edge_type = finding.get('edge_type', 'Unknown')
        source = finding.get('source', 'Unknown')
        target = finding.get('target', 'Unknown')
        
        query = f"""Analyze this Active Directory security finding and provide detailed information in the following JSON format:
        {{
            "finding_metadata": {{
                "number": {finding_number},
                "edge_type": "{edge_type}",
                "source": "{source}",
                "target": "{target}",
                "risk_level": "High/Medium/Low",
                "severity_score": "number from 1-10"
            }},
            "analysis": {{
                "title": "Clear, descriptive title for this vulnerability (10-15 words)",
                "explanation": "Comprehensive technical explanation of the vulnerability, why it exists, what it means for security, and how attackers could exploit it. Use clear language that junior analysts can understand. (400-500 words)",
                "attack_scenario": "Step-by-step attack scenario showing how this could be exploited (200-300 words)",
                "business_impact": "Specific business risks and potential consequences (150-200 words)"
            }},
            "remediation": {{
                "steps": [
                    "Step 1: Detailed remediation action with specific instructions (100-150 words)",
                    "Step 2: Detailed remediation action with specific instructions (100-150 words)",
                    "Step 3: Detailed remediation action with specific instructions (100-150 words)"
                ],
                "powershell_script": "Complete, production-ready PowerShell script with error handling and comments. Include realistic domain/account names from the finding context.",
                "rollback_script": "Complete PowerShell script to revert changes if needed",
                "verification": "How to verify the fix worked (100-150 words)"
            }},
            "security_details": {{
                "mitre_mapping": ["T1078.002", "T1134.001"],
                "detection_methods": [
                    "Detection method 1 with specific event IDs and log sources (80-120 words)",
                    "Detection method 2 with specific event IDs and log sources (80-120 words)",
                    "Detection method 3 with specific event IDs and log sources (80-120 words)"
                ],
                "warnings": [
                    "Critical warning 1 about potential service disruption (60-100 words)",
                    "Critical warning 2 about prerequisites or dependencies (60-100 words)",
                    "Critical warning 3 about testing requirements (60-100 words)"
                ]
            }}
        }}
        
        FINDING DETAILS:
        - Edge Type: {edge_type}
        - Source: {source}
        - Target: {target}
        - Risk Level: {finding.get('risk_level', 'Medium')}
        
        CRITICAL REQUIREMENTS:
        - Keep inline code together: use "Owns, WriteDacl, WriteOwner" NOT separate lines
        - Provide realistic PowerShell with actual cmdlets and parameters
        - Focus on defensive security (remediation, not exploitation)
        - Use domain-specific names from the finding context
        - Ensure all scripts are production-ready with error handling

        CRITICAL: Return ONLY valid JSON. Do NOT wrap in markdown code blocks. Do NOT include any markdown formatting. Return pure JSON that can be parsed directly with json.loads()."""

        # Add entity context from GraphRAG if available
        graph_entity_context = ""
        if hasattr(self.rag_service, 'graphrag') and self.rag_service.graphrag:
            try:
                # Get entity context for the edge type (attack technique)
                entity_ctx = self.rag_service.graphrag.get_entity_context(edge_type)
                if entity_ctx:
                    graph_entity_context = f"""

        KNOWLEDGE GRAPH CONTEXT for {edge_type}:
        - Description: {entity_ctx.get('description', '')[:500]}
        - Entity Type: {entity_ctx.get('type', 'Unknown')}
        - Related Concepts: {', '.join([r.get('target', '') for r in entity_ctx.get('relationships', [])[:5]])}

        Use this context to provide more accurate and comprehensive analysis."""
                    logger.debug(f"Added GraphRAG entity context for {edge_type}")
            except Exception as e:
                logger.warning(f"Failed to get GraphRAG entity context: {e}")

        # Insert graph context into query if available
        if graph_entity_context:
            query = query.replace(
                "CRITICAL REQUIREMENTS:",
                f"{graph_entity_context}\n\n        CRITICAL REQUIREMENTS:"
            )

        try:
            raw_result = self.rag_service.query(query)['result']
            logger.info(f"📝 Raw RAG response for finding {finding_number} ({len(raw_result)} characters)")
            logger.debug(f"Raw response preview: {raw_result[:500]}...")
            
            # Extract JSON from response (might be wrapped in markdown code blocks)
            json_text = self._extract_json_from_response(raw_result)
            
            if not json_text:
                logger.error(f"❌ No JSON found in response for finding {finding_number}")
                logger.error(f"Response preview: {raw_result[:1000]}")
                return None
            
            # Parse and validate JSON
            finding_data = json.loads(json_text)
            logger.info(f"✅ Successfully parsed JSON for finding {finding_number}")
            
            # Clean and validate structure
            validated_finding = {
                'finding_number': finding_number,
                'edge_type': edge_type,
                'source': source,
                'target': target,
                'risk_level': finding_data.get('finding_metadata', {}).get('risk_level', finding.get('risk_level', 'Medium')),
                'severity_score': float(finding_data.get('finding_metadata', {}).get('severity_score', 5)),
                
                'title': finding_data.get('analysis', {}).get('title', f"{edge_type} Vulnerability"),
                'explanation': finding_data.get('analysis', {}).get('explanation', 'Analysis unavailable'),
                'attack_scenario': finding_data.get('analysis', {}).get('attack_scenario', 'Attack scenario unavailable'),
                'business_impact': finding_data.get('analysis', {}).get('business_impact', 'Impact assessment unavailable'),
                
                'remediation_steps': finding_data.get('remediation', {}).get('steps', [])[:3],
                'powershell_script': finding_data.get('remediation', {}).get('powershell_script', '# PowerShell script unavailable'),
                'rollback_script': finding_data.get('remediation', {}).get('rollback_script', '# Rollback script unavailable'),
                'verification': finding_data.get('remediation', {}).get('verification', 'Verification steps unavailable'),
                
                'mitre_mapping': finding_data.get('security_details', {}).get('mitre_mapping', [])[:3],
                'detection_methods': finding_data.get('security_details', {}).get('detection_methods', [])[:3],
                'warnings': finding_data.get('security_details', {}).get('warnings', [])[:3]
            }
            
            return validated_finding
            
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error for finding {finding_number}: {str(e)}")
            logger.error(f"Response that failed to parse: {raw_result[:2000] if 'raw_result' in locals() else 'N/A'}")
        except Exception as e:
            logger.error(f"❌ Error generating finding {finding_number}: {str(e)}", exc_info=True)
        
        return None
    
    def _extract_json_from_response(self, response: str) -> Optional[str]:
        """
        Extract JSON from RAG response.
        Handles cases where JSON might be wrapped in markdown code blocks.
        """
        import re
        
        if not response or not response.strip():
            logger.warning("⚠️ Empty response received")
            return None
        
        # Try to find JSON in markdown code blocks (more flexible patterns)
        json_patterns = [
            r'```json\s*\n(.*?)\n```',           # ```json ... ```
            r'```\s*json\s*\n(.*?)\n```',       # ``` json ... ```
            r'```\s*\n(.*?)\n```',                 # ``` ... ``` (generic code block)
            r'```\s*\n(.*?)\n```',                # ``` ... ``` (with whitespace)
            r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}',  # Nested JSON object (improved)
        ]
        
        for i, pattern in enumerate(json_patterns):
            try:
                matches = re.findall(pattern, response, re.DOTALL)
                if matches:
                    # Try the longest match (most likely to be complete JSON)
                    json_candidate = max(matches, key=len).strip()
                    # Clean up common issues
                    json_candidate = json_candidate.strip('`').strip()
                    
                    # Try to find the actual JSON object start
                    json_start = json_candidate.find('{')
                    if json_start >= 0:
                        json_candidate = json_candidate[json_start:]
                    
                    try:
                        # Validate it's valid JSON
                        parsed = json.loads(json_candidate)
                        logger.info(f"✅ Extracted JSON from response using pattern {i+1} ({len(json_candidate)} chars)")
                        return json_candidate
                    except json.JSONDecodeError as e:
                        logger.debug(f"Pattern {i+1} matched but JSON invalid: {str(e)[:100]}")
                        continue
            except Exception as e:
                logger.debug(f"Pattern {i+1} error: {str(e)[:100]}")
                continue
        
        # If no code blocks found, try to find JSON object in the response
        try:
            # Look for JSON object boundaries
            json_start = response.find('{')
            json_end = response.rfind('}')
            
            if json_start >= 0 and json_end > json_start:
                json_candidate = response[json_start:json_end+1].strip()
                try:
                    parsed = json.loads(json_candidate)
                    logger.info(f"✅ Extracted JSON from response (found object boundaries, {len(json_candidate)} chars)")
                    return json_candidate
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            logger.debug(f"Error finding JSON boundaries: {str(e)[:100]}")
        
        # Last resort: try the whole response
        try:
            json.loads(response.strip())
            logger.info("✅ Response is valid JSON without code blocks")
            return response.strip()
        except json.JSONDecodeError:
            pass
        
        logger.warning(f"⚠️ Could not extract valid JSON from response (length: {len(response)})")
        logger.debug(f"Response preview (first 500 chars): {response[:500]}")
        return None

    def _get_error_report_structure(self) -> Dict[str, Any]:
        """Return default error structure when report generation fails."""
        return {
            "report_metadata": {
                "report_id": "ERROR",
                "generated_at": "",
                "domain_name": "UNKNOWN",
                "total_findings": 0,
                "processed_findings": 0
            },
            "statistics": {
                "total_findings": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "total_nodes": 0,
                "total_edges": 0
            },
            "executive_summary": {
                "overview": "Report generation failed. Please check logs and try again.",
                "key_findings": [],
                "risk_assessment": {
                    "overall_risk_level": "Unknown",
                    "risk_explanation": "Unable to assess risk due to generation failure",
                    "business_impact": "Impact assessment unavailable"
                },
                "immediate_actions": [],
                "recommendations": []
            },
            "findings": []
        }

    def convert_to_professional_format(self, structured_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert structured JSON report to format expected by ProfessionalReportView.
        This bridges the gap between our new JSON structure and existing React component.

        Includes T0 lateral movement findings in a separate section.
        """
        try:
            # Map to existing component format
            professional_format = {
                "report_id": structured_report['report_metadata']['report_id'],
                "generated_at": structured_report['report_metadata']['generated_at'],
                "domain_name": structured_report['report_metadata']['domain_name'],

                # Create executive summary markdown from structured data
                "executive_summary": self._build_executive_summary_markdown(structured_report['executive_summary']),

                # Environment overview is optional
                "environment_overview": None,

                # Convert actionable findings to expected format
                "findings": [
                    {
                        "finding_number": finding['finding_number'],
                        "edge_type": finding['edge_type'],
                        "source": finding['source'],
                        "target": finding['target'],
                        "risk_level": finding['risk_level'],
                        "classification": "actionable",
                        "explanation": finding['explanation'],
                        "remediation_steps": finding['remediation_steps'],
                        "powershell_script": finding['powershell_script'],
                        "rollback_script": finding['rollback_script'],
                        "mitre_mapping": finding['mitre_mapping'],
                        "detection_methods": finding['detection_methods'],
                        "warnings": finding['warnings']
                    }
                    for finding in structured_report['findings']
                ],

                # T0 lateral movement findings (expected privileges)
                "t0_lateral_movement": [
                    {
                        "finding_number": finding['finding_number'],
                        "edge_type": finding['edge_type'],
                        "source": finding['source'],
                        "target": finding['target'],
                        "risk_level": finding.get('risk_level', 'T0 Expected'),
                        "classification": "t0_lateral",
                        "title": finding.get('title', f"T0: {finding['edge_type']}"),
                        "explanation": finding.get('explanation', ''),
                        "blast_radius_note": finding.get('blast_radius_note', '')
                    }
                    for finding in structured_report.get('t0_lateral_movement', [])
                ],

                "statistics": structured_report['statistics'],
                "tier0_statistics": structured_report.get('tier0_statistics', {
                    "enabled": False,
                    "assets_count": 0,
                    "actionable_count": len(structured_report['findings']),
                    "t0_lateral_count": 0
                })
            }

            return professional_format

        except Exception as e:
            logger.error(f"Error converting to professional format: {str(e)}")
            return self._get_default_professional_format()

    def _build_executive_summary_markdown(self, executive_data: Dict[str, Any]) -> str:
        """Build clean markdown from structured executive summary data."""
        
        markdown_parts = []
        
        # Overview
        markdown_parts.append("## Overall Security Posture and Risk Level")
        markdown_parts.append(executive_data['overview'])
        
        # Key Findings
        if executive_data['key_findings']:
            markdown_parts.append("## Critical Vulnerabilities Identified")
            for i, finding in enumerate(executive_data['key_findings'], 1):
                markdown_parts.append(f"{i}. **{finding}**")
        
        # Risk Assessment
        risk_data = executive_data['risk_assessment']
        markdown_parts.append("## Risk Assessment")
        markdown_parts.append(f"**Overall Risk Level:** {risk_data['overall_risk_level']}")
        markdown_parts.append(risk_data['risk_explanation'])
        
        if risk_data['business_impact']:
            markdown_parts.append("### Business Impact")
            markdown_parts.append(risk_data['business_impact'])
        
        # Immediate Actions
        if executive_data['immediate_actions']:
            markdown_parts.append("## Immediate Actions Required")
            for i, action in enumerate(executive_data['immediate_actions'], 1):
                markdown_parts.append(f"{i}. **{action}**")
        
        # Strategic Recommendations
        if executive_data['recommendations']:
            markdown_parts.append("## Strategic Recommendations")
            for i, rec in enumerate(executive_data['recommendations'], 1):
                markdown_parts.append(f"{i}. **{rec}**")
        
        return "\n\n".join(markdown_parts)

    def _get_default_professional_format(self) -> Dict[str, Any]:
        """Default format when conversion fails."""
        return {
            "report_id": "ERROR",
            "generated_at": "",
            "domain_name": "UNKNOWN",
            "executive_summary": "# Report Generation Failed\n\nUnable to generate security assessment report. Please check system logs and try again.",
            "environment_overview": None,
            "findings": [],
            "statistics": {
                "total_findings": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "total_nodes": 0,
                "total_edges": 0
            }
        }