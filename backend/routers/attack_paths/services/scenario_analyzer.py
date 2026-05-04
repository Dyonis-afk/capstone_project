"""
Scenario Analysis Services for Attack Path Analysis
Location: backend/routers/attack_paths/services/scenario_analyzer.py

Functions for analyzing attack scenarios:
- RAG results formatting
- Section extraction from RAG responses
"""

import re
import json
from typing import Dict, Any, List, Optional

from services.rag_service import RAGService

from ..models import FindingsSummary, QueryResult
from ..state import add_log, update_progress as _update_progress
from ..constants import EDGE_TYPE_QUERY_TEMPLATES


def _format_results_for_rag(results: List[Dict[str, Any]], max_results: int = 10) -> str:
    """
    Format query results for RAG prompt with deduplication and essential fields only.

    This prevents token limit errors by:
    1. Deduplicating results by (source, target, edge_type) tuple
    2. Stripping each result to only essential fields
    3. Limiting the number of results included
    4. Using a compact format instead of JSON
    """
    if not results:
        return "No results found."

    # Deduplicate by (source, target, edge_type)
    seen = set()
    unique_results = []

    for r in results:
        source = r.get('source', '').split('@')[0] if r.get('source') else ''
        target = r.get('target', '').split('@')[0] if r.get('target') else ''
        edge_type = r.get('edge_type', '')

        key = (source.upper(), target.upper(), edge_type.upper())

        if key not in seen and source and target:
            seen.add(key)
            unique_results.append({
                'source': r.get('source', ''),
                'source_type': r.get('source_type', 'Unknown'),
                'edge_type': edge_type,
                'target': r.get('target', ''),
                'target_type': r.get('target_type', 'Unknown'),
            })

    # Limit to max_results
    unique_results = unique_results[:max_results]

    # Format as compact table
    lines = ["| Source | Type | Edge | Target | Type |", "|--------|------|------|--------|------|"]

    for r in unique_results:
        source_short = r['source'].split('@')[0][:25]
        target_short = r['target'].split('@')[0][:25]
        lines.append(f"| {source_short} | {r['source_type']} | {r['edge_type']} | {target_short} | {r['target_type']} |")

    total = len(results)
    unique = len(unique_results)

    if total > unique:
        lines.append(f"\n*Showing {unique} unique paths out of {total} total results*")

    return "\n".join(lines)


def _extract_section(text: str, section_name: str) -> str:
    """Extract a section from RAG response text with improved pattern matching"""

    if not text:
        return ""

    # Normalize line endings (Windows \r\n -> Unix \n)
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    section_name_lower = section_name.lower().strip()

    # Normalize section name variations
    section_aliases = {
        'path overview': ['path overview', 'overview', 'description', 'summary', 'path description'],
        'technical analysis': ['technical analysis', 'technical details', 'how it works', 'vulnerability analysis', 'technical explanation'],
        'attack scenario': ['attack scenario', 'attack steps', 'exploitation', 'exploitation steps', 'attack commands', 'step-by-step', 'attack', 'commands'],
        'remediation strategy': ['remediation strategy', 'remediation', 'mitigation', 'recommendations', 'how to fix', 'fixes', 'remediation steps', 'remediation actions'],
        'detection methods': ['detection methods', 'detection', 'monitoring', 'how to detect', 'detection opportunities'],
        'mitre': ['mitre', 'mitre att&ck', 'att&ck', 'technique', 'mitre mapping', 'attack mapping']
    }

    # Get all possible names for this section
    possible_names = [section_name_lower]
    for key, aliases in section_aliases.items():
        if section_name_lower in aliases or key == section_name_lower:
            possible_names = aliases
            break

    # Try to find section with multiple patterns
    for name in possible_names:
        escaped_name = re.escape(name)

        # Pattern 1: Markdown headers (## Section or ### Section)
        pattern1 = rf'#{2,4}\s*\**{escaped_name}[^\n]*\n(.*?)(?=\n#{2,4}\s|\n\*\*[A-Z]|\Z)'
        match = re.search(pattern1, text, re.IGNORECASE | re.DOTALL)
        if match:
            content = match.group(1).strip()
            if content and len(content) > 20:
                return content

        # Pattern 2: Bold headers (**Section:**)
        pattern2 = rf'\*\*{escaped_name}[:\*\s]*\*\*[:\s]*(.*?)(?=\n\*\*[A-Z]|\n#{2,4}|\Z)'
        match = re.search(pattern2, text, re.IGNORECASE | re.DOTALL)
        if match:
            content = match.group(1).strip()
            if content and len(content) > 20:
                return content

        # Pattern 3: Numbered sections (1. Section Name: or **1. Section**)
        pattern3 = rf'\d+\.\s*\**{escaped_name}[:\s]*\**[:\s]*(.*?)(?=\n\d+\.|\n\*\*[A-Z]|\n#{2,4}|\Z)'
        match = re.search(pattern3, text, re.IGNORECASE | re.DOTALL)
        if match:
            content = match.group(1).strip()
            if content and len(content) > 20:
                return content

    # Fallback: For path_overview, extract introductory content before first code block
    if any(x in section_name_lower for x in ['path overview', 'overview', 'summary', 'description']):
        overview_patterns = [
            r'(?:path overview|overview|summary)[^\n]*\n(.*?)(?=\n#{2,4}\s|\n```|\n\*\*[A-Z]|\Z)',
            r'^(.*?)(?=\n#{2,4}\s*(?:technical|attack|remediation)|\n```)',
        ]
        for pattern in overview_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1).strip()
                content = re.sub(r'#{2,4}\s+[^\n]+\n?', '', content)
                content = content.strip()
                if content and len(content) > 50:
                    return content

    # Fallback: For technical_analysis
    if any(x in section_name_lower for x in ['technical analysis', 'technical details', 'how it works']):
        tech_patterns = [
            r'(?:technical analysis|technical details|how it works)[^\n]*\n(.*?)(?=\n#{2,4}\s|\n```|\n\*\*(?:attack|step)|\Z)',
            r'(?:active directory|AD|misconfiguration|permission|ACL|ACE|DACL)[^\n]*[.!]\s*(.*?)(?=\n#{2,4}\s|\n```|\Z)',
        ]
        for pattern in tech_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1).strip()
                if content and len(content) > 50:
                    return content

    # Fallback: For attack_scenario, extract ALL code blocks
    if any(x in section_name_lower for x in ['attack', 'scenario', 'command', 'step', 'exploit']):
        code_blocks = re.findall(r'```(?:powershell|bash|python|cmd|shell)?\n?(.*?)```', text, re.DOTALL | re.IGNORECASE)
        if code_blocks:
            formatted = []
            for i, block in enumerate(code_blocks[:10], 1):
                block_clean = block.strip()
                if block_clean and len(block_clean) > 10:
                    if any(cmd in block_clean.lower() for cmd in ['invoke-', 'get-', 'set-', 'add-', 'remove-', 'new-', 'import-']):
                        lang = "powershell"
                    elif any(cmd in block_clean.lower() for cmd in ['python', 'impacket', '.py', 'hashcat', 'john', 'rubeus', 'secretsdump']):
                        lang = "bash"
                    else:
                        lang = "powershell"
                    formatted.append(f"**Step {i}:**\n```{lang}\n{block_clean}\n```")

            if formatted:
                return "\n\n".join(formatted)

    # Fallback: For remediation
    if any(x in section_name_lower for x in ['remediation', 'mitigation', 'fix']):
        remediation_patterns = [
            r'(?:to remediate|to fix|to resolve|recommendation|remediation)[:\s]*(.*?)(?=\n\n[A-Z#*]|\Z)',
            r'(?:immediate actions|remediation steps|mitigation steps)[:\s]*(.*?)(?=\n\n[A-Z#*]|\Z)'
        ]
        for pattern in remediation_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                content = match.group(1).strip()
                if content and len(content) > 30:
                    return content

    # Fallback: Look for MITRE technique IDs
    if section_name_lower in ['mitre', 'mitre att&ck', 'mitre mapping']:
        mitre_pattern = r'(T\d{4}(?:\.\d{3})?(?:[,\s]+T\d{4}(?:\.\d{3})?)*)'
        mitre_match = re.search(mitre_pattern, text)
        if mitre_match:
            return mitre_match.group(1)

    return ""
