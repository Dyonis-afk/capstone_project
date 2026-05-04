"""
Utility Functions for Attack Path Analysis
Location: backend/routers/attack_paths/utils.py
"""

import re
import json
from typing import List, Dict, Any, Optional


def format_entity_type(entity_type: str) -> str:
    """Format entity type for display."""
    type_map = {
        'User': 'User Account',
        'Group': 'Security Group',
        'Computer': 'Computer',
        'Domain': 'Domain',
        'GPO': 'Group Policy Object',
        'OU': 'Organizational Unit',
        'Container': 'Container',
        'CertTemplate': 'Certificate Template',
        'EnterpriseCA': 'Enterprise CA',
    }
    return type_map.get(entity_type, entity_type)


def get_node_name(node) -> str:
    """Extract the name from a Neo4j node (handles various record types)."""
    if node is None:
        return ""

    # If it's already a string, return it
    if isinstance(node, str):
        return node

    # If it's a dict (converted from Neo4j record)
    if isinstance(node, dict):
        return node.get('name', '') or node.get('objectid', '') or str(node)

    # If it's a Neo4j Node object
    if hasattr(node, 'get'):
        return node.get('name', '') or node.get('objectid', '') or ''

    # If it has a .name attribute
    if hasattr(node, 'name'):
        return node.name or ''

    # If it has properties (Neo4j Node)
    if hasattr(node, '_properties'):
        props = node._properties
        return props.get('name', '') or props.get('objectid', '') or ''

    # Fallback to string representation
    return str(node) if node else ""


def parse_llm_json(raw_text: str, add_log: callable = None) -> List[Dict]:
    """
    Robustly parse JSON from LLM output, handling common formatting issues.

    LLMs often produce JSON with:
    - Trailing commas: [{}, {},]
    - Single quotes instead of double quotes
    - Comments or explanations mixed in
    - Incomplete/truncated arrays

    This function attempts multiple strategies to extract valid JSON.
    """
    if not raw_text or not raw_text.strip():
        return []

    # Strategy 1: Try to find JSON array with greedy match
    json_match = re.search(r'\[\s*\{[\s\S]*\}\s*\]', raw_text)

    if json_match:
        json_str = json_match.group()

        # Fix common LLM JSON issues
        # 1. Remove trailing commas before ] or }
        json_str = re.sub(r',\s*([}\]])', r'\1', json_str)

        # 2. Remove JavaScript-style comments
        json_str = re.sub(r'//[^\n]*\n', '\n', json_str)
        json_str = re.sub(r'/\*[\s\S]*?\*/', '', json_str)

        # Try parsing
        try:
            result = json.loads(json_str)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

        # Strategy 2: Try with single quote replacement
        try:
            fixed = re.sub(r"'(\w+)':", r'"\1":', json_str)
            fixed = re.sub(r":\s*'([^']*)'", r': "\1"', fixed)
            result = json.loads(fixed)
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

        # Strategy 3: Try to parse individual objects if array fails
        try:
            objects = []
            obj_pattern = r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
            for obj_match in re.finditer(obj_pattern, json_str):
                obj_str = obj_match.group()
                obj_str = re.sub(r',\s*([}\]])', r'\1', obj_str)
                try:
                    obj = json.loads(obj_str)
                    if isinstance(obj, dict):
                        objects.append(obj)
                except:
                    continue

            if objects:
                if add_log:
                    add_log("DEBUG", f"Recovered {len(objects)} objects from malformed JSON", debug_only=True)
                return objects
        except:
            pass

    # Strategy 4: Look for objects with opsec_options (specific to attack steps)
    try:
        objects = []
        step_pattern = r'\{\s*"step_number"\s*:\s*\d+[\s\S]*?"opsec_options"\s*:\s*\[[\s\S]*?\]\s*\}'
        for match in re.finditer(step_pattern, raw_text):
            obj_str = match.group()
            obj_str = re.sub(r',\s*([}\]])', r'\1', obj_str)
            try:
                obj = json.loads(obj_str)
                objects.append(obj)
            except:
                continue

        if objects:
            if add_log:
                add_log("DEBUG", f"Extracted {len(objects)} attack steps via pattern matching", debug_only=True)
            return objects
    except:
        pass

    return []


def extract_section(text: str, section_name: str, default: str = "") -> str:
    """Extract a section from markdown text by header name."""
    if not text:
        return default

    # Try to find section with ## header
    pattern = rf'##\s*{re.escape(section_name)}\s*\n([\s\S]*?)(?=##|\Z)'
    match = re.search(pattern, text, re.IGNORECASE)

    if match:
        return match.group(1).strip()

    return default


def format_results_for_rag(results: List[Dict], max_results: int = 10) -> str:
    """Format query results for RAG prompt context, showing full chain for multi-hop paths."""
    if not results:
        return "No results"

    formatted_lines = []
    for i, result in enumerate(results[:max_results]):
        if 'source' in result and 'target' in result:
            source = result.get('source', 'Unknown')
            target = result.get('target', 'Unknown')
            path_edges = result.get('path_edges', [])
            intermediate = result.get('intermediate_nodes', [])

            # Show full chain if multi-hop path data is available
            if path_edges and len(path_edges) > 1 and intermediate:
                parts = [source]
                for j, edge_name in enumerate(path_edges):
                    if j < len(intermediate):
                        parts.append(f"-[{edge_name}]-> {intermediate[j]}")
                    else:
                        parts.append(f"-[{edge_name}]-> {target}")
                if not parts[-1].endswith(target):
                    parts.append(f"-> {target}")
                formatted_lines.append(f"{i+1}. {' '.join(parts)}")
            else:
                edge = result.get('edge_type', result.get('rel_type', 'Unknown'))
                formatted_lines.append(f"{i+1}. {source} --[{edge}]--> {target}")
        else:
            # Generic formatting for other result types
            formatted_lines.append(f"{i+1}. {result}")

    return "\n".join(formatted_lines)


def build_affected_entities(findings: List[Dict]) -> List[Dict]:
    """Build affected entities list from findings."""
    entities = []
    seen = set()

    for finding in findings:
        source = finding.get('source', '')
        target = finding.get('target', '')
        source_type = finding.get('source_type', 'Unknown')
        target_type = finding.get('target_type', 'Unknown')
        edge_type = finding.get('edge_type', '')

        key = f"{source}|{target}"
        if key in seen or not source:
            continue
        seen.add(key)

        entity = {
            'principal': source,
            'type': format_entity_type(source_type),
            'target_group': target if target_type in ['Group', 'Domain'] else None,
            'path': 'Direct' if edge_type == 'MemberOf' else edge_type,
        }
        entities.append(entity)

    return entities
