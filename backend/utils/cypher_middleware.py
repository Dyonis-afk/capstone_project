"""Injects per-project filters into Cypher queries so RAG-generated queries
stay clean and project isolation is enforced at runtime.
"""

import re
import logging
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)

# Property name used to tag all nodes and relationships with project ID
PROJECT_PROPERTY = "_aegis_project"


def inject_project_filter(
    query: str, 
    project_id: str,
    params: Optional[Dict[str, Any]] = None
) -> Tuple[str, Dict[str, Any]]:
    """
    Inject project filtering into a Cypher query.
    
    Takes a clean Cypher query and adds project_id filtering to all node patterns.
    
    Args:
        query: The original Cypher query
        project_id: The project ID to filter by
        params: Existing query parameters (optional)
    
    Returns:
        Tuple of (modified_query, updated_params)
    
    Example:
        Input:  "MATCH (u:User)-[:MemberOf]->(g:Group) RETURN u, g"
        Output: "MATCH (u:User {_aegis_project: $__project_id})-[:MemberOf {_aegis_project: $__project_id}]->(g:Group {_aegis_project: $__project_id}) RETURN u, g"
    """
    if params is None:
        params = {}
    
    # Add project_id to params
    params["__project_id"] = project_id
    
    # Inject project filter into node patterns
    modified_query = _inject_node_filters(query)
    
    # Inject project filter into relationship patterns
    modified_query = _inject_relationship_filters(modified_query)
    
    logger.debug(f"Injected project filter for project {project_id}")
    
    return modified_query, params


def _inject_node_filters(query: str) -> str:
    """
    Inject project filter into node patterns.
    
    Patterns handled:
    - (n:Label) → (n:Label {_aegis_project: $__project_id})
    - (n:Label {prop: val}) → (n:Label {_aegis_project: $__project_id, prop: val})
    - (:Label) → (:Label {_aegis_project: $__project_id})
    """
    
    # Pattern for node with label and existing properties
    # (var:Label {existing: props})
    pattern_with_props = r'\((\w*)(:\w+(?::\w+)*)\s*\{([^}]*)\}\)'
    
    def replace_with_props(match):
        var = match.group(1) or ''
        labels = match.group(2)
        props = match.group(3).strip()
        
        # Don't double-inject
        if PROJECT_PROPERTY in props:
            return match.group(0)
        
        if props:
            new_props = f"{PROJECT_PROPERTY}: $__project_id, {props}"
        else:
            new_props = f"{PROJECT_PROPERTY}: $__project_id"
        
        return f"({var}{labels} {{{new_props}}})"
    
    query = re.sub(pattern_with_props, replace_with_props, query)
    
    # Pattern for node with label but no properties
    # (var:Label) or (:Label)
    pattern_no_props = r'\((\w*)(:\w+(?::\w+)*)\)(?!\s*\{)'
    
    def replace_no_props(match):
        var = match.group(1) or ''
        labels = match.group(2)
        return f"({var}{labels} {{{PROJECT_PROPERTY}: $__project_id}})"
    
    query = re.sub(pattern_no_props, replace_no_props, query)
    
    return query


def _inject_relationship_filters(query: str) -> str:
    """
    Inject project filter into relationship patterns.
    
    Patterns handled:
    - -[:TYPE]-> → -[:TYPE {_aegis_project: $__project_id}]->
    - -[r:TYPE]-> → -[r:TYPE {_aegis_project: $__project_id}]->
    - -[r:TYPE {prop: val}]-> → -[r:TYPE {_aegis_project: $__project_id, prop: val}]->
    """
    
    # Pattern for relationship with existing properties
    pattern_rel_with_props = r'\[(\w*)(:\w+(?:\|?\w+)*)\s*\{([^}]*)\}\]'
    
    def replace_rel_with_props(match):
        var = match.group(1) or ''
        types = match.group(2)
        props = match.group(3).strip()
        
        # Don't double-inject
        if PROJECT_PROPERTY in props:
            return match.group(0)
        
        if props:
            new_props = f"{PROJECT_PROPERTY}: $__project_id, {props}"
        else:
            new_props = f"{PROJECT_PROPERTY}: $__project_id"
        
        return f"[{var}{types} {{{new_props}}}]"
    
    query = re.sub(pattern_rel_with_props, replace_rel_with_props, query)
    
    # Pattern for relationship without properties
    # -[:TYPE]-> or -[r:TYPE]->
    pattern_rel_no_props = r'\[(\w*)(:\w+(?:\|?\w+)*)\](?!\s*\{)'
    
    def replace_rel_no_props(match):
        var = match.group(1) or ''
        types = match.group(2)
        return f"[{var}{types} {{{PROJECT_PROPERTY}: $__project_id}}]"
    
    query = re.sub(pattern_rel_no_props, replace_rel_no_props, query)
    
    return query


def get_project_data_check_query(project_id: str) -> Tuple[str, Dict[str, Any]]: 
    """
    Get detailed stats query for checking project data.
    """
    query = f"""
    MATCH (n {{{PROJECT_PROPERTY}: $project_id}})
    WITH count(n) as total_nodes,
         sum(CASE WHEN 'User' IN labels(n) THEN 1 ELSE 0 END) as users,
         sum(CASE WHEN 'Group' IN labels(n) THEN 1 ELSE 0 END) as groups,
         sum(CASE WHEN 'Computer' IN labels(n) THEN 1 ELSE 0 END) as computers
    OPTIONAL MATCH (a {{{PROJECT_PROPERTY}: $project_id}})-[r {{{PROJECT_PROPERTY}: $project_id}}]->(b)
    RETURN total_nodes, users, groups, computers, count(r) as total_relationships
    """
    return query, {"project_id": project_id}


def get_project_clear_query(project_id: str) -> Tuple[str, Dict[str, Any]]:
    """
    Get query to delete all data for a project.
    """
    query = f"""
    MATCH (n {{{PROJECT_PROPERTY}: $project_id}})
    DETACH DELETE n
    """
    return query, {"project_id": project_id}


def add_project_to_properties(properties: Dict[str, Any], project_id: str) -> Dict[str, Any]:
    """
    Add project ID to node/relationship properties for import.
    """
    if properties is None:
        properties = {}
    properties[PROJECT_PROPERTY] = project_id
    return properties