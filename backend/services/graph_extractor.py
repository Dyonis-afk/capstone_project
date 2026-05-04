"""Extracts visualization data (nodes and edges) from attack path analysis results.

The output is embedded into the generated report so the graph can be rendered
offline by the Electron client.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class AttackPathGraphExtractor:
    """Extract graph visualization data from attack path analysis results"""
    
    def __init__(self):
        self.node_colors = {
            'User': '#4A90E2',      # Blue
            'Group': '#F5A623',     # Orange  
            'Computer': '#50E3C2',  # Teal
            'Domain': '#D0021B',    # Red
            'Unknown': '#9B9B9B'    # Gray
        }
        
        self.edge_colors = {
            'OWNS': '#FF6B6B',           # Red - ownership
            'GENERICALL': '#FF8E53',     # Orange-red - powerful
            'WRITEDACL': '#FF6B9D',      # Pink - ACL manipulation
            'WRITEOWNER': '#C44569',     # Dark pink - ownership change
            'MEMBEROF': '#4834D4',       # Purple - group membership
            'ADMINLOCALLYTO': '#30336B', # Dark blue - local admin
            'ADMINTO': '#30336B',        # Dark blue - admin to
            'ALLEXTENDEDRIGHTS': '#FF5722', # Deep orange - extended rights
            'GENERICWRITE': '#FF9800',   # Orange - write access
            'ADDMEMBER': '#8E24AA',      # Purple - group modification
            'FORCECHANGEPASSWORD': '#E91E63', # Pink - password control
            'GETCHANGES': '#D32F2F',     # Red - DCSync
            'GETCHANGESALL': '#D32F2F',  # Red - DCSync
            'DCSYNC': '#D32F2F',         # Red - DCSync
            'default': '#757575'         # Gray - unknown
        }
        
        self.risk_colors = {
            'Critical': '#FF1744',  # Bright red
            'High': '#FF5722',      # Deep orange  
            'Medium': '#FF9800',    # Orange
            'Low': '#4CAF50'        # Green
        }
    
    def extract_graph_from_attack_paths(self, attack_paths: List[Dict[str, Any]], analysis_id: str) -> Dict[str, Any]:
        """
        Extract graph visualization data from attack path analysis results
        
        Args:
            attack_paths: List of analyzed attack paths from RAG service
            analysis_id: Analysis identifier
            
        Returns:
            Graph data formatted for frontend visualization
        """
        logger.info(f"🔍 Extracting graph data from {len(attack_paths)} attack paths...")
        
        nodes_dict = {}  # Avoid duplicates - keyed by node ID
        edges_dict = {}  # FIXED: Avoid duplicate edges - keyed by source-target-type
        paths_list = []
        
        for path_index, attack_path in enumerate(attack_paths):
            try:
                # Extract path information
                path_info = self._extract_path_info(attack_path, path_index)
                
                if not path_info:
                    continue
                
                # Extract nodes and edges from this specific path
                path_nodes, path_edges = self._extract_nodes_and_edges_from_path(attack_path, path_index)
                
                # Add nodes to global dict (avoiding duplicates)
                for node in path_nodes:
                    node_id = node['id']
                    if node_id not in nodes_dict:
                        nodes_dict[node_id] = node
                    else:
                        # Update node if this path has higher risk
                        existing_risk = nodes_dict[node_id].get('riskLevel', 'Low')
                        new_risk = node.get('riskLevel', 'Low')
                        if self._compare_risk_levels(new_risk, existing_risk):
                            nodes_dict[node_id].update(node)
                
                # FIXED: Add edges with deduplication
                # Key edges by source-target-type to avoid visual duplicates
                # CRITICAL: pathIndex must match scenario_number - 1 for frontend filtering
                scenario_path_index = path_info['scenario_number'] - 1
                for edge in path_edges:
                    edge['pathId'] = path_info['id']
                    edge['pathIndex'] = scenario_path_index
                    
                    # Create a unique key for edge deduplication
                    # Edges between same nodes with same type should only appear once
                    edge_key = f"{edge['source']}|{edge['target']}|{edge['type']}"
                    
                    if edge_key not in edges_dict:
                        edges_dict[edge_key] = edge
                    else:
                        # Edge already exists - update if this one has higher risk
                        existing_edge = edges_dict[edge_key]
                        if self._compare_risk_levels(
                            edge.get('riskLevel', 'Low'),
                            existing_edge.get('riskLevel', 'Low')
                        ):
                            edges_dict[edge_key] = edge
                
                # Add path metadata
                paths_list.append(path_info)
                
            except Exception as e:
                logger.warning(f"⚠️ Failed to extract path {path_index}: {str(e)}")
                continue
        
        # Convert dicts to lists
        nodes_list = list(nodes_dict.values())
        edges_list = list(edges_dict.values())
        
        # Generate layout hints for frontend
        layout_hints = self._generate_layout_hints(nodes_list, edges_list, paths_list)
        
        graph_data = {
            "graph": {
                "nodes": nodes_list,
                "edges": edges_list,
                "paths": paths_list
            },
            "layout": layout_hints,
            "metadata": {
                "analysis_id": analysis_id,
                "total_paths": len(paths_list),
                "total_nodes": len(nodes_list),
                "total_edges": len(edges_list),
                "generated_at": datetime.now().isoformat()
            }
        }
        
        logger.info(f"✅ Graph extraction complete: {len(nodes_list)} nodes, {len(edges_list)} edges, {len(paths_list)} paths")
        return graph_data
    
    def _extract_path_info(self, attack_path: Dict[str, Any], path_index: int) -> Optional[Dict[str, Any]]:
        """Extract high-level path information"""
        try:
            query_info = attack_path.get('query_info', {})
            
            # Extract risk level and priority
            priority = query_info.get('priority', 'Medium')
            risk_level = self._priority_to_risk_level(priority)
            
            # Get scenario number or use index
            scenario_number = attack_path.get('scenario_number', path_index + 1)
            
            path_info = {
                "id": f"path_{scenario_number}",
                "name": query_info.get('name', f'Attack Path {scenario_number}'),
                "description": query_info.get('description', ''),
                "attack_type": query_info.get('attack_type', 'unknown'),
                "priority": priority,
                "risk_level": risk_level,
                "result_count": attack_path.get('result_count', 0),
                "scenario_number": scenario_number,
                "color": self.risk_colors.get(risk_level, self.risk_colors['Medium'])
            }
            
            return path_info
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to extract path info for index {path_index}: {str(e)}")
            return None
    
    def _extract_nodes_and_edges_from_path(self, attack_path: Dict[str, Any], path_index: int) -> Tuple[List[Dict], List[Dict]]:
        """Extract nodes and edges from attack path results"""
        nodes = []
        edges = []
        
        # Limit max results per path for graph visualization performance
        MAX_RESULTS_PER_PATH = 200  # Cytoscape struggles with too many elements
        
        try:
            # Try multiple possible keys where results might be stored
            results = None
            
            # Check different possible result locations (in order of likelihood)
            if 'results' in attack_path and attack_path['results']:
                results = attack_path['results']
            elif 'query_results' in attack_path and attack_path['query_results']:
                results = attack_path['query_results']
            elif 'neo4j_results' in attack_path and attack_path['neo4j_results']:
                results = attack_path['neo4j_results']
            elif 'raw_results' in attack_path and attack_path['raw_results']:
                results = attack_path['raw_results']
            elif 'data' in attack_path and isinstance(attack_path['data'], list):
                results = attack_path['data']
            
            # If still no results, check if it's a list directly
            if not results and isinstance(attack_path, list):
                results = attack_path
            
            # Get query info for context
            query_info = attack_path.get('query_info', {})
            
            if not results:
                logger.debug(f"⚠️ No results found for path {path_index}")
                return nodes, edges
            
            # Ensure results is a list
            if not isinstance(results, list):
                results = [results] if results else []
            
            # Limit results for graph visualization performance
            total_results = len(results)
            if total_results > MAX_RESULTS_PER_PATH:
                logger.warning(f"⚠️ Path {path_index} has {total_results} results, limiting to {MAX_RESULTS_PER_PATH}")
                half = MAX_RESULTS_PER_PATH // 2
                results = results[:half] + results[-half:]
            
            # Extract entities from Cypher query results
            for result_index, result in enumerate(results):
                try:
                    result_nodes, result_edges = self._parse_cypher_result(result, query_info, path_index, result_index)
                    nodes.extend(result_nodes)
                    edges.extend(result_edges)
                    
                except Exception as e:
                    if result_index == 0:
                        logger.debug(f"⚠️ Failed to parse result {result_index} in path {path_index}: {str(e)}")
                    continue
            
            logger.debug(f"✅ Extracted {len(nodes)} nodes and {len(edges)} edges from path {path_index}")
            
        except Exception as e:
            logger.error(f"❌ Failed to extract nodes/edges from path {path_index}: {str(e)}")
        
        return nodes, edges
    
    def _parse_cypher_result(self, result: Dict[str, Any], query_info: Dict[str, Any], path_index: int, result_index: int) -> Tuple[List[Dict], List[Dict]]:
        """Parse individual Cypher query result into nodes and edges"""
        nodes = []
        edges = []
        
        if not isinstance(result, dict):
            return nodes, edges
        
        def get_non_empty(d: Dict, *keys) -> Optional[str]:
            """Get first non-empty string value from dict for given keys"""
            for key in keys:
                val = d.get(key)
                if val and isinstance(val, str) and val.strip():
                    return val.strip()
            return None
        
        try:
            # Track if we successfully parsed via Case 1
            case1_success = False

            # =================================================================
            # Case 0: Scan ALL values for path-like structures (BloodHound CE / Electron format)
            # This handles results like {"p": {start, end, segments}} where "p" is from RETURN p
            # =================================================================
            for key, value in result.items():
                if isinstance(value, dict) and 'start' in value and 'end' in value:
                    # This looks like a path object from Electron's Neo4j service
                    path_data = value
                    segments = path_data.get('segments', [])

                    if segments:
                        logger.debug(f"📍 Case 0: Found path in key '{key}' with {len(segments)} segments")

                        # Add start node
                        start_node_data = path_data.get('start')
                        if start_node_data:
                            node = self._create_node_from_path_data(start_node_data, path_index)
                            if node:
                                nodes.append(node)

                        # Process each segment
                        for seg_index, segment in enumerate(segments):
                            end_node_data = segment.get('end')
                            if end_node_data:
                                node = self._create_node_from_path_data(end_node_data, path_index)
                                if node:
                                    nodes.append(node)

                            rel_data = segment.get('relationship', {})
                            if rel_data:
                                seg_start = segment.get('start', {})
                                seg_end = segment.get('end', {})
                                source_name = self._get_node_name(seg_start) if seg_start else None
                                target_name = self._get_node_name(seg_end) if seg_end else None
                                edge_type = rel_data.get('type', 'RELATED_TO')

                                if source_name and target_name and source_name != 'Unknown' and target_name != 'Unknown':
                                    edge = self._create_edge(
                                        source=source_name,
                                        target=target_name,
                                        edge_type=edge_type,
                                        query_info=query_info,
                                        path_index=path_index,
                                        result_index=result_index + seg_index
                                    )
                                    edges.append(edge)

                        if nodes:
                            logger.debug(f"✅ Case 0: Extracted {len(nodes)} nodes and {len(edges)} edges from path key '{key}'")
                            return nodes, edges
                    else:
                        # Path with no segments - direct start to end
                        logger.debug(f"📍 Case 0: Found direct path in key '{key}' (no segments)")
                        start_node = self._create_node_from_path_data(path_data.get('start'), path_index)
                        end_node = self._create_node_from_path_data(path_data.get('end'), path_index)

                        if start_node and end_node:
                            nodes.extend([start_node, end_node])
                            source_name = self._get_node_name(path_data.get('start'))
                            target_name = self._get_node_name(path_data.get('end'))

                            if source_name and target_name:
                                edge = self._create_edge(
                                    source=source_name,
                                    target=target_name,
                                    edge_type='PATH',
                                    query_info=query_info,
                                    path_index=path_index,
                                    result_index=result_index
                                )
                                edges.append(edge)

                            logger.debug(f"✅ Case 0: Extracted {len(nodes)} nodes and {len(edges)} edges from direct path")
                            return nodes, edges

            # Check if this is a multi-hop path that needs full segment processing
            path_length = result.get('path_length', 0)
            has_multi_hop_path = path_length > 1 and 'raw_path' in result

            # If we have a multi-hop path, ALWAYS process raw_path segments first
            # This ensures intermediate nodes (like groups) are not lost
            if has_multi_hop_path:
                path_data = result['raw_path']
                if isinstance(path_data, dict) and 'segments' in path_data:
                    segments = path_data.get('segments', [])
                    logger.debug(f"📍 Processing multi-hop path with {len(segments)} segments (path_length={path_length})")

                    # Add start node of the path
                    start_node_data = path_data.get('start')
                    if start_node_data:
                        node = self._create_node_from_path_data(start_node_data, path_index)
                        if node:
                            nodes.append(node)

                    # Process each segment to capture ALL intermediate nodes
                    for seg_index, segment in enumerate(segments):
                        # Extract the end node of this segment (which is the intermediate or final node)
                        end_node_data = segment.get('end')
                        if end_node_data:
                            node = self._create_node_from_path_data(end_node_data, path_index)
                            if node:
                                nodes.append(node)

                        # Extract the relationship for this segment
                        rel_data = segment.get('relationship', {})
                        if rel_data:
                            seg_start = segment.get('start', {})
                            seg_end = segment.get('end', {})
                            source_name = self._get_node_name(seg_start) if seg_start else None
                            target_name = self._get_node_name(seg_end) if seg_end else None
                            edge_type = rel_data.get('type', 'RELATED_TO')

                            if source_name and target_name and source_name != 'Unknown' and target_name != 'Unknown':
                                edge = self._create_edge(
                                    source=source_name,
                                    target=target_name,
                                    edge_type=edge_type,
                                    query_info=query_info,
                                    path_index=path_index,
                                    result_index=result_index + seg_index
                                )
                                edges.append(edge)

                    if nodes:
                        logger.debug(f"✅ Extracted {len(nodes)} nodes and {len(edges)} edges from multi-hop path segments")
                        return nodes, edges

            # Case 1: Simple source -> target relationship (for single-hop paths)
            if 'source' in result and 'target' in result and not has_multi_hop_path:
                source_name = result['source']
                target_name = result['target']
                source_type = result.get('source_type', 'Unknown')
                target_type = result.get('target_type', 'Unknown')

                # Validate source and target are not empty or 'Unknown'
                if source_name and source_name != 'Unknown' and target_name and target_name != 'Unknown':
                    # Get edge type from various possible keys
                    edge_type = get_non_empty(result, 'edge_type', 'relationship_type', 'relationship', 'type', 'rel_type')

                    # If still no edge type, try to infer from query_info
                    if not edge_type:
                        edges_used = query_info.get('edges_used', [])
                        if edges_used and len(edges_used) == 1:
                            edge_type = edges_used[0]
                        elif edges_used:
                            edge_type = query_info.get('attack_type', '|'.join(edges_used[:2]))
                        else:
                            edge_type = query_info.get('attack_type', 'RELATED_TO')

                    if not edge_type:
                        edge_type = 'RELATED_TO'

                    source_node = self._create_node(source_name, source_type, path_index)
                    target_node = self._create_node(target_name, target_type, path_index)

                    edge = self._create_edge(
                        source=source_name,
                        target=target_name,
                        edge_type=edge_type,
                        query_info=query_info,
                        path_index=path_index,
                        result_index=result_index
                    )

                    nodes.extend([source_node, target_node])
                    edges.append(edge)
                    case1_success = True
                else:
                    logger.debug(f"⚠️ Case 1 failed: empty/unknown source ({source_name}) or target ({target_name})")

            # If Case 1 failed or didn't produce results, try raw_path as fallback
            if not case1_success and 'raw_path' in result and not has_multi_hop_path:
                path_data = result['raw_path']
                if isinstance(path_data, dict):
                    # Handle BloodHound CE segment-based path format in raw_path
                    if 'segments' in path_data:
                        segments = path_data.get('segments', [])
                        logger.debug(f"📍 Falling back to raw_path with {len(segments)} segments (BloodHound CE format)")

                        # Add start node of the path
                        start_node_data = path_data.get('start')
                        if start_node_data:
                            node = self._create_node_from_path_data(start_node_data, path_index)
                            if node:
                                nodes.append(node)

                        # Process each segment
                        for seg_index, segment in enumerate(segments):
                            # Extract the end node of this segment
                            end_node_data = segment.get('end')
                            if end_node_data:
                                node = self._create_node_from_path_data(end_node_data, path_index)
                                if node:
                                    nodes.append(node)

                            # Extract the relationship
                            rel_data = segment.get('relationship', {})
                            if rel_data:
                                seg_start = segment.get('start', {})
                                seg_end = segment.get('end', {})
                                source_name = self._get_node_name(seg_start) if seg_start else None
                                target_name = self._get_node_name(seg_end) if seg_end else None
                                edge_type = rel_data.get('type', 'RELATED_TO')

                                if source_name and target_name and source_name != 'Unknown' and target_name != 'Unknown':
                                    edge = self._create_edge(
                                        source=source_name,
                                        target=target_name,
                                        edge_type=edge_type,
                                        query_info=query_info,
                                        path_index=path_index,
                                        result_index=result_index + seg_index
                                    )
                                    edges.append(edge)

                        if nodes:
                            logger.debug(f"✅ Extracted {len(nodes)} nodes and {len(edges)} edges from raw_path segments")
                            return nodes, edges

                    # Handle standard Neo4j path format in raw_path
                    elif 'nodes' in path_data:
                        logger.debug(f"📍 Falling back to raw_path with {len(path_data.get('nodes', []))} nodes")
                        for node_data in path_data['nodes']:
                            node = self._create_node_from_path_data(node_data, path_index)
                            if node:
                                nodes.append(node)

                        if 'relationships' in path_data:
                            for rel_data in path_data['relationships']:
                                edge = self._create_edge_from_path_data(rel_data, query_info, path_index, result_index)
                                if edge:
                                    edges.append(edge)

                        if nodes:  # If we got results from raw_path, return
                            return nodes, edges

            # Return early if Case 1 was successful
            if case1_success:
                return nodes, edges

            # Case 2: User-related patterns (only if source not present)
            if ('user' in result or 'principal' in result) and 'source' not in result:
                user_name = result.get('user') or result.get('principal', '')
                user_type = result.get('principal_type', 'User')

                if user_name:
                    user_node = self._create_node(user_name, user_type, path_index)
                    nodes.append(user_node)

                    # Check for related entities
                    for key in ['computer', 'computers', 'domain', 'group', 'groups']:
                        related = result.get(key)
                        if related:
                            if isinstance(related, list):
                                for item in related[:10]:  # Limit to 10
                                    rel_name = item if isinstance(item, str) else str(item)
                                    rel_type = 'Computer' if 'computer' in key else ('Group' if 'group' in key else 'Domain')
                                    rel_node = self._create_node(rel_name, rel_type, path_index)
                                    nodes.append(rel_node)

                                    edge = self._create_edge(
                                        source=user_name,
                                        target=rel_name,
                                        edge_type=query_info.get('attack_type', 'RELATED_TO'),
                                        query_info=query_info,
                                        path_index=path_index,
                                        result_index=result_index
                                    )
                                    edges.append(edge)
                            elif isinstance(related, str):
                                rel_type = 'Computer' if 'computer' in key else ('Group' if 'group' in key else 'Domain')
                                rel_node = self._create_node(related, rel_type, path_index)
                                nodes.append(rel_node)

                                edge = self._create_edge(
                                    source=user_name,
                                    target=related,
                                    edge_type=query_info.get('attack_type', 'RELATED_TO'),
                                    query_info=query_info,
                                    path_index=path_index,
                                    result_index=result_index
                                )
                                edges.append(edge)
                    return nodes, edges
            
            # Case 3: Computer-related patterns
            if 'computer' in result and 'source' not in result:
                computer_name = result.get('computer', '')
                if computer_name:
                    comp_node = self._create_node(computer_name, 'Computer', path_index)
                    nodes.append(comp_node)

                    # Check for local admins
                    admins = result.get('local_admins', [])
                    if isinstance(admins, list):
                        for admin in admins[:10]:
                            admin_name = admin if isinstance(admin, str) else str(admin)
                            admin_node = self._create_node(admin_name, 'User', path_index)
                            nodes.append(admin_node)

                            edge = self._create_edge(
                                source=admin_name,
                                target=computer_name,
                                edge_type='ADMINTO',
                                query_info=query_info,
                                path_index=path_index,
                                result_index=result_index
                            )
                            edges.append(edge)
                    return nodes, edges

            # Case 4: Path results (including raw_path from converted results)
            if ('path' in result or 'p' in result) and 'source' not in result:
                path_data = result.get('path') or result.get('p')
                if isinstance(path_data, dict):
                    # Handle BloodHound CE segment-based path format
                    # Format: {start: {...}, end: {...}, segments: [{start, end, relationship}, ...]}
                    if 'segments' in path_data:
                        segments = path_data.get('segments', [])
                        logger.debug(f"📍 Processing BloodHound CE path with {len(segments)} segments")

                        # Add start node of the path
                        start_node_data = path_data.get('start')
                        if start_node_data:
                            node = self._create_node_from_path_data(start_node_data, path_index)
                            if node:
                                nodes.append(node)

                        # Process each segment
                        for seg_index, segment in enumerate(segments):
                            # Extract the end node of this segment
                            end_node_data = segment.get('end')
                            if end_node_data:
                                node = self._create_node_from_path_data(end_node_data, path_index)
                                if node:
                                    nodes.append(node)

                            # Extract the relationship
                            rel_data = segment.get('relationship', {})
                            if rel_data:
                                # Get source and target from segment's start/end
                                seg_start = segment.get('start', {})
                                seg_end = segment.get('end', {})
                                source_name = self._get_node_name(seg_start) if seg_start else None
                                target_name = self._get_node_name(seg_end) if seg_end else None
                                edge_type = rel_data.get('type', 'RELATED_TO')

                                if source_name and target_name and source_name != 'Unknown' and target_name != 'Unknown':
                                    edge = self._create_edge(
                                        source=source_name,
                                        target=target_name,
                                        edge_type=edge_type,
                                        query_info=query_info,
                                        path_index=path_index,
                                        result_index=result_index + seg_index
                                    )
                                    edges.append(edge)

                        if nodes:
                            logger.debug(f"✅ Extracted {len(nodes)} nodes and {len(edges)} edges from BloodHound CE segments")
                            return nodes, edges

                    # Handle standard Neo4j path format with nodes array
                    elif 'nodes' in path_data:
                        logger.debug(f"📍 Processing path with {len(path_data.get('nodes', []))} nodes")
                        for node_data in path_data['nodes']:
                            node = self._create_node_from_path_data(node_data, path_index)
                            if node:
                                nodes.append(node)

                        if 'relationships' in path_data:
                            for rel_data in path_data['relationships']:
                                edge = self._create_edge_from_path_data(rel_data, query_info, path_index, result_index)
                                if edge:
                                    edges.append(edge)
                        return nodes, edges

            # Case 5: Extract any AD entity patterns (fallback)
            if not nodes:
                for key, value in result.items():
                    if isinstance(value, str) and '@' in value:
                        node = self._create_node(value, 'Unknown', path_index)
                        nodes.append(node)
                    elif isinstance(value, dict) and 'name' in value:
                        name = value.get('name', '')
                        labels = value.get('labels', ['Unknown'])
                        node_type = labels[0] if labels else 'Unknown'
                        node = self._create_node(name, node_type, path_index)
                        nodes.append(node)
        
        except Exception as e:
            logger.debug(f"⚠️ Failed to parse result {result_index} in path {path_index}: {str(e)}")
        
        return nodes, edges
    
    def _create_node(self, name: str, node_type: str, path_index: int) -> Dict[str, Any]:
        """Create a node object for graph visualization"""
        
        # Clean and determine node type
        clean_name = str(name).strip()
        detected_type = self._detect_node_type(clean_name, node_type)
        
        # Generate unique ID - MUST match the ID format used in _create_edge
        node_id = f"node_{clean_name.replace('@', '_').replace('.', '_').replace(' ', '_').replace('$', '_')}"
        
        return {
            "id": node_id,
            "label": clean_name,
            "name": clean_name,
            "type": detected_type,
            "color": self.node_colors.get(detected_type, self.node_colors['Unknown']),
            "riskLevel": "High",  # Default for nodes in attack paths
            "inAttackPath": True,
            "pathIndex": path_index,
            "properties": {
                "original_name": name,
                "detected_type": detected_type
            }
        }
    
    def _create_edge(self, source: str, target: str, edge_type: str, query_info: Dict[str, Any], path_index: int, result_index: int) -> Dict[str, Any]:
        """Create an edge object for graph visualization"""
        
        # Clean edge type
        clean_edge_type = str(edge_type).upper().strip() if edge_type else 'UNKNOWN'
        
        # FIXED: Strip whitespace from source and target BEFORE generating IDs
        # This ensures edge source/target IDs match the node IDs created by _create_node
        source_stripped = str(source).strip()
        target_stripped = str(target).strip()
        
        # Generate cleaned versions for ID creation (must match _create_node logic)
        source_clean = source_stripped.replace('@', '_').replace('.', '_').replace(' ', '_').replace('$', '_')
        target_clean = target_stripped.replace('@', '_').replace('.', '_').replace(' ', '_').replace('$', '_')
        
        # Generate unique edge ID
        edge_id = f"edge_{path_index}_{result_index}_{source_clean}_to_{target_clean}"
        
        return {
            "id": edge_id,
            "source": f"node_{source_clean}",
            "target": f"node_{target_clean}",
            "label": clean_edge_type,
            "type": clean_edge_type,
            "color": self.edge_colors.get(clean_edge_type, self.edge_colors['default']),
            "riskLevel": "High",  # Default for edges in attack paths
            "inAttackPath": True,
            "pathIndex": path_index,
            "attack_type": query_info.get('attack_type', 'unknown'),
            "description": f"{clean_edge_type} relationship allowing {query_info.get('attack_type', 'attack progression')}",
            "properties": {
                "original_source": source,
                "original_target": target,
                "original_type": edge_type
            }
        }
    
    def _get_node_name(self, node_data: Dict[str, Any]) -> str:
        """
        Extract node name from various possible BloodHound property names.
        BloodHound CE may use different properties depending on node type.

        Node structure can be:
        1. Direct properties: {'name': 'USER@DOMAIN', ...}
        2. Nested in 'properties': {'id': ..., 'labels': [...], 'properties': {'name': 'USER@DOMAIN', ...}}
        """
        # Try common property names in order of preference
        name_properties = ['name', 'samaccountname', 'displayname', 'distinguishedname', 'objectid']

        # First, check if properties are nested (BloodHound CE format)
        props = node_data.get('properties', node_data)  # Use 'properties' if exists, else use node directly

        for prop in name_properties:
            value = props.get(prop)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

        # Also check at top level in case of mixed format
        if props is not node_data:
            for prop in name_properties:
                value = node_data.get(prop)
                if value and isinstance(value, str) and value.strip():
                    return value.strip()

        # Try to get from id or _id as fallback
        for id_prop in ['id', '_id', 'element_id']:
            value = node_data.get(id_prop)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

        # Last resort: try to find any string value that looks like an AD name
        for key, value in props.items():
            if isinstance(value, str) and '@' in value:
                return value

        return 'Unknown'

    def _create_node_from_path_data(self, node_data: Dict[str, Any], path_index: int) -> Optional[Dict[str, Any]]:
        """Create node from Neo4j path data structure"""
        try:
            # Use robust name extraction
            name = self._get_node_name(node_data)

            # Try to get labels from various possible keys
            # BloodHound CE format: {'id': ..., 'labels': [...], 'properties': {...}}
            # Standard format: {'_labels': [...], 'name': ...}
            labels = node_data.get('labels', node_data.get('_labels', []))
            if labels:
                # Use the first non-Base label as the type
                node_type = next((l for l in labels if l not in ['Base', 'Tag_Tier_Zero']), labels[0] if labels else 'Unknown')
            else:
                # Fall back to detection
                node_type = self._detect_node_type(name, 'Unknown')

            if name and name != 'Unknown':
                return self._create_node(name, node_type, path_index)
            else:
                logger.debug(f"⚠️ Could not extract node name from: {list(node_data.keys())}")
                return None
        except Exception as e:
            logger.debug(f"⚠️ Failed to create node from path data: {str(e)}")
            return None

    def _create_edge_from_path_data(self, rel_data: Dict[str, Any], query_info: Dict[str, Any], path_index: int, result_index: int) -> Optional[Dict[str, Any]]:
        """Create edge from Neo4j relationship data structure"""
        try:
            # Try to get source/target from start_node/end_node first
            start_node = rel_data.get('start_node', {})
            end_node = rel_data.get('end_node', {})

            source = self._get_node_name(start_node) if isinstance(start_node, dict) else str(start_node)
            target = self._get_node_name(end_node) if isinstance(end_node, dict) else str(end_node)
            edge_type = rel_data.get('type', 'UNKNOWN')

            if source and target and source != 'Unknown' and target != 'Unknown':
                return self._create_edge(source, target, edge_type, query_info, path_index, result_index)
            else:
                logger.debug(f"⚠️ Could not extract edge endpoints: source={source}, target={target}")
                return None
        except Exception as e:
            logger.debug(f"⚠️ Failed to create edge from path data: {str(e)}")
            return None
    
    def _detect_node_type(self, name: str, provided_type: str) -> str:
        """Detect node type from name patterns"""
        if provided_type and provided_type != 'Unknown':
            return provided_type

        name_lower = str(name).lower()

        # Group detection FIRST (common AD group patterns) - must come before domain check
        # because group names like "DOMAIN ADMINS@MARVEL.LOCAL" contain ".local"
        group_patterns = [
            'admin', 'group', 'users', 'operators', 'guests', 'power users',
            'domain controllers', 'enterprise', 'schema', 'backup', 'account operators',
            'print operators', 'server operators', 'replicator', 'incoming forest',
            'protected users', 'denied rodc', 'allowed rodc', 'dnsadmins',
            'exchange', 'organization management', 'cert publishers'
        ]
        if any(pattern in name_lower for pattern in group_patterns):
            return 'Group'

        # Domain detection - only match if the ENTIRE name looks like a domain
        # (not names that contain a domain suffix like "USER@DOMAIN.LOCAL")
        if '@' not in name and '.' in name:
            # Name doesn't have @, so it might be a pure domain like "MARVEL.LOCAL"
            if any(name_lower.endswith(tld) for tld in ['.local', '.com', '.org', '.net', '.lan']):
                return 'Domain'

        # Computer detection
        if any(indicator in name_lower for indicator in ['$', 'dc0', 'srv', 'server', 'ws0', 'pc0', 'laptop', 'workstation']):
            return 'Computer'

        # Service account detection
        if any(indicator in name_lower for indicator in ['svc', 'service', 'sql', 'iis', 'app']):
            return 'User'

        # Default to User for @ symbols (typical user accounts)
        if '@' in name:
            return 'User'

        return 'Unknown'
    
    def _priority_to_risk_level(self, priority: str) -> str:
        """Convert priority to risk level"""
        priority_map = {
            'Critical': 'Critical',
            'High': 'High', 
            'Medium': 'Medium',
            'Low': 'Low'
        }
        return priority_map.get(str(priority).title(), 'Medium')
    
    def _compare_risk_levels(self, new_risk: str, existing_risk: str) -> bool:
        """Return True if new_risk is higher than existing_risk"""
        risk_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        return risk_order.get(new_risk, 2) > risk_order.get(existing_risk, 2)
    
    def _generate_layout_hints(self, nodes: List[Dict], edges: List[Dict], paths: List[Dict]) -> Dict[str, Any]:
        """Generate layout hints for frontend visualization"""
        
        # Group nodes by path for better layout
        paths_layout = {}
        for path in paths:
            path_id = path['id']
            path_nodes = [n for n in nodes if n.get('pathIndex') == path.get('scenario_number', 0) - 1]
            path_edges = [e for e in edges if e.get('pathId') == path_id]
            
            paths_layout[path_id] = {
                "nodes": len(path_nodes),
                "edges": len(path_edges),
                "complexity": len(path_nodes) + len(path_edges),
                "risk_level": path.get('risk_level', 'Medium')
            }
        
        return {
            "suggested_layout": "hierarchical" if len(paths) > 2 else "force-directed",
            "paths_layout": paths_layout,
            "total_complexity": sum(p["complexity"] for p in paths_layout.values()),
            "max_nodes_per_path": max((p["nodes"] for p in paths_layout.values()), default=0)
        }