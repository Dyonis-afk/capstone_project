"""
Efficient Smart BloodHound Query Builder
Uses existing RAG service for edge intelligence, scans database for available edges
"""

import logging
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)

class SmartQueryBuilder:
    """
    Builds adaptive attack path queries using available database edges
    and existing RAG service for intelligence
    """
    
    def __init__(self, neo4j_service, rag_service):
        self.neo4j_service = neo4j_service
        self.rag_service = rag_service
        self.available_edges = set()
        
        # Basic attack categories - will adapt based on available edges
        self.attack_patterns = {
            'privilege_escalation': {
                'description': 'Direct privilege escalation through permissions',
                'target_edges': ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'AllExtendedRights', 'GenericWrite'],
                'priority': 'Critical'
            },
            'group_manipulation': {
                'description': 'Group membership attacks',
                'target_edges': ['AddMember', 'AddSelf', 'MemberOf'],
                'priority': 'High'
            },
            'lateral_movement': {
                'description': 'Remote access and lateral movement',
                'target_edges': ['AdminTo', 'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'HasSession'],
                'priority': 'Medium'
            },
            'credential_access': {
                'description': 'Password and credential attacks',
                'target_edges': ['ReadLAPSPassword', 'DCSync', 'ForceChangePassword'],
                'priority': 'High'
            }
        }
    
    def scan_available_edges(self) -> List[Dict]:
        """Scan database to find what edge types actually exist"""
        logger.info("🔍 Scanning database for available edge types...")
        
        query = """
        MATCH ()-[r]->()
        RETURN DISTINCT type(r) as edge_type, count(r) as count
        ORDER BY count DESC
        """
        
        try:
            results = self.neo4j_service.run_cypher_query(query)
            self.available_edges = {result['edge_type'] for result in results}
            
            logger.info(f"📊 Found {len(self.available_edges)} edge types:")
            for result in results:
                logger.info(f"   {result['edge_type']}: {result['count']} instances")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Failed to scan edges: {str(e)}")
            return []
    
    def get_matching_edges_for_pattern(self, pattern_name: str) -> List[str]:
        """Find which edges from a pattern are actually available in the database"""
        if pattern_name not in self.attack_patterns:
            return []
        
        target_edges = self.attack_patterns[pattern_name]['target_edges']
        matching_edges = []
        
        for target_edge in target_edges:
            # Check exact match first
            if target_edge in self.available_edges:
                matching_edges.append(target_edge)
            else:
                # Check case-insensitive variations (GENERICALL, GenericAll, etc.)
                for available_edge in self.available_edges:
                    if target_edge.upper() == available_edge.upper():
                        matching_edges.append(available_edge)
                        break
        
        return matching_edges
    
    def build_edge_filter(self, pattern_names: List[str]) -> Optional[str]:
        """Build Cypher edge filter for given patterns"""
        all_edges = []
        
        for pattern_name in pattern_names:
            edges = self.get_matching_edges_for_pattern(pattern_name)
            all_edges.extend(edges)
        
        if not all_edges:
            return None
        
        # Remove duplicates
        unique_edges = list(set(all_edges))
        return '|'.join(unique_edges)
    
    def generate_adaptive_queries(self) -> List[Dict]:
        """Generate attack queries based on available edges"""
        logger.info("🧠 Generating adaptive attack queries...")
        
        # Scan what edges are available
        edge_results = self.scan_available_edges()
        
        if not self.available_edges:
            logger.warning("⚠️ No edges found in database")
            return []
        
        queries = []
        
        # Generate queries for each pattern that has available edges
        for pattern_name, pattern_info in self.attack_patterns.items():
            matching_edges = self.get_matching_edges_for_pattern(pattern_name)
            
            if not matching_edges:
                logger.info(f"⏭️ Skipping {pattern_name} - no matching edges available")
                continue
            
            edge_filter = '|'.join(matching_edges)
            
            # Build query based on pattern type
            if pattern_name == 'privilege_escalation':
                query = f"""
                MATCH (source)-[r:{edge_filter}]->(target:Group)
                WHERE source.enabled = true AND (target.admincount = true OR target.name CONTAINS 'ADMIN')
                RETURN source.name as source, type(r) as edge_type, target.name as target,
                       labels(source)[0] as source_type, labels(target)[0] as target_type,
                       CASE WHEN target.highvalue = true THEN 'Critical'
                            WHEN target.name CONTAINS 'ADMIN' THEN 'High'
                            ELSE 'Medium' END as risk_level
                ORDER BY risk_level, target.name
                """
            
            elif pattern_name == 'group_manipulation':
                query = f"""
                MATCH (source)-[r:{edge_filter}]->(target:Group)
                WHERE source.enabled = true AND target.admincount = true
                RETURN source.name as source, type(r) as edge_type, target.name as target,
                       labels(source)[0] as source_type, labels(target)[0] as target_type,
                       CASE WHEN target.name CONTAINS 'DOMAIN ADMIN' THEN 'Critical'
                            WHEN target.name CONTAINS 'ENTERPRISE ADMIN' THEN 'Critical'
                            WHEN target.admincount = true THEN 'High'
                            ELSE 'Medium' END as risk_level
                ORDER BY risk_level, target.name
                """
            
            elif pattern_name == 'lateral_movement':
                query = f"""
                MATCH (source)-[r:{edge_filter}]->(target:Computer)
                WHERE source.enabled = true
                RETURN source.name as source, type(r) as edge_type, target.name as target,
                       labels(source)[0] as source_type, labels(target)[0] as target_type,
                       'Medium' as risk_level
                ORDER BY target.name
                """
            
            elif pattern_name == 'credential_access':
                query = f"""
                MATCH (source)-[r:{edge_filter}]->(target)
                WHERE source.enabled = true
                RETURN source.name as source, type(r) as edge_type, target.name as target,
                       labels(source)[0] as source_type, labels(target)[0] as target_type,
                       'High' as risk_level
                ORDER BY target.name
                """
            
            else:
                # Generic query for other patterns
                query = f"""
                MATCH (source)-[r:{edge_filter}]->(target)
                WHERE source.enabled = true
                RETURN source.name as source, type(r) as edge_type, target.name as target,
                       labels(source)[0] as source_type, labels(target)[0] as target_type
                ORDER BY target.name
                """
            
            queries.append({
                'name': pattern_info['description'],
                'pattern': pattern_name,
                'edges_used': matching_edges,
                'priority': pattern_info['priority'],
                'query': query.strip(),
                'description': f"Using available edges: {', '.join(matching_edges)}"
            })
        
        # Add multi-step attack paths if we have high-priority edges
        high_priority_edges = []
        for pattern in ['privilege_escalation', 'group_manipulation', 'credential_access']:
            high_priority_edges.extend(self.get_matching_edges_for_pattern(pattern))
        
        if high_priority_edges:
            unique_high_edges = list(set(high_priority_edges))
            edge_filter = '|'.join(unique_high_edges)
            
            queries.append({
                'name': 'Multi-Step Attack Paths',
                'pattern': 'multi_step',
                'edges_used': unique_high_edges,
                'priority': 'Critical',
                'query': f"""
                MATCH p=(start)-[r1:{edge_filter}]->(middle)-[r2:{edge_filter}]->(end)
                WHERE start.enabled = true AND end.admincount = true
                AND start <> end AND middle <> start AND middle <> end
                RETURN start.name as source,
                       [rel in relationships(p) | type(rel)] as attack_path,
                       end.name as target,
                       labels(start)[0] as source_type,
                       labels(end)[0] as target_type,
                       length(p) as path_length,
                       'Critical' as risk_level
                ORDER BY path_length, end.name
                """.strip(),
                'description': f"Complex attack chains using: {', '.join(unique_high_edges)}"
            })
        
        # Add additional comprehensive queries for common attack patterns
        # GenericAll Abuse (Critical Findings)
        if 'GENERICALL' in self.available_edges or 'GenericAll' in self.available_edges:
            genericall_edge = 'GENERICALL' if 'GENERICALL' in self.available_edges else 'GenericAll'
            queries.append({
                'name': 'Critical ACL Abuse - GenericAll',
                'pattern': 'genericall_abuse',
                'edges_used': [genericall_edge],
                'priority': 'Critical',
                'query': f"""
                MATCH (source)-[r:{genericall_edge}]->(target)
                WHERE target.highvalue = true OR 
                      target.name CONTAINS 'ADMIN' OR
                      labels(target) = ['Group']
                RETURN source.name as source, target.name as target,
                       '{genericall_edge}' as edge_type, 
                       labels(source)[0] as source_type,
                       labels(target)[0] as target_type,
                       CASE WHEN target.highvalue = true THEN 'Critical'
                            WHEN target.name CONTAINS 'ADMIN' THEN 'High'
                            ELSE 'Medium' END as risk_level
                ORDER BY risk_level, target.name
                """.strip(),
                'description': f'Users/groups with {genericall_edge} permissions on high-value targets'
            })
        
        # WriteDacl Abuse (High Findings)
        if 'WRITEDACL' in self.available_edges or 'WriteDacl' in self.available_edges:
            writedacl_edge = 'WRITEDACL' if 'WRITEDACL' in self.available_edges else 'WriteDacl'
            queries.append({
                'name': 'ACL Modification Rights - WriteDacl',
                'pattern': 'writedacl_abuse',
                'edges_used': [writedacl_edge],
                'priority': 'High',
                'query': f"""
                MATCH (source)-[r:{writedacl_edge}]->(target)
                RETURN source.name as source, target.name as target,
                       '{writedacl_edge}' as edge_type,
                       labels(source)[0] as source_type,
                       labels(target)[0] as target_type,
                       CASE WHEN target.highvalue = true THEN 'Critical'
                            WHEN labels(target) = ['Group'] THEN 'High'
                            ELSE 'Medium' END as risk_level
                ORDER BY risk_level, target.name
                """.strip(),
                'description': f'Ability to modify object permissions via {writedacl_edge}'
            })
        
        # Ownership Issues
        ownership_edges = []
        if 'OWNS' in self.available_edges:
            ownership_edges.append('OWNS')
        if 'WRITEOWNER' in self.available_edges or 'WriteOwner' in self.available_edges:
            ownership_edges.append('WRITEOWNER' if 'WRITEOWNER' in self.available_edges else 'WriteOwner')
        
        if ownership_edges:
            edge_filter = '|'.join(ownership_edges)
            queries.append({
                'name': 'Object Ownership Issues',
                'pattern': 'ownership_abuse',
                'edges_used': ownership_edges,
                'priority': 'High',
                'query': f"""
                MATCH (source)-[r:{edge_filter}]->(target)
                WHERE target.highvalue = true OR labels(target) = ['Group']
                RETURN source.name as source, target.name as target,
                       type(r) as edge_type,
                       labels(source)[0] as source_type,
                       labels(target)[0] as target_type,
                       'High' as risk_level
                ORDER BY target.name
                """.strip(),
                'description': f'Ownership and ownership modification rights: {", ".join(ownership_edges)}'
            })
        
        # Service Account Issues
        queries.append({
            'name': 'Service Account Vulnerabilities',
            'pattern': 'service_account_abuse',
            'edges_used': list(self.available_edges),
            'priority': 'Medium',
            'query': """
            MATCH (source)-[r]->(target)
            WHERE (source.name CONTAINS 'SVC' OR source.name CONTAINS 'SERVICE'
                   OR source.serviceprincipalname IS NOT NULL)
                  AND source.enabled = true
            RETURN source.name as source, target.name as target,
                   type(r) as edge_type,
                   labels(source)[0] as source_type,
                   labels(target)[0] as target_type,
                   CASE WHEN target.highvalue = true THEN 'High'
                        WHEN labels(target) = ['Group'] AND target.admincount = true THEN 'High'
                        ELSE 'Medium' END as risk_level
            ORDER BY risk_level, source.name
            """.strip(),
            'description': 'Service accounts with excessive privileges'
        })
        
        # Always add edge summary for debugging
        queries.append({
            'name': 'Available Edge Types',
            'pattern': 'summary',
            'edges_used': list(self.available_edges),
            'priority': 'Info',
            'query': """
            MATCH ()-[r]->()
            RETURN DISTINCT type(r) as edge_type, count(r) as count
            ORDER BY count DESC
            """.strip(),
            'description': 'Summary of all available edge types in database'
        })
        
        logger.info(f"✅ Generated {len(queries)} adaptive queries")
        logger.info(f"📊 Patterns covered: {', '.join(set(q['pattern'] for q in queries))}")
        
        return queries
    
    def get_edge_explanation(self, edge_type: str) -> str:
        """Use RAG service to get explanation for an edge type"""
        try:
            rag_query = f"What is the {edge_type} BloodHound edge type? Explain the attack method, detection, and remediation."
            explanation = self.rag_service.query(rag_query)
            return explanation
            
        except Exception as e:
            logger.warning(f"⚠️ Could not get RAG explanation for {edge_type}: {str(e)}")
            return f"No explanation available for {edge_type}"
    
    def explain_attack_scenario(self, edge_type: str, source: str, target: str) -> str:
        """Generate detailed explanation for a specific attack scenario using RAG"""
        try:
            rag_query = f"""
            Explain this BloodHound attack scenario:
            - Edge Type: {edge_type}
            - Source: {source}
            - Target: {target}
            
            Provide attack method, remediation steps, and detection guidance.
            """
            
            explanation = self.rag_service.query(rag_query)
            return explanation
            
        except Exception as e:
            logger.warning(f"⚠️ Could not generate scenario explanation: {str(e)}")
            return f"Attack scenario: {source} can use {edge_type} against {target}"
    
    def execute_smart_queries(self) -> List[Dict]:
        """Execute all adaptive queries and return results with explanations"""
        queries = self.generate_adaptive_queries()
        results = []
        
        for query_info in queries:
            logger.info(f"🔍 Executing: {query_info['name']}")
            
            try:
                query_results = self.neo4j_service.run_cypher_query(query_info['query'])
                
                results.append({
                    'name': query_info['name'],
                    'pattern': query_info['pattern'],
                    'priority': query_info['priority'],
                    'edges_used': query_info['edges_used'],
                    'description': query_info['description'],
                    'query': query_info['query'],  # Include the Cypher query for reference
                    'results': query_results,
                    'result_count': len(query_results),
                    # ✅ ADD: Explicit field names for frontend compatibility
                    'cypher_query': query_info['query'],  # Explicit field name for frontend
                    'query_name': query_info['name'],
                    'query_description': query_info['description']
                })
                
                logger.info(f"✅ Found {len(query_results)} results")
                
            except Exception as e:
                logger.error(f"❌ Query failed: {str(e)}")
                results.append({
                    'name': query_info['name'],
                    'pattern': query_info['pattern'],
                    'priority': query_info['priority'],
                    'edges_used': query_info['edges_used'],
                    'description': query_info['description'],
                    'query': query_info['query'],  # Include the Cypher query for reference
                    'results': [],
                    'result_count': 0,
                    'error': str(e),
                    # ✅ ADD: Explicit field names for frontend compatibility
                    'cypher_query': query_info['query'],  # Explicit field name for frontend
                    'query_name': query_info['name'],
                    'query_description': query_info['description']
                })
        
        return results