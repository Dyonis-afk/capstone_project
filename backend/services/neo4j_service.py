"""Basic Neo4j operations: connection, BloodHound import, Cypher execution, stats."""

import logging
import os
from typing import List, Dict, Any, Optional
from neo4j import GraphDatabase, Transaction
from neo4j.exceptions import Neo4jError
import json
from datetime import datetime

# Import project filtering middleware
from utils.cypher_middleware import (
    inject_project_filter,
    get_project_data_check_query,
    get_project_clear_query,
    add_project_to_properties,
    PROJECT_PROPERTY
)

logger = logging.getLogger(__name__)

class Neo4jService:
    """Simplified Neo4j service for basic graph operations"""
    
    def __init__(self, uri: str = None, username: str = None, password: str = None):
        """Initialize Neo4j connection"""
        self.uri = uri or os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        # Support both NEO4J_USER and NEO4J_USERNAME for compatibility
        self.username = username or os.getenv('NEO4J_USER') or os.getenv('NEO4J_USERNAME', 'neo4j')
        self.password = password or os.getenv('NEO4J_PASSWORD', 'bloodhoundcommunityedition')
        
        # Log connection details (without password) for debugging
        logger.info(f"🔌 Initializing Neo4j connection: {self.uri}, user: {self.username}")
        
        self.driver = None
        self._connect()
    
    def _connect(self):
        """Establish connection to Neo4j database"""
        try:
            # Close existing driver if any
            if self.driver:
                try:
                    self.driver.close()
                except:
                    pass
            
            logger.info(f"🔌 Attempting to connect to Neo4j at {self.uri} with user '{self.username}'")
            logger.debug(f"   Password length: {len(self.password) if self.password else 0}")
            
            self.driver = GraphDatabase.driver(
                self.uri, 
                auth=(self.username, self.password),
                max_connection_lifetime=3600,
                keep_alive=True,
                connection_timeout=10  # 10 second timeout
            )
            # Test connection with explicit error handling
            try:
                self.driver.verify_connectivity()
                logger.info(f"✅ Connected to Neo4j at {self.uri} successfully")
            except Exception as verify_error:
                # Close driver on verification failure
                try:
                    self.driver.close()
                except:
                    pass
                self.driver = None
                raise verify_error
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Failed to connect to Neo4j: {error_msg}")
            logger.error(f"   URI: {self.uri}")
            logger.error(f"   Username: {self.username}")
            logger.error(f"   Password set: {'Yes' if self.password else 'No'} (length: {len(self.password) if self.password else 0})")
            # Don't raise immediately - allow lazy connection retry
            self.driver = None
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("🔒 Neo4j connection closed")
    
    def test_connection(self) -> Dict[str, Any]:
        """Test if Neo4j connection is working and return connection details"""
        try:
            # Try to reconnect if driver is None or connection failed
            if not self.driver:
                logger.info("🔄 Driver not initialized, attempting to reconnect...")
                try:
                    self._connect()
                except Exception as reconnect_error:
                    logger.error(f"❌ Reconnection attempt failed: {str(reconnect_error)}")
            
            if not self.driver:
                return {
                    "connected": False,
                    "database": None,
                    "node_count": None,
                    "relationship_count": None,
                    "error": "Driver not initialized - check credentials and Neo4j status"
                }
            
            with self.driver.session() as session:
                # Test basic connectivity
                result = session.run("RETURN 1 as test")
                test_value = result.single()["test"]
                
                if test_value != 1:
                    return {
                        "connected": False,
                        "database": None,
                        "node_count": None,
                        "relationship_count": None,
                        "error": "Connection test returned unexpected value"
                    }
                
                # Get database statistics
                db_result = session.run("CALL db.info() YIELD name RETURN name as database")
                database = None
                try:
                    db_record = db_result.single()
                    if db_record:
                        database = db_record.get("database", "neo4j")
                except:
                    database = "neo4j"  # Default database name
                
                # Get node count
                node_result = session.run("MATCH (n) RETURN count(n) as count")
                node_count = node_result.single()["count"] if node_result else 0
                
                # Get relationship count
                rel_result = session.run("MATCH ()-[r]->() RETURN count(r) as count")
                relationship_count = rel_result.single()["count"] if rel_result else 0
                
                logger.info(f"✅ Neo4j connection test successful - Database: {database}, Nodes: {node_count}, Relationships: {relationship_count}")
                
                return {
                    "connected": True,
                    "database": database,
                    "node_count": node_count,
                    "relationship_count": relationship_count,
                    "error": None
                }
        except Exception as e:
            error_msg = str(e)
            logger.error(f"❌ Neo4j connection test failed: {error_msg}")
            return {
                "connected": False,
                "database": None,
                "node_count": None,
                "relationship_count": None,
                "error": error_msg
            }
    
    def check_project_data(self, project_id: str) -> Dict[str, Any]:
        """
        Check if a project has existing data in Neo4j.
        
        Args:
            project_id: The project ID to check
            
        Returns:
            Dictionary with data status and statistics
        """
        logger.info(f"🔍 Checking data for project: {project_id}")
        
        try:
            query, params = get_project_data_check_query(project_id)
            
            with self.driver.session() as session:
                result = session.run(query, params)
                record = result.single()
                
                if record is None:
                    return {
                        "has_existing_data": False,
                        "total_nodes": 0,
                        "total_relationships": 0,
                        "users": 0,
                        "groups": 0,
                        "computers": 0,
                        "recommendation": "ready_for_import",
                        "message": "No existing data found. Ready for import.",
                        "estimated_clear_time": "instant"
                    }
                
                total_nodes = record.get("total_nodes", 0) or 0
                total_rels = record.get("total_relationships", 0) or 0
                users = record.get("users", 0) or 0
                groups = record.get("groups", 0) or 0
                computers = record.get("computers", 0) or 0
                
                has_data = total_nodes > 0 or total_rels > 0
                
                # Estimate clear time
                total_items = total_nodes + total_rels
                if total_items < 1000:
                    est_time = "< 5 seconds"
                elif total_items < 10000:
                    est_time = "5-15 seconds"
                elif total_items < 100000:
                    est_time = "15-60 seconds"
                else:
                    est_time = "1-5 minutes"
                
                recommendation = "user_choice_required" if has_data else "ready_for_import"
                message = f"Found {total_nodes:,} nodes and {total_rels:,} relationships." if has_data else "Ready for import."
                
                return {
                    "has_existing_data": has_data,
                    "total_nodes": total_nodes,
                    "total_relationships": total_rels,
                    "users": users,
                    "groups": groups,
                    "computers": computers,
                    "recommendation": recommendation,
                    "message": message,
                    "estimated_clear_time": est_time
                }
                
        except Exception as e:
            logger.error(f"❌ Error checking project data: {str(e)}")
            return {
                "has_existing_data": False,
                "total_nodes": 0,
                "total_relationships": 0,
                "users": 0,
                "groups": 0,
                "computers": 0,
                "recommendation": "ready_for_import",
                "message": f"Error checking data: {str(e)}",
                "estimated_clear_time": "unknown",
                "error": str(e)
            }

    def get_domain_statistics(self, project_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive domain statistics from Neo4j.

        Returns:
            Dictionary with domain overview data including:
            - domain_name, forest_name, functional_level
            - total_users, total_groups, total_computers, domain_controllers
        """
        logger.info(f"📊 Getting domain statistics...")

        try:
            with self.driver.session() as session:
                # Get domain info
                domain_query = """
                MATCH (d:Domain)
                RETURN d.name as domain_name,
                       d.functionallevel as functional_level,
                       d.distinguishedname as dn
                LIMIT 1
                """
                domain_result = session.run(domain_query)
                domain_record = domain_result.single()

                domain_name = domain_record["domain_name"] if domain_record else "Unknown"
                functional_level = domain_record["functional_level"] if domain_record else None

                # Map functional level number to name
                functional_level_map = {
                    0: "Windows 2000",
                    1: "Windows Server 2003 Interim",
                    2: "Windows Server 2003",
                    3: "Windows Server 2008",
                    4: "Windows Server 2008 R2",
                    5: "Windows Server 2012",
                    6: "Windows Server 2012 R2",
                    7: "Windows Server 2016",
                }
                functional_level_str = functional_level_map.get(functional_level, f"Level {functional_level}") if functional_level is not None else "Unknown"

                # Count users
                users_query = "MATCH (u:User) RETURN count(u) as count"
                users_result = session.run(users_query)
                total_users = users_result.single()["count"]

                # Count groups
                groups_query = "MATCH (g:Group) RETURN count(g) as count"
                groups_result = session.run(groups_query)
                total_groups = groups_result.single()["count"]

                # Count computers
                computers_query = "MATCH (c:Computer) RETURN count(c) as count"
                computers_result = session.run(computers_query)
                total_computers = computers_result.single()["count"]

                # Count domain controllers
                dc_query = """
                MATCH (c:Computer)
                WHERE c.isdc = true OR
                      toLower(c.name) CONTAINS 'dc' OR
                      EXISTS((c)-[:MemberOf*1..3]->(:Group {name: 'DOMAIN CONTROLLERS@' + c.domain}))
                RETURN count(DISTINCT c) as count
                """
                dc_result = session.run(dc_query)
                domain_controllers = dc_result.single()["count"]

                # Count OUs
                ou_query = "MATCH (o:OU) RETURN count(o) as count"
                ou_result = session.run(ou_query)
                total_ous = ou_result.single()["count"]

                # Count GPOs
                gpo_query = "MATCH (g:GPO) RETURN count(g) as count"
                gpo_result = session.run(gpo_query)
                total_gpos = gpo_result.single()["count"]

                logger.info(f"✅ Domain stats: {domain_name} - {total_users} users, {total_groups} groups, {total_computers} computers, {domain_controllers} DCs")

                return {
                    "domain_name": domain_name,
                    "forest_name": domain_name,  # Often same as domain for single-forest
                    "functional_level": functional_level_str,
                    "total_users": total_users,
                    "total_groups": total_groups,
                    "total_computers": total_computers,
                    "domain_controllers": domain_controllers,
                    "total_ous": total_ous,
                    "total_gpos": total_gpos,
                    "collection_method": "BloodHound CE"
                }

        except Exception as e:
            logger.error(f"❌ Error getting domain statistics: {str(e)}")
            return {
                "domain_name": "Unknown",
                "forest_name": "Unknown",
                "functional_level": "Unknown",
                "total_users": 0,
                "total_groups": 0,
                "total_computers": 0,
                "domain_controllers": 0,
                "total_ous": 0,
                "total_gpos": 0,
                "collection_method": "BloodHound CE",
                "error": str(e)
            }

    def clear_project_data(self, project_id: str) -> Dict[str, Any]:
        """
        Delete all nodes and relationships for a specific project.

        Args:
            project_id: The project ID to clear

        Returns:
            Dictionary with deletion results
        """
        logger.info(f"🗑️ Clearing all data for project: {project_id}")
        
        try:
            query, params = get_project_clear_query(project_id)
            
            with self.driver.session() as session:
                result = session.run(query, params)
                summary = result.consume()
                
                nodes_deleted = summary.counters.nodes_deleted
                rels_deleted = summary.counters.relationships_deleted
                
                logger.info(f"✅ Cleared project {project_id}: {nodes_deleted} nodes, {rels_deleted} relationships")
                
                return {
                    "success": True,
                    "nodes_deleted": nodes_deleted,
                    "relationships_deleted": rels_deleted
                }
                
        except Exception as e:
            logger.error(f"❌ Error clearing project data: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "nodes_deleted": 0,
                "relationships_deleted": 0
            }
    
    def clear_database(self):
        """Clear all data from Neo4j database (use with caution)"""
        logger.warning("🗑️ Clearing entire Neo4j database...")
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.info("✅ Neo4j database cleared")
    
    def create_constraints_and_indexes(self):
        """Create necessary constraints and indexes for optimal performance"""
        logger.info("🔧 Creating Neo4j constraints and indexes...")
        
        constraints_and_indexes = [
            # Constraints for uniqueness
            "CREATE CONSTRAINT user_name_unique IF NOT EXISTS FOR (u:User) REQUIRE u.name IS UNIQUE",
            "CREATE CONSTRAINT group_name_unique IF NOT EXISTS FOR (g:Group) REQUIRE g.name IS UNIQUE", 
            "CREATE CONSTRAINT computer_name_unique IF NOT EXISTS FOR (c:Computer) REQUIRE c.name IS UNIQUE",
            "CREATE CONSTRAINT domain_name_unique IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            
            # Indexes for performance
            "CREATE INDEX user_enabled IF NOT EXISTS FOR (u:User) ON (u.enabled)",
            "CREATE INDEX user_admin_count IF NOT EXISTS FOR (u:User) ON (u.admincount)",
            "CREATE INDEX group_admin_count IF NOT EXISTS FOR (g:Group) ON (g.admincount)",
            "CREATE INDEX computer_enabled IF NOT EXISTS FOR (c:Computer) ON (c.enabled)",
            "CREATE INDEX user_spn IF NOT EXISTS FOR (u:User) ON (u.hasspn)",
            "CREATE INDEX group_high_value IF NOT EXISTS FOR (g:Group) ON (g.highvalue)",
            
            # Composite indexes for common queries
            "CREATE INDEX user_enabled_admin IF NOT EXISTS FOR (u:User) ON (u.enabled, u.admincount)",
            # Index for project filtering (important for performance)
            f"CREATE INDEX node_project IF NOT EXISTS FOR (n) ON (n.{PROJECT_PROPERTY})"
        ]
        
        with self.driver.session() as session:
            for cmd in constraints_and_indexes:
                try:
                    session.run(cmd)
                    logger.debug(f"✅ Created: {cmd.split('IF NOT EXISTS')[0].strip()}")
                except Exception as e:
                    logger.warning(f"⚠️ Constraint/index might already exist: {str(e)}")
    
    def import_bloodhound_data(self, parsed_bloodhound_data: Dict[str, Any], project_id: str = None) -> bool:
        """
        Import BloodHound data from your existing parser into Neo4j
        
        Args:
            parsed_bloodhound_data: Output from your BloodHoundParser.parse_json()
            
        Returns:
            bool: Success status
        """
        logger.info("📊 Starting BloodHound data import to Neo4j...")
        
        try:
            # Create constraints and indexes first
            self.create_constraints_and_indexes()
            
            # Import in batches for better performance
            with self.driver.session() as session:
                # Import nodes and relationships from findings
                self._import_findings_to_graph(session, parsed_bloodhound_data, project_id)
                
            logger.info("✅ BloodHound data import completed successfully")
            
            # Log statistics
            if project_id:
                stats = self.check_project_data(project_id)
                logger.info(f"📊 Project {project_id} statistics: {stats['total_nodes']} nodes, {stats['total_relationships']} relationships")
            else:
                stats = self.get_database_statistics()
                logger.info(f"📊 Database statistics: {stats}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ BloodHound data import failed: {str(e)}")
            return False
    
    def debug_bloodhound_data(self, bloodhound_data: Dict[str, Any]):
            """Debug the structure of BloodHound data to understand what we're working with"""
            logger.info("🔍 DEBUG: Analyzing BloodHound data structure...")
            
            # Show top-level structure
            logger.info(f"📋 Top-level keys: {list(bloodhound_data.keys())}")
            
            # Analyze findings by risk level
            for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
                findings = bloodhound_data.get(risk_level, [])
                logger.info(f"📊 {risk_level}: {len(findings)} findings")
                
                if findings:
                    # Show structure of first finding in detail
                    first_finding = findings[0]
                    logger.info(f"🔍 First {risk_level} finding structure:")
                    logger.info(f"   Keys: {list(first_finding.keys())}")
                    logger.info(f"   Full finding: {first_finding}")
                    
                    # Show a few more for pattern recognition
                    if len(findings) > 1:
                        logger.info(f"🔍 Second {risk_level} finding:")
                        logger.info(f"   Keys: {list(findings[1].keys())}")
                        logger.info(f"   Source: {findings[1].get('source')}")
                        logger.info(f"   Target: {findings[1].get('target')}")
                        logger.info(f"   Edge type: {findings[1].get('edge_type')}")
                    
                    if len(findings) > 2:
                        logger.info(f"🔍 Third {risk_level} finding:")
                        logger.info(f"   Keys: {list(findings[2].keys())}")
                        logger.info(f"   Source: {findings[2].get('source')}")
                        logger.info(f"   Target: {findings[2].get('target')}")
                        logger.info(f"   Edge type: {findings[2].get('edge_type')}")
            
            # Show summary if available
            summary = bloodhound_data.get('summary', {})
            logger.info(f"📋 Summary: {summary}")
            
            # Count total findings being extracted
            total_extracted = (len(bloodhound_data.get('high_risk', [])) + 
                            len(bloodhound_data.get('medium_risk', [])) + 
                            len(bloodhound_data.get('low_risk', [])))
            
            expected_total = summary.get('high_risk_count', 0) + summary.get('medium_risk_count', 0) + summary.get('low_risk_count', 0)
            
            logger.info(f"🔍 EXTRACTION MISMATCH:")
            logger.info(f"   Expected total findings: {expected_total}")
            logger.info(f"   Actually extracted: {total_extracted}")
            logger.info(f"   Missing: {expected_total - total_extracted}")
            
            if total_extracted != expected_total:
                logger.warning("⚠️ MAJOR ISSUE: Most findings are not being extracted!")
                logger.warning("   This suggests the BloodHound data structure doesn't match expectations")
                logger.warning("   The parser created 37k+ findings but we're only seeing 5")
                
                # Show what other keys might contain the findings
                logger.info("🔍 Looking for findings in other keys:")
                for key, value in bloodhound_data.items():
                    if key not in ['high_risk', 'medium_risk', 'low_risk', 'summary']:
                        if isinstance(value, list):
                            logger.info(f"   Found list in '{key}': {len(value)} items")
                            if value and isinstance(value[0], dict):
                                logger.info(f"     Sample item keys: {list(value[0].keys())}")
                        elif isinstance(value, dict):
                            logger.info(f"   Found dict in '{key}': {list(value.keys())}")

    def _import_findings_to_graph(self, session, bloodhound_data: Dict[str, Any], project_id: str = None):
        """Import nodes and relationships - FIXED FOR CAMEL CASE FIELDS"""
        logger.info(f"🔗 Importing BloodHound findings to graph (project: {project_id or 'GLOBAL'})...")
        
        # Debug the data structure first
        self.debug_bloodhound_data(bloodhound_data)
        
        # Extract all findings from your existing parser output
        all_findings = []
        all_findings.extend(bloodhound_data.get('high_risk', []))
        all_findings.extend(bloodhound_data.get('medium_risk', []))
        all_findings.extend(bloodhound_data.get('low_risk', []))
        
        # CHECK: Is there a complete data source we're missing?
        summary = bloodhound_data.get('summary', {})
        expected_total = (summary.get('high_risk_count', 0) + 
                         summary.get('medium_risk_count', 0) + 
                         summary.get('low_risk_count', 0))
        
        if len(all_findings) < expected_total * 0.1:  # Less than 10% of expected
            logger.warning(f"🔍 Only found {len(all_findings)} findings but expected {expected_total}")
            self.investigate_missing_findings(bloodhound_data)
            
            logger.warning("🔍 Looking for complete findings in raw_json or other sources...")
            
            # Try to get the complete findings from raw data
            raw_json = bloodhound_data.get('raw_json')
            if raw_json:
                logger.info("🔍 Found raw_json, attempting to re-parse...")
                try:
                    # You might need to re-parse the raw JSON to get all findings
                    # This is a temporary debugging step
                    import json
                    if isinstance(raw_json, str):
                        raw_data = json.loads(raw_json)
                        logger.info(f"🔍 Raw JSON structure: {list(raw_data.keys()) if isinstance(raw_data, dict) else 'Not a dict'}")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to parse raw_json: {e}")
        
        if not all_findings:
            logger.warning("⚠️ No findings to import")
            return
        
        logger.info(f"📊 Found {len(all_findings)} total findings to import")
        
        # Collect unique nodes and relationships - FIXED FIELD NAMES
        nodes = set()
        relationships = []
        
        for finding in all_findings:
            # Extract source and target nodes
            if 'source' in finding and finding['source']:
                nodes.add(finding['source'])
            if 'target' in finding and finding['target']:
                nodes.add(finding['target'])
            
            # FIXED: Use camelCase field names that your parser actually outputs
            relationships.append({
                'source': finding.get('source'),
                'target': finding.get('target'),
                'edge_type': finding.get('edgeType'),  # ← FIXED: was 'edge_type'
                'risk_level': finding.get('riskLevel'),  # ← FIXED: was 'risk_level'
                'source_type': finding.get('sourceType'),  # ← FIXED: was 'source_type'
                'target_type': finding.get('targetType'),  # ← FIXED: was 'target_type'
                'explanation': finding.get('explanation', '')
            })
        
        logger.info(f"📊 Extracted {len(nodes)} unique nodes and {len(relationships)} relationships")
        
        # Show sample relationships with corrected fields
        logger.info("🔍 Sample relationships with corrected field mapping:")
        for i, rel in enumerate(relationships[:3]):
            logger.info(f"  {i+1}. {rel['source']} -[{rel['edge_type']}]-> {rel['target']}")
        
        # Create nodes and relationships in batches
        if nodes:
            self._create_nodes_batch(session, list(nodes), project_id=project_id)
        
        if relationships:
            # Use optimized batch method for fast relationship creation
            self._create_relationships_batch(session, relationships, project_id=project_id)  # ✅ Good (1000 batch)
            # OR for maximum speed (uncomment to use):
            # self._create_relationships_with_transaction_batching(relationships)  # 🚀 Even faster (5000 batch)
        
        logger.info("✅ BloodHound findings imported successfully")

    def investigate_missing_findings(self, bloodhound_data: Dict[str, Any]):
        """Investigate why 37k+ findings are missing from the import"""
        logger.info("🔍 INVESTIGATING: Why are most findings missing?")
        
        summary = bloodhound_data.get('summary', {})
        expected_high = summary.get('high_risk_count', 0)
        expected_medium = summary.get('medium_risk_count', 0) 
        expected_low = summary.get('low_risk_count', 0)
        
        actual_high = len(bloodhound_data.get('high_risk', []))
        actual_medium = len(bloodhound_data.get('medium_risk', []))
        actual_low = len(bloodhound_data.get('low_risk', []))
        
        logger.info(f"📊 SUMMARY MISMATCH:")
        logger.info(f"   High Risk - Expected: {expected_high}, Actual: {actual_high}, Missing: {expected_high - actual_high}")
        logger.info(f"   Medium Risk - Expected: {expected_medium}, Actual: {actual_medium}, Missing: {expected_medium - actual_medium}")
        logger.info(f"   Low Risk - Expected: {expected_low}, Actual: {actual_low}, Missing: {expected_low - actual_low}")
        
        # Check if findings are being stored elsewhere during upload processing
        logger.warning("🚨 CRITICAL ISSUE: Findings are being lost between parser and import!")
        logger.warning("   This suggests a problem in the upload processing pipeline")
        logger.warning("   The BloodHound parser is working but data is lost during transfer")
        
        # Recommend investigation points
        logger.info("🔧 INVESTIGATION NEEDED:")
        logger.info("   1. Check bloodhound router upload endpoint - are all findings being passed?")
        logger.info("   2. Check if findings are being truncated due to memory/size limits")
        logger.info("   3. Check if findings are stored in a different data structure")
        logger.info("   4. Consider direct parser integration instead of pre-processed data")
        
    def _create_nodes_batch(self, session, nodes: List[str], batch_size: int = 1000, project_id: str = None):
        """
        Create nodes in batches for better performance
        
        Args:
            session: Neo4j session  
            nodes: List of node names
            batch_size: Batch size for node creation
        """
        if not nodes:
            return
            
        logger.info(f"👥 Creating {len(nodes)} nodes in batches...")
        
        # Process nodes in batches
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(nodes) + batch_size - 1) // batch_size
            
            logger.info(f"👥 Processing node batch {batch_num}/{total_batches} ({len(batch)} nodes)")
            
            try:
                if project_id:
                    # Create nodes WITH project tagging
                    cypher_query = f"""
                    UNWIND $batch as node_name
                    MERGE (n {{name: node_name, {PROJECT_PROPERTY}: $project_id}})
                    ON CREATE SET n.created_at = datetime()
                    RETURN count(n) as created
                    """
                    result = session.run(cypher_query, batch=batch, project_id=project_id)
                else:
                    # Legacy: Create nodes without project tagging
                    cypher_query = """
                    UNWIND $batch as node_name
                    MERGE (n {name: node_name})
                    ON CREATE SET n.created_at = datetime()
                    RETURN count(n) as created
                    """
                    result = session.run(cypher_query, batch=batch)
                
                created_count = result.single()["created"]
                logger.info(f"✅ Created {created_count} nodes in batch {batch_num}")
                
            except Exception as e:
                logger.error(f"❌ Node batch {batch_num} failed: {str(e)}")
                continue
        
        logger.info("👥 Node creation complete")
    

    def _create_relationships_batch(self, session, relationships: List[Dict[str, Any]], batch_size: int = 1000, project_id: str = None):
        """
        Create relationships in batches for massive performance improvement
        
        Args:
            session: Neo4j session
            relationships: List of relationship data
            batch_size: Number of relationships per batch (default 1000)
        """
        if not relationships:
            logger.warning("⚠️ No relationships to create")
            return
        
        logger.info(f"🔗 Creating {len(relationships)} relationships in batches of {batch_size}...")
        
        success_count = 0
        error_count = 0
        
        # Process relationships in batches
        for i in range(0, len(relationships), batch_size):
            batch = relationships[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(relationships) + batch_size - 1) // batch_size
            
            logger.info(f"🔗 Processing batch {batch_num}/{total_batches} ({len(batch)} relationships)")
            
            try:
                # Group relationships by edge type for efficient batching
                edge_type_groups = {}
                for rel in batch:
                    edge_type = rel.get('edge_type')
                    if not edge_type:
                        continue
                        
                    # Clean edge type for Cypher
                    clean_edge_type = edge_type.upper().replace(' ', '_').replace('-', '_')
                    clean_edge_type = ''.join(c for c in clean_edge_type if c.isalnum() or c == '_')
                    
                    if clean_edge_type not in edge_type_groups:
                        edge_type_groups[clean_edge_type] = []
                    
                    edge_type_groups[clean_edge_type].append({
                        'source': rel.get('source'),
                        'target': rel.get('target'),
                        'risk_level': rel.get('risk_level', 'Unknown'),
                        'source_type': rel.get('source_type', 'Unknown'),
                        'target_type': rel.get('target_type', 'Unknown'),
                        'original_edge_type': rel.get('edge_type', edge_type)
                    })
                
                # Create relationships for each edge type in batch
                for edge_type, rel_batch in edge_type_groups.items():
                    batch_success = self._create_relationships_by_type_batch(session, edge_type, rel_batch, project_id=project_id)
                    success_count += batch_success
                    
            except Exception as e:
                logger.error(f"❌ Batch {batch_num} failed: {str(e)}")
                error_count += len(batch)
                continue
        
        logger.info(f"🔗 Relationship creation complete: {success_count} success, {error_count} errors")
        
        # Get final count
        try:
            count_result = session.run("MATCH ()-[r]->() RETURN count(r) as total")
            total_relationships = count_result.single()["total"]
            logger.info(f"📊 Total relationships in database: {total_relationships}")
        except Exception as e:
            logger.warning(f"⚠️ Failed to get relationship count: {str(e)}")
    
    def _create_relationships_by_type_batch(self, session, edge_type: str, relationships: List[Dict[str, Any]], project_id: str = None) -> int:
        """
        Create a batch of relationships of the same type using UNWIND
        
        Args:
            session: Neo4j session
            edge_type: Edge type (e.g., 'OWNS', 'MEMBEROF')
            relationships: List of relationship data
            
        Returns:
            Number of relationships created successfully
        """
        if not relationships or not edge_type:
            return 0
        
        try:
            if project_id:
                # Create relationships WITH project tagging
                cypher_query = f"""
                UNWIND $batch as row
                MATCH (source {{name: row.source, {PROJECT_PROPERTY}: $project_id}})
                MATCH (target {{name: row.target, {PROJECT_PROPERTY}: $project_id}})
                MERGE (source)-[r:{edge_type} {{{PROJECT_PROPERTY}: $project_id}}]->(target)
                ON CREATE SET 
                    r.risk_level = row.risk_level,
                    r.source_type = row.source_type,
                    r.target_type = row.target_type,
                    r.original_edge_type = row.original_edge_type,
                    r.created_at = datetime()
                RETURN count(r) as created
                """
                result = session.run(cypher_query, batch=relationships, project_id=project_id)
            else:
                # Legacy: Create relationships without project tagging
                cypher_query = f"""
                UNWIND $batch as row
                MATCH (source {{name: row.source}})
                MATCH (target {{name: row.target}})
                MERGE (source)-[r:{edge_type}]->(target)
                ON CREATE SET 
                    r.risk_level = row.risk_level,
                    r.source_type = row.source_type,
                    r.target_type = row.target_type,
                    r.original_edge_type = row.original_edge_type,
                    r.created_at = datetime()
                RETURN count(r) as created
                """
                result = session.run(cypher_query, batch=relationships)
            
            created_count = result.single()["created"]
            
            logger.info(f"✅ Created {created_count} {edge_type} relationships")
            return created_count
            
        except Exception as e:
            logger.error(f"❌ Failed to create {edge_type} relationships: {str(e)}")
            return 0
    
    def _create_relationships_fallback(self, session, relationships: List[Dict]):
        """Fallback relationship creation without APOC"""
        logger.info("🔧 Using fallback relationship creation...")
        
        for rel in relationships:
            try:
                # Use dynamic relationship type (requires escaping)
                edge_type = rel['edge_type'].upper().replace(' ', '_')
                
                cypher_query = f"""
                MATCH (source {{name: $source}})
                MATCH (target {{name: $target}})
                CREATE (source)-[r:{edge_type} {{
                    risk_level: $risk_level,
                    created_at: datetime(),
                    source_type: $source_type,
                    target_type: $target_type
                }}]->(target)
                RETURN r
                """
                
                session.run(cypher_query, 
                           source=rel['source'],
                           target=rel['target'],
                           risk_level=rel['risk_level'],
                           source_type=rel['source_type'],
                           target_type=rel['target_type'])
                           
            except Exception as e:
                logger.debug(f"⚠️ Failed to create relationship {rel['source']} -> {rel['target']}: {str(e)}")
                continue
    
    def _create_relationships_with_transaction_batching(self, relationships: List[Dict[str, Any]]):
        """
        Ultra-fast relationship creation using explicit transactions
        Use this if you want maximum performance
        """
        logger.info(f"🚀 Creating {len(relationships)} relationships with transaction batching...")
        
        batch_size = 5000  # Larger batches for transactions
        success_count = 0
        
        for i in range(0, len(relationships), batch_size):
            batch = relationships[i:i + batch_size]
            
            try:
                with self.driver.session() as session:
                    with session.begin_transaction() as tx:
                        # Group by edge type
                        edge_type_groups = {}
                        for rel in batch:
                            edge_type = rel.get('edge_type', '').upper().replace(' ', '_')
                            if edge_type not in edge_type_groups:
                                edge_type_groups[edge_type] = []
                            edge_type_groups[edge_type].append(rel)
                        
                        # Create all edge types in this transaction
                        for edge_type, rel_batch in edge_type_groups.items():
                            if not edge_type:
                                continue
                                
                            cypher = f"""
                            UNWIND $batch as row
                            MATCH (s {{name: row.source}})
                            MATCH (t {{name: row.target}})
                            MERGE (s)-[r:{edge_type}]->(t)
                            SET r.risk_level = row.risk_level
                            """
                            
                            tx.run(cypher, batch=[{
                                'source': r.get('source'),
                                'target': r.get('target'), 
                                'risk_level': r.get('risk_level', 'Unknown')
                            } for r in rel_batch])
                        
                        # Commit transaction
                        tx.commit()
                        success_count += len(batch)
                        logger.info(f"✅ Transaction batch complete: {success_count}/{len(relationships)}")
                        
            except Exception as e:
                logger.error(f"❌ Transaction batch failed: {str(e)}")
                continue
        
        logger.info(f"🚀 Transaction batching complete: {success_count} relationships created")
    
    def run_cypher_query(self, cypher_query: str, parameters: Dict[str, Any] = None, project_id: str = None) -> List[Dict[str, Any]]:
        """
        Execute a Cypher query and return results

        Args:
            cypher_query: The Cypher query to execute
            parameters: Optional query parameters
            project_id: Optional project ID (DEPRECATED - BloodHound CE uses single-dataset model)

        Returns:
            List of result records as dictionaries
        """
        if parameters is None:
            parameters = {}

        # NOTE: BloodHound CE uses a single-dataset model. Project isolation is handled
        # at the BloodHound CE level, not by tagging nodes with _aegis_project properties.
        # The inject_project_filter is disabled as BloodHound data doesn't have these tags.
        # if project_id:
        #     cypher_query, parameters = inject_project_filter(cypher_query, project_id, parameters)

        logger.info(f"🔍 Executing Cypher query: {cypher_query[:100]}...")

        if not self.driver:
            logger.warning("⚠️ Neo4j driver not available - skipping query execution")
            return []

        try:
            with self.driver.session() as session:
                result = session.run(cypher_query, parameters or {})
                
                # Convert records to list of dictionaries
                records = []
                for record in result:
                    record_dict = {}
                    for key in record.keys():
                        value = record[key]
                        
                        # Handle Neo4j specific types
                        if hasattr(value, 'nodes') and hasattr(value, 'relationships'):
                            # It's a path - extract full node and relationship data
                            path_nodes = []
                            for node in value.nodes:
                                node_data = dict(node)
                                # Add labels as a list
                                node_data['_labels'] = list(node.labels) if hasattr(node, 'labels') else []
                                node_data['_id'] = node.element_id if hasattr(node, 'element_id') else str(node.id)
                                path_nodes.append(node_data)
                                # Log first node for debugging
                                if len(path_nodes) == 1:
                                    logger.debug(f"📊 Path node sample - keys: {list(node_data.keys())}, name: {node_data.get('name', 'N/A')}, labels: {node_data.get('_labels', [])}")

                            path_rels = []
                            for i, rel in enumerate(value.relationships):
                                rel_data = dict(rel)
                                # Add relationship type and endpoint info
                                rel_data['type'] = rel.type if hasattr(rel, 'type') else 'UNKNOWN'
                                # Store start/end node names from the path nodes
                                if i < len(path_nodes) - 1:
                                    rel_data['start_node'] = {'name': path_nodes[i].get('name', '')}
                                    rel_data['end_node'] = {'name': path_nodes[i + 1].get('name', '')}
                                path_rels.append(rel_data)

                            record_dict[key] = {
                                'nodes': path_nodes,
                                'relationships': path_rels,
                                'length': len(value.nodes) - 1
                            }
                        elif hasattr(value, 'labels') and hasattr(value, 'items'):
                            # It's a Neo4j Node - convert to dict with labels
                            node_data = dict(value)
                            node_data['_labels'] = list(value.labels) if hasattr(value, 'labels') else []
                            node_data['_id'] = value.element_id if hasattr(value, 'element_id') else str(value.id) if hasattr(value, 'id') else None
                            record_dict[key] = node_data
                            logger.debug(f"📊 Single node - keys: {list(node_data.keys())}, name: {node_data.get('name', 'N/A')}, labels: {node_data.get('_labels', [])}")
                        elif hasattr(value, '__iter__') and not isinstance(value, str):
                            # It's a list
                            record_dict[key] = list(value)
                        else:
                            record_dict[key] = value
                    
                    records.append(record_dict)
                
                logger.info(f"✅ Query completed: {len(records)} results")
                return records
                
        except Exception as e:
            logger.error(f"❌ Cypher query failed: {str(e)}")
            return []
    
    def get_database_statistics(self, project_id: str = None) -> Dict[str, Any]:
        """Get database statistics for monitoring and reporting"""
        if project_id:
            # Project-specific statistics
            return self.check_project_data(project_id)
        
        # Global statistics (legacy)
        stats_queries = {
            "total_nodes": "MATCH (n) RETURN count(n) as count",
            "total_relationships": "MATCH ()-[r]->() RETURN count(r) as count", 
            "users": "MATCH (u:User) RETURN count(u) as count",
            "groups": "MATCH (g:Group) RETURN count(g) as count",
            "computers": "MATCH (c:Computer) RETURN count(c) as count",
            "domains": "MATCH (d:Domain) RETURN count(d) as count",
            "high_value_groups": "MATCH (g:Group) WHERE g.highvalue = true RETURN count(g) as count",
            "service_accounts": "MATCH (u:User) WHERE u.hasspn = true RETURN count(u) as count"
        }
        
        stats = {}
        with self.driver.session() as session:
            for stat_name, query in stats_queries.items():
                try:
                    result = session.run(query)
                    stats[stat_name] = result.single()["count"]
                except Exception as e:
                    logger.warning(f"⚠️ Failed to get {stat_name} statistic: {str(e)}")
                    stats[stat_name] = 0
        
        return stats
    
    def get_environment_summary(self, project_id: str = None) -> Dict[str, Any]:
        """
        Get a summary of the environment for RAG analysis
        
        Args:
            project_id: Optional project ID to filter results
            
        Returns:
            Dictionary with environment information for RAG processing
        """
        logger.info(f"📋 Generating environment summary for RAG analysis (project: {project_id or 'GLOBAL'})...")
        
        # Build project filter if needed
        if project_id:
            project_filter = f" WHERE d.{PROJECT_PROPERTY} = $project_id"
            params = {"project_id": project_id}
        else:
            project_filter = ""
            params = {}
        
        summary_queries = {
            "domain_names": f"MATCH (d:Domain){project_filter} RETURN DISTINCT d.name as name",
            "domain_admin_groups": f"MATCH (g:Group){project_filter.replace('d.', 'g.')} WHERE g.name CONTAINS 'DOMAIN ADMIN' RETURN g.name as name",
            "high_value_groups": f"MATCH (g:Group){project_filter.replace('d.', 'g.')} WHERE g.highvalue = true RETURN g.name as name",
            "service_accounts": f"MATCH (u:User){project_filter.replace('d.', 'u.')} WHERE u.hasspn = true RETURN u.name as name LIMIT 10",
            "computers": f"MATCH (c:Computer){project_filter.replace('d.', 'c.')} RETURN c.name as name LIMIT 10",
            "admin_users": f"MATCH (u:User){project_filter.replace('d.', 'u.')} WHERE u.admincount = true RETURN u.name as name LIMIT 10"
        }
        
        summary = {}
        with self.driver.session() as session:
            for category, query in summary_queries.items():
                try:
                    result = session.run(query, params)
                    summary[category] = [record["name"] for record in result]
                except Exception as e:
                    logger.warning(f"⚠️ Failed to get {category}: {str(e)}")
                    summary[category] = []
        
        logger.info("✅ Environment summary generated")
        return summary
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.close()


# Example usage and testing
if __name__ == "__main__":
    # Test Neo4j connection and basic operations
    try:
        neo4j_service = Neo4jService()
        
        # Test connection
        if neo4j_service.test_connection():
            print("✅ Neo4j connection successful")
            
            # Get statistics
            stats = neo4j_service.get_database_statistics()
            print(f"📊 Database stats: {stats}")
            
            # Get environment summary
            env_summary = neo4j_service.get_environment_summary()
            print(f"🌍 Environment summary: {env_summary}")
            
        else:
            print("❌ Neo4j connection failed")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
    finally:
        neo4j_service.close()