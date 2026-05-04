"""
Query Executor for Report Generation
Location: backend/routers/attack_paths/services/query_executor.py

Provides Neo4j query execution capabilities to RAG generators during report generation.
Allows the LLM to request additional data from the graph database.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)

# Maximum results to return per query (prevents massive outputs)
MAX_QUERY_RESULTS = 25

# Query patterns the model can request
QUERY_REQUEST_PATTERN = r'\{\{QUERY:\s*(.*?)\}\}'
QUERY_RESULT_PATTERN = r'\{\{RESULT:\s*(.*?)\}\}'


class QueryExecutor:
    """
    Provides safe query execution for LLM-driven report generation.

    Usage:
        executor = QueryExecutor(neo4j_service)

        # Execute a query and get formatted results
        results = executor.execute("MATCH (n:User) RETURN n.name LIMIT 10")

        # Process LLM output that may contain query requests
        final_output = executor.process_query_requests(llm_output)
    """

    def __init__(self, neo4j_service, add_log: Callable = None):
        """
        Initialize the query executor.

        Args:
            neo4j_service: Neo4j service instance with run_cypher_query method
            add_log: Optional logging callback
        """
        self.neo4j = neo4j_service
        self.add_log = add_log or (lambda *args, **kwargs: None)
        self._query_count = 0
        self._max_queries_per_generation = 5  # Limit queries per generation

    def execute(self, query: str, limit: int = MAX_QUERY_RESULTS) -> Dict[str, Any]:
        """
        Execute a Cypher query and return formatted results.

        Args:
            query: Cypher query to execute
            limit: Maximum results to return

        Returns:
            Dict with 'success', 'count', 'results', and 'summary' keys
        """
        if self._query_count >= self._max_queries_per_generation:
            return {
                'success': False,
                'error': 'Query limit reached for this generation',
                'count': 0,
                'results': [],
                'summary': 'Query limit reached'
            }

        # Validate query safety
        validation = self._validate_query(query)
        if not validation['safe']:
            return {
                'success': False,
                'error': validation['reason'],
                'count': 0,
                'results': [],
                'summary': f"Query blocked: {validation['reason']}"
            }

        # Add LIMIT if not present
        query_with_limit = self._ensure_limit(query, limit)

        try:
            self._query_count += 1
            self.add_log("DEBUG", f"  🔍 Executing ad-hoc query: {query[:80]}...", debug_only=True)

            results = self.neo4j.run_cypher_query(query_with_limit)

            # Format results for LLM consumption
            formatted = self._format_results(results, limit)

            self.add_log("DEBUG", f"  ✅ Query returned {formatted['count']} results", debug_only=True)

            return {
                'success': True,
                'count': formatted['count'],
                'results': formatted['results'],
                'summary': formatted['summary']
            }

        except Exception as e:
            error_msg = str(e)[:200]
            self.add_log("WARNING", f"  ⚠️ Query execution failed: {error_msg}")
            return {
                'success': False,
                'error': error_msg,
                'count': 0,
                'results': [],
                'summary': f"Query failed: {error_msg}"
            }

    def _validate_query(self, query: str) -> Dict[str, Any]:
        """
        Validate that a query is safe to execute.
        Only allows read operations.
        """
        query_upper = query.upper().strip()

        # Block write operations
        dangerous_keywords = [
            'CREATE', 'DELETE', 'REMOVE', 'SET', 'MERGE',
            'DROP', 'DETACH', 'CALL {', 'FOREACH'
        ]

        for keyword in dangerous_keywords:
            if keyword in query_upper:
                return {
                    'safe': False,
                    'reason': f'Write operation not allowed: {keyword}'
                }

        # Must start with MATCH, OPTIONAL MATCH, or WITH
        valid_starts = ['MATCH', 'OPTIONAL', 'WITH', 'CALL']
        if not any(query_upper.startswith(start) for start in valid_starts):
            return {
                'safe': False,
                'reason': 'Query must start with MATCH, OPTIONAL MATCH, WITH, or CALL'
            }

        return {'safe': True}

    def _ensure_limit(self, query: str, limit: int) -> str:
        """Ensure query has a LIMIT clause."""
        query_upper = query.upper()

        if 'LIMIT' not in query_upper:
            # Add LIMIT before any final semicolon
            query = query.rstrip(';').strip()
            query = f"{query} LIMIT {limit}"

        return query

    def _format_results(self, results: List[Dict], limit: int) -> Dict[str, Any]:
        """Format query results for LLM consumption."""
        if not results:
            return {
                'count': 0,
                'results': [],
                'summary': 'No results found'
            }

        # Truncate if needed
        truncated = results[:limit]
        count = len(results)

        # Build summary
        formatted_results = []
        for record in truncated:
            # Flatten nested structures for readability
            flat_record = self._flatten_record(record)
            formatted_results.append(flat_record)

        # Create text summary
        if count == 1:
            summary = f"Found 1 result"
        elif count <= limit:
            summary = f"Found {count} results"
        else:
            summary = f"Found {count} results (showing first {limit})"

        return {
            'count': count,
            'results': formatted_results,
            'summary': summary
        }

    def _flatten_record(self, record: Dict) -> Dict:
        """Flatten a record for easier LLM consumption."""
        flat = {}

        for key, value in record.items():
            if isinstance(value, dict):
                # Extract key properties from nested dicts (nodes)
                if 'name' in value:
                    flat[f'{key}_name'] = value['name']
                if '_labels' in value:
                    flat[f'{key}_type'] = value['_labels'][0] if value['_labels'] else 'Unknown'
                # Include other useful properties
                for prop in ['objectid', 'domain', 'enabled', 'admincount']:
                    if prop in value:
                        flat[f'{key}_{prop}'] = value[prop]
            elif isinstance(value, list):
                # Handle path nodes/relationships
                if value and isinstance(value[0], dict):
                    names = [v.get('name') or str(v) for v in value[:5]]
                    flat[key] = ' -> '.join(str(n) for n in names)
                else:
                    flat[key] = value
            else:
                flat[key] = value

        return flat

    def process_query_requests(self, text: str) -> str:
        """
        Process LLM output that may contain query requests.

        Looks for patterns like: {{QUERY: MATCH (n) RETURN n LIMIT 5}}
        Executes the query and replaces with: {{RESULT: [formatted results]}}

        Args:
            text: LLM output text that may contain query requests

        Returns:
            Text with query requests replaced by results
        """
        # Find all query requests
        matches = list(re.finditer(QUERY_REQUEST_PATTERN, text, re.DOTALL | re.IGNORECASE))

        if not matches:
            return text

        self.add_log("INFO", f"  🔄 Processing {len(matches)} embedded query request(s)")

        # Process each match (in reverse to preserve positions)
        for match in reversed(matches):
            query = match.group(1).strip()

            # Execute the query
            result = self.execute(query)

            # Format result for insertion
            if result['success']:
                if result['count'] == 0:
                    replacement = f"**Query Result:** No matching data found."
                else:
                    # Format results as a readable list
                    result_lines = [f"**Query Result:** {result['summary']}"]
                    for i, record in enumerate(result['results'][:10], 1):
                        # Create a readable line from the record
                        parts = []
                        for k, v in record.items():
                            if v and not k.startswith('_'):
                                parts.append(f"{k}: {v}")
                        if parts:
                            result_lines.append(f"  {i}. {', '.join(parts[:4])}")
                    replacement = '\n'.join(result_lines)
            else:
                replacement = f"**Query Error:** {result.get('error', 'Unknown error')}"

            # Replace the query request with the result
            text = text[:match.start()] + replacement + text[match.end():]

        return text

    def reset_query_count(self):
        """Reset the query counter for a new generation."""
        self._query_count = 0

    def pre_fetch_context(
        self,
        edges: List[str],
        sources: List[str],
        targets: List[str],
        domain: str,
        findings: List[Dict[str, Any]] = None,
    ) -> str:
        """
        Pre-fetch entity details from Neo4j based on edge types, returning
        a formatted text block to inject into the R1 prompt.

        Gives R1 concrete entity names so it generates real commands
        (bloodyAD, nxc, certipy) instead of Cypher queries.
        """
        lines: List[str] = []
        edges_upper = {e.upper() for e in edges}
        findings = findings or []

        # --- Group membership context (for ACL abuse on groups) ---
        acl_edges = {'GENERICALL', 'GENERICWRITE', 'WRITEDACL', 'WRITEOWNER',
                     'ADDMEMBER', 'ADDSELF', 'FORCECHANGEPASSWORD', 'ALLEXTENDEDRIGHTS'}
        if edges_upper & acl_edges:
            for target in targets[:3]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                result = self.execute(
                    f"MATCH (m)-[:MemberOf]->(g:Group {{name: '{full_name}'}}) "
                    f"RETURN m.name AS name, labels(m) AS labels LIMIT 10",
                    limit=10
                )
                if result['success'] and result['count'] > 0:
                    members = [r.get('name') or r.get('name_name') or '?' for r in result['results']]
                    lines.append(f"- Group \"{target}\" members: {', '.join(members[:8])}")
                elif result['success']:
                    lines.append(f"- Group \"{target}\" members: (none found)")

        # --- SPN context (for Kerberoasting paths) ---
        if edges_upper & {'KERBEROASTABLE', 'HASSPN'}:
            for source in sources[:3]:
                full_name = f"{source}@{domain}" if '@' not in source else source
                result = self.execute(
                    f"MATCH (u:User {{name: '{full_name}'}}) "
                    f"RETURN u.serviceprincipalnames AS spns LIMIT 1",
                    limit=1
                )
                if result['success'] and result['results']:
                    spns = result['results'][0].get('spns', [])
                    if spns:
                        spn_list = spns if isinstance(spns, list) else [spns]
                        spn_strs = [str(s) if s is not None else '?' for s in spn_list[:4]]
                        lines.append(f"- User \"{source}\" SPNs: {', '.join(spn_strs)}")

        # --- Computer hostname & OS (for lateral movement) ---
        lateral_edges = {'ADMINTO', 'CANRDP', 'CANPSREMOTE', 'EXECUTEDCOM', 'SQLADMIN'}
        if edges_upper & lateral_edges:
            for target in targets[:3]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                result = self.execute(
                    f"MATCH (c:Computer {{name: '{full_name}'}}) "
                    f"RETURN c.name AS name, c.operatingsystem AS os LIMIT 1",
                    limit=1
                )
                if result['success'] and result['results']:
                    rec = result['results'][0]
                    os_info = rec.get('os') or 'Unknown OS'
                    lines.append(f"- Computer \"{target}\": {os_info}")

        # --- ADCS context (CA names, template names) ---
        adcs_edges = {'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC5',
                      'ADCSESC6', 'ADCSESC7', 'ADCSESC8', 'ADCSESC9', 'ADCSESC10',
                      'ADCSESC11', 'ADCSESC13', 'ENROLL', 'AUTOENROLL', 'MANAGECA',
                      'MANAGECERTIFICATES', 'PUBLISHEDTO'}
        if edges_upper & adcs_edges:
            result = self.execute(
                "MATCH (ca:EnterpriseCA) RETURN ca.name AS name LIMIT 5",
                limit=5
            )
            if result['success'] and result['results']:
                ca_names = [r.get('name') or '?' for r in result['results']]
                lines.append(f"- Enterprise CAs: {', '.join(ca_names)}")

            result = self.execute(
                "MATCH (ct:CertTemplate) WHERE ct.authenticationenabled = true "
                "RETURN ct.name AS name LIMIT 10",
                limit=10
            )
            if result['success'] and result['results']:
                templates = [r.get('name') or '?' for r in result['results']]
                lines.append(f"- Auth-enabled templates: {', '.join(templates[:6])}")

        # --- Shadow credentials / key credential context ---
        if 'ADDKEYCREDENTIALLINK' in edges_upper:
            for target in targets[:2]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                result = self.execute(
                    f"MATCH (n {{name: '{full_name}'}}) "
                    f"RETURN n.name AS name, labels(n) AS labels, n.enabled AS enabled LIMIT 1",
                    limit=1
                )
                if result['success'] and result['results']:
                    rec = result['results'][0]
                    labels = rec.get('labels') or rec.get('labels_name') or 'Unknown'
                    enabled_val = rec.get('enabled')
                    lines.append(f"- Target \"{target}\": type={labels}, enabled={enabled_val if enabled_val is not None else '?'}")

        # --- GMSA / LAPS context ---
        if edges_upper & {'READGMSAPASSWORD', 'DUMPSMSAPASSWORD'}:
            for target in targets[:2]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                result = self.execute(
                    f"MATCH (n {{name: '{full_name}'}}) "
                    f"RETURN n.name AS name, labels(n) AS labels LIMIT 1",
                    limit=1
                )
                if result['success'] and result['results']:
                    lines.append(f"- gMSA target \"{target}\": service account with managed password")

        # --- DC hostname (always useful) ---
        result = self.execute(
            "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
            "RETURN c.name AS name LIMIT 1",
            limit=1
        )
        if result['success'] and result['results']:
            dc = result['results'][0].get('name') or '?'
            lines.append(f"- Domain Controller: {dc}")

        if not lines:
            return ""

        self.add_log("DEBUG", f"  📊 Pre-fetched {len(lines)} context items for R1", debug_only=True)
        return "## LIVE GRAPH DATA (from BloodHound)\n" + "\n".join(lines)


    @staticmethod
    def generate_context_queries(
        edges: List[str],
        sources: List[str],
        targets: List[str],
        domain: str,
        finding_index: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Generate context-enrichment Cypher queries based on edge types.

        Same logic as pre_fetch_context() but returns query dicts instead
        of executing them. The client executes these locally.

        Returns:
            List of dicts: {id, finding_index, query_type, cypher, entity_name}
        """
        queries: List[Dict[str, Any]] = []
        edges_upper = {e.upper() for e in edges}
        query_counter = 0

        def _add(query_type: str, cypher: str, entity_name: str = None):
            nonlocal query_counter
            queries.append({
                'id': f'ctx_{finding_index}_{query_counter}',
                'finding_index': finding_index,
                'query_type': query_type,
                'cypher': cypher,
                'entity_name': entity_name,
            })
            query_counter += 1

        # --- Group membership context (for ACL abuse on groups) ---
        acl_edges = {'GENERICALL', 'GENERICWRITE', 'WRITEDACL', 'WRITEOWNER',
                     'ADDMEMBER', 'ADDSELF', 'FORCECHANGEPASSWORD', 'ALLEXTENDEDRIGHTS'}
        if edges_upper & acl_edges:
            for target in targets[:3]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                _add(
                    'group_members',
                    f"MATCH (m)-[:MemberOf]->(g:Group {{name: '{full_name}'}}) "
                    f"RETURN m.name AS name, labels(m) AS labels LIMIT 10",
                    entity_name=target
                )

        # --- SPN context (for Kerberoasting paths) ---
        if edges_upper & {'KERBEROASTABLE', 'HASSPN'}:
            for source in sources[:3]:
                full_name = f"{source}@{domain}" if '@' not in source else source
                _add(
                    'spns',
                    f"MATCH (u:User {{name: '{full_name}'}}) "
                    f"RETURN u.serviceprincipalnames AS spns LIMIT 1",
                    entity_name=source
                )

        # --- Computer hostname & OS (for lateral movement) ---
        lateral_edges = {'ADMINTO', 'CANRDP', 'CANPSREMOTE', 'EXECUTEDCOM', 'SQLADMIN'}
        if edges_upper & lateral_edges:
            for target in targets[:3]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                _add(
                    'computer_info',
                    f"MATCH (c:Computer {{name: '{full_name}'}}) "
                    f"RETURN c.name AS name, c.operatingsystem AS os LIMIT 1",
                    entity_name=target
                )

        # --- ADCS context (CA names, template names) ---
        adcs_edges = {'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC5',
                      'ADCSESC6', 'ADCSESC7', 'ADCSESC8', 'ADCSESC9', 'ADCSESC10',
                      'ADCSESC11', 'ADCSESC13', 'ENROLL', 'AUTOENROLL', 'MANAGECA',
                      'MANAGECERTIFICATES', 'PUBLISHEDTO'}
        if edges_upper & adcs_edges:
            _add(
                'adcs_cas',
                "MATCH (ca:EnterpriseCA) RETURN ca.name AS name LIMIT 5",
            )
            _add(
                'adcs_templates',
                "MATCH (ct:CertTemplate) WHERE ct.authenticationenabled = true "
                "RETURN ct.name AS name LIMIT 10",
            )

        # --- Shadow credentials / key credential context ---
        if 'ADDKEYCREDENTIALLINK' in edges_upper:
            for target in targets[:2]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                _add(
                    'shadow_creds_target',
                    f"MATCH (n {{name: '{full_name}'}}) "
                    f"RETURN n.name AS name, labels(n) AS labels, n.enabled AS enabled LIMIT 1",
                    entity_name=target
                )

        # --- GMSA / LAPS context ---
        if edges_upper & {'READGMSAPASSWORD', 'DUMPSMSAPASSWORD'}:
            for target in targets[:2]:
                full_name = f"{target}@{domain}" if '@' not in target else target
                _add(
                    'gmsa_target',
                    f"MATCH (n {{name: '{full_name}'}}) "
                    f"RETURN n.name AS name, labels(n) AS labels LIMIT 1",
                    entity_name=target
                )

        # --- DC hostname (always useful, global query) ---
        _add(
            'dc_detection',
            "MATCH (c:Computer) WHERE c.unconstraineddelegation = true "
            "RETURN c.name AS name LIMIT 1",
        )
        # Override finding_index for DC detection to -1 (global)
        queries[-1]['finding_index'] = -1

        return queries

    @staticmethod
    def format_context_results(context_results: List[Dict[str, Any]]) -> Dict[int, str]:
        """
        Format client-executed context query results into text blocks per finding.

        Takes the executed context query results, groups by finding_index,
        and formats each group into the same "## LIVE GRAPH DATA" text block
        that pre_fetch_context() produces.

        Args:
            context_results: List of executed context query result dicts

        Returns:
            Dict mapping finding_index -> formatted text block
        """
        # Group results by finding_index
        grouped: Dict[int, List[Dict[str, Any]]] = {}
        dc_hostname = None

        for cr in context_results:
            idx = cr.get('finding_index', 0)
            if idx not in grouped:
                grouped[idx] = []
            grouped[idx].append(cr)

            # Extract DC hostname from global dc_detection query
            if cr.get('query_type') == 'dc_detection' and cr.get('results'):
                results = cr['results']
                if results and isinstance(results, list) and len(results) > 0:
                    dc_hostname = results[0].get('name')

        # Format each finding's context
        finding_context_map: Dict[int, str] = {}

        for idx, results in grouped.items():
            if idx == -1:
                continue  # Global queries (DC detection) handled separately

            lines: List[str] = []

            for cr in results:
                query_type = cr.get('query_type', '')
                entity_name = cr.get('entity_name', '?')
                records = cr.get('results', [])

                if not records:
                    if query_type == 'group_members':
                        lines.append(f"- Group \"{entity_name}\" members: (none found)")
                    continue

                if query_type == 'group_members':
                    members = [r.get('name') or '?' for r in records[:8]]
                    lines.append(f"- Group \"{entity_name}\" members: {', '.join(members)}")

                elif query_type == 'spns':
                    spns = records[0].get('spns', [])
                    if spns:
                        spn_list = spns if isinstance(spns, list) else [spns]
                        spn_strs = [str(s) for s in spn_list[:4] if s is not None]
                        if spn_strs:
                            lines.append(f"- User \"{entity_name}\" SPNs: {', '.join(spn_strs)}")

                elif query_type == 'computer_info':
                    rec = records[0]
                    os_info = rec.get('os') or 'Unknown OS'
                    lines.append(f"- Computer \"{entity_name}\": {os_info}")

                elif query_type == 'adcs_cas':
                    ca_names = [r.get('name') or '?' for r in records]
                    lines.append(f"- Enterprise CAs: {', '.join(ca_names)}")

                elif query_type == 'adcs_templates':
                    templates = [r.get('name') or '?' for r in records[:6]]
                    lines.append(f"- Auth-enabled templates: {', '.join(templates)}")

                elif query_type == 'shadow_creds_target':
                    rec = records[0]
                    labels = rec.get('labels') or 'Unknown'
                    enabled_val = rec.get('enabled')
                    lines.append(f"- Target \"{entity_name}\": type={labels}, enabled={enabled_val if enabled_val is not None else '?'}")

                elif query_type == 'gmsa_target':
                    lines.append(f"- gMSA target \"{entity_name}\": service account with managed password")

            # Add DC hostname if available
            if dc_hostname:
                lines.append(f"- Domain Controller: {dc_hostname}")

            if lines:
                finding_context_map[idx] = "## LIVE GRAPH DATA (from BloodHound)\n" + "\n".join(lines)

        return finding_context_map


def get_query_instruction() -> str:
    """
    Returns instruction text to include in prompts that tells the LLM
    how to request queries during generation.
    """
    return """
## QUERY EXECUTION CAPABILITY
You can request data from the BloodHound graph database during generation.
To request a query, use this exact format:

{{QUERY: MATCH (n:User)-[:MemberOf]->(g:Group) WHERE g.name = 'DOMAIN ADMINS@DOMAIN.LOCAL' RETURN n.name}}

The query will be executed and results will be included in your output.
Use this when you need to:
- Verify additional relationships
- Get specific entity details
- Check for related attack paths

RULES:
- Only use READ queries (MATCH, not CREATE/DELETE)
- Include LIMIT in your queries (max 25 results)
- Only request queries when the data would improve the report
- Don't request queries for data you already have in the context
"""
