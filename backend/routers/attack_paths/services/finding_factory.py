"""
FindingFactory - Creates findings anchored to ground-truth data.

Every finding MUST reference specific result row IDs. If a finding
can't be traced to data, it's rejected.
"""
from typing import List, Optional

from .result_store import ResultStore, StoredResult
from .entity_resolver import EntityResolver
from .deduplicator import Finding


class FindingFactory:
    """
    Creates findings anchored to ground-truth data.
    Every finding MUST reference specific result row IDs.
    """

    def __init__(self, result_store: ResultStore, entity_resolver: EntityResolver):
        self.store = result_store
        self.resolver = entity_resolver

    def create_finding(
        self,
        query_name: str,
        row_ids: List[str],
        severity: str,
    ) -> Optional[Finding]:
        """
        Create a finding from specific result rows.

        Args:
            query_name: Name of the query that produced these results
            row_ids: List of result row IDs (REQUIRED - must cite source data)
            severity: Severity level for this finding

        Returns:
            Finding if validation passes, None if rejected
        """
        # 1. Verify all row_ids exist
        results: List[StoredResult] = []
        for rid in row_ids:
            result = self.store.get(rid)
            if result is None:
                return None  # Invalid row reference - reject
            results.append(result)

        if not results:
            return None

        # 2. Extract entities FROM results (not generated)
        sources = list(set(r.source for r in results if r.source))
        targets = list(set(r.target for r in results if r.target))
        edge_types = list(set(r.edge_type for r in results if r.edge_type))

        # 3. Resolve and validate all entities exist
        for source in sources:
            if not self.resolver.resolve(source):
                return None  # Unknown entity - reject

        for target in targets:
            if not self.resolver.resolve(target):
                return None  # Unknown entity - reject

        # 4. Determine compromisable entity (for remediation)
        compromisable_entity = self._identify_compromisable(results)

        # 5. Build finding with ONLY ground-truth data
        return Finding(
            query_name=query_name,
            result_row_ids=row_ids,
            sources=sources,
            targets=targets,
            edge_types=edge_types,
            compromisable_entity=compromisable_entity,
            severity=severity,
        )

    def _identify_compromisable(self, results: List[StoredResult]) -> Optional[str]:
        """
        Identify the actual vulnerable entity from results.

        Uses node properties (hasspn, dontreqpreauth) and entity roles
        to determine which entity should be the focus of remediation.

        Args:
            results: List of stored results for this finding

        Returns:
            Entity name that is compromisable, or None
        """
        # Priority 1: User with hasspn (Kerberoastable)
        for r in results:
            props = r.properties or {}
            if props.get('hasspn') and r.source_type == 'User':
                return r.source

        # Priority 2: User with dontreqpreauth (AS-REP Roastable)
        for r in results:
            props = r.properties or {}
            if props.get('dontreqpreauth') and r.source_type == 'User':
                return r.source

        # Priority 3: User with delegation properties
        for r in results:
            props = r.properties or {}
            if (props.get('trustedtoauth') or props.get('unconstraineddelegation')) and r.source_type == 'User':
                return r.source

        # Priority 4: Any User source (for ACL abuse, etc.)
        for r in results:
            if r.source_type == 'User':
                return r.source

        # Fallback: First source
        return results[0].source if results else None
