"""
ResultStore - Ground truth data storage for Neo4j query results.

This is the single source of truth for all entity data. Every finding
must reference specific row IDs from this store.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class StoredResult:
    """A single stored result row from a Neo4j query."""
    row_id: str
    query_name: str
    source: str
    source_type: str
    target: str
    target_type: str
    edge_type: str
    properties: Dict[str, Any] = field(default_factory=dict)


class ResultStore:
    """
    Stores Neo4j results with unique IDs.
    All entity data MUST come from here - no exceptions.
    """

    def __init__(self):
        self.results: Dict[str, StoredResult] = {}
        self._entity_index: Dict[str, str] = {}  # entity_name -> first row_id

    def store(self, query_name: str, raw_results: List[Dict[str, Any]]) -> List[str]:
        """
        Store results and return assigned row IDs.

        Args:
            query_name: Name of the query that produced these results
            raw_results: List of result dictionaries from Neo4j

        Returns:
            List of assigned row IDs (format: "query_name:index")
        """
        row_ids = []

        for i, row in enumerate(raw_results):
            row_id = f"{query_name}:{i}"

            source = row.get('source', '')
            target = row.get('target', '')

            stored = StoredResult(
                row_id=row_id,
                query_name=query_name,
                source=source,
                source_type=row.get('source_type', 'Unknown'),
                target=target,
                target_type=row.get('target_type', 'Unknown'),
                edge_type=row.get('edge_type', 'Unknown'),
                properties=row.get('source_properties', {}),
            )

            self.results[row_id] = stored
            row_ids.append(row_id)

            # Index entities for lookup
            if source and source not in self._entity_index:
                self._entity_index[source] = row_id
            if target and target not in self._entity_index:
                self._entity_index[target] = row_id

        return row_ids

    def get(self, row_id: str) -> Optional[StoredResult]:
        """
        Get a stored result by row ID.

        Args:
            row_id: The unique row ID (format: "query_name:index")

        Returns:
            StoredResult if found, None otherwise
        """
        return self.results.get(row_id)

    def get_entity(self, name: str) -> Optional[StoredResult]:
        """
        Look up entity by name - returns first occurrence.

        Used to validate that an entity actually exists in the data.

        Args:
            name: Entity name to look up

        Returns:
            StoredResult containing this entity, or None if not found
        """
        row_id = self._entity_index.get(name)
        if row_id:
            return self.results.get(row_id)
        return None

    def get_all_entities(self) -> List[str]:
        """Get all unique entity names in the store."""
        return list(self._entity_index.keys())

    def clear(self):
        """Clear all stored results."""
        self.results.clear()
        self._entity_index.clear()
