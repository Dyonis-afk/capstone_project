"""
EntityResolver - Type-safe entity resolution and validation.

Ensures entity names come FROM the data and operations match entity types.
Prevents groups being treated as users, etc.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional

from .result_store import ResultStore, StoredResult


# Operations allowed per entity type
ALLOWED_OPERATIONS: Dict[str, List[str]] = {
    'User': [
        'reset_password',
        'disable_account',
        'remove_spn',
        'set_preauth',
        'remove_from_group',
        'modify_acl',
    ],
    'Computer': [
        'disable_account',
        'remove_delegation',
        'remove_from_group',
        'modify_acl',
    ],
    'Group': [
        'remove_member',
        'modify_acl',
        'delete_group',
    ],
    'Domain': [
        'modify_policy',
        'modify_acl',
    ],
    'GPO': [
        'modify_gpo',
        'unlink_gpo',
    ],
}


@dataclass
class ResolvedEntity:
    """An entity resolved against ground-truth data."""
    name: str
    type: str
    row_id: str


class EntityResolver:
    """
    Resolves and validates entities against ground truth.
    Prevents groups being treated as users, etc.
    """

    def __init__(self, result_store: ResultStore):
        self.store = result_store
        self._resolved_cache: Dict[str, ResolvedEntity] = {}

    def resolve(self, entity_name: str) -> Optional[ResolvedEntity]:
        """
        Resolve an entity name to its ground-truth data.

        Args:
            entity_name: The entity name to resolve

        Returns:
            ResolvedEntity if found in data, None otherwise
        """
        if entity_name in self._resolved_cache:
            return self._resolved_cache[entity_name]

        # Search through all stored results
        for row_id, result in self.store.results.items():
            if result.source == entity_name:
                entity = ResolvedEntity(
                    name=result.source,
                    type=result.source_type,
                    row_id=row_id,
                )
                self._resolved_cache[entity_name] = entity
                return entity

            if result.target == entity_name:
                entity = ResolvedEntity(
                    name=result.target,
                    type=result.target_type,
                    row_id=row_id,
                )
                self._resolved_cache[entity_name] = entity
                return entity

        return None

    def validate_operation(self, entity_name: str, operation: str) -> bool:
        """
        Check if an operation is valid for this entity type.

        Prevents invalid operations like 'reset_password' on groups.

        Args:
            entity_name: The entity to check
            operation: The operation to validate

        Returns:
            True if operation is valid, False otherwise
        """
        entity = self.resolve(entity_name)
        if not entity:
            return False

        allowed = ALLOWED_OPERATIONS.get(entity.type, [])
        return operation in allowed

    def get_remediation_target(self, finding_row_ids: List[str]) -> Optional[ResolvedEntity]:
        """
        Determine the correct remediation target from finding results.

        Uses entity roles and node properties (hasspn, dontreqpreauth) to
        identify the actual vulnerable entity.

        Args:
            finding_row_ids: List of result row IDs for this finding

        Returns:
            The ResolvedEntity that should be remediated, or None
        """
        results = [self.store.get(rid) for rid in finding_row_ids]
        results = [r for r in results if r is not None]

        if not results:
            return None

        # Priority 1: User with hasspn (Kerberoastable)
        for r in results:
            props = r.properties or {}
            if props.get('hasspn') and r.source_type == 'User':
                return self.resolve(r.source)

        # Priority 2: User with dontreqpreauth (AS-REP Roastable)
        for r in results:
            props = r.properties or {}
            if props.get('dontreqpreauth') and r.source_type == 'User':
                return self.resolve(r.source)

        # Priority 3: Source that is a User (for ACL abuse, etc.)
        for r in results:
            if r.source_type == 'User':
                return self.resolve(r.source)

        # Fallback: First source
        if results:
            return self.resolve(results[0].source)

        return None

    def clear_cache(self):
        """Clear the resolution cache."""
        self._resolved_cache.clear()
