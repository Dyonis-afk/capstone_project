"""Tests for ResultStore - ground truth data storage."""
import pytest
from routers.attack_paths.services.result_store import ResultStore, StoredResult


class TestResultStore:
    """Tests for ResultStore class."""

    def test_store_results_returns_row_ids(self, sample_neo4j_results):
        """Storing results should return unique row IDs."""
        store = ResultStore()
        row_ids = store.store('Kerberoastable', sample_neo4j_results)

        assert len(row_ids) == 3
        assert row_ids[0] == 'Kerberoastable:0'
        assert row_ids[1] == 'Kerberoastable:1'
        assert row_ids[2] == 'Kerberoastable:2'

    def test_get_returns_stored_result(self, sample_neo4j_results):
        """Getting by row ID should return the stored result."""
        store = ResultStore()
        store.store('Kerberoastable', sample_neo4j_results)

        result = store.get('Kerberoastable:0')

        assert result is not None
        assert result.source == 'SVC_TGS@ACTIVE.HTB'
        assert result.source_type == 'User'
        assert result.target == 'DOMAIN ADMINS@ACTIVE.HTB'
        assert result.target_type == 'Group'

    def test_get_nonexistent_returns_none(self):
        """Getting nonexistent row ID should return None."""
        store = ResultStore()

        result = store.get('nonexistent:0')

        assert result is None

    def test_get_entity_finds_source(self, sample_neo4j_results):
        """get_entity should find entity when it's a source."""
        store = ResultStore()
        store.store('Kerberoastable', sample_neo4j_results)

        result = store.get_entity('SVC_TGS@ACTIVE.HTB')

        assert result is not None
        assert result.source == 'SVC_TGS@ACTIVE.HTB'

    def test_get_entity_finds_target(self, sample_neo4j_results):
        """get_entity should find entity when it's a target."""
        store = ResultStore()
        store.store('Kerberoastable', sample_neo4j_results)

        result = store.get_entity('DOMAIN ADMINS@ACTIVE.HTB')

        assert result is not None
        assert result.target == 'DOMAIN ADMINS@ACTIVE.HTB'

    def test_get_entity_not_found_returns_none(self, sample_neo4j_results):
        """get_entity should return None for unknown entities."""
        store = ResultStore()
        store.store('Kerberoastable', sample_neo4j_results)

        result = store.get_entity('UNKNOWN@FAKE.HTB')

        assert result is None

    def test_stored_result_preserves_properties(self, kerberoastable_results):
        """StoredResult should preserve source_properties."""
        store = ResultStore()
        store.store('Kerberoastable', kerberoastable_results)

        result = store.get('Kerberoastable:0')

        assert result.properties.get('hasspn') is True
        assert 'active/CIFS:445' in result.properties.get('serviceprincipalnames', [])
