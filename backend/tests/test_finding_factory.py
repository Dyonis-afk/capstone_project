"""Tests for FindingFactory - traceable finding creation."""
import pytest
from routers.attack_paths.services.result_store import ResultStore
from routers.attack_paths.services.entity_resolver import EntityResolver
from routers.attack_paths.services.finding_factory import FindingFactory


class TestFindingFactory:
    """Tests for FindingFactory class."""

    @pytest.fixture
    def factory(self, sample_neo4j_results):
        """Create factory with sample data."""
        store = ResultStore()
        store.store('TestQuery', sample_neo4j_results)
        resolver = EntityResolver(store)
        return FindingFactory(store, resolver)

    def test_create_finding_returns_finding(self, factory):
        """Should create finding from valid row IDs."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0'],
            severity='High',
        )

        assert finding is not None
        assert finding.query_name == 'TestQuery'
        assert finding.severity == 'High'

    def test_create_finding_extracts_sources_from_data(self, factory):
        """Sources should come FROM data, not generated."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0'],
            severity='High',
        )

        assert 'SVC_TGS@ACTIVE.HTB' in finding.sources

    def test_create_finding_extracts_targets_from_data(self, factory):
        """Targets should come FROM data, not generated."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0'],
            severity='High',
        )

        assert 'DOMAIN ADMINS@ACTIVE.HTB' in finding.targets

    def test_create_finding_extracts_edge_types(self, factory):
        """Edge types should come FROM data."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0'],
            severity='High',
        )

        assert 'MemberOf' in finding.edge_types

    def test_create_finding_includes_row_ids(self, factory):
        """Finding should include result row IDs for traceability."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0', 'TestQuery:1'],
            severity='High',
        )

        assert 'TestQuery:0' in finding.result_row_ids
        assert 'TestQuery:1' in finding.result_row_ids

    def test_create_finding_rejects_invalid_row_id(self, factory):
        """Should return None for invalid row IDs."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['FakeQuery:999'],  # Doesn't exist
            severity='High',
        )

        assert finding is None

    def test_create_finding_identifies_kerberoastable(self, kerberoastable_results):
        """Should identify Kerberoastable user as compromisable."""
        store = ResultStore()
        store.store('Kerberoastable', kerberoastable_results)
        resolver = EntityResolver(store)
        factory = FindingFactory(store, resolver)

        finding = factory.create_finding(
            query_name='Kerberoastable',
            row_ids=['Kerberoastable:0'],
            severity='Critical',
        )

        assert finding.compromisable_entity == 'SVC_TGS@ACTIVE.HTB'

    def test_create_finding_multiple_rows(self, factory):
        """Should handle multiple result rows."""
        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=['TestQuery:0', 'TestQuery:1', 'TestQuery:2'],
            severity='High',
        )

        assert finding is not None
        assert len(finding.result_row_ids) == 3
        # Should have multiple sources
        assert len(finding.sources) >= 2
