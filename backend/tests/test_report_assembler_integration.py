"""Integration tests for report assembler with ground-truth anchoring."""
import pytest
from routers.attack_paths.services.result_store import ResultStore
from routers.attack_paths.services.entity_resolver import EntityResolver
from routers.attack_paths.services.finding_factory import FindingFactory
from routers.attack_paths.services.deduplicator import Deduplicator
from routers.attack_paths.services.validation_layer import ValidationLayer, ValidationResult


class TestGroundTruthIntegration:
    """Integration tests for the full ground-truth pipeline."""

    def test_full_pipeline_kerberoasting(self, kerberoastable_results):
        """Full pipeline should correctly identify Kerberoastable user."""
        # 1. Store results
        store = ResultStore()
        row_ids = store.store('Kerberoastable', kerberoastable_results)

        # 2. Create resolver
        resolver = EntityResolver(store)

        # 3. Create finding
        factory = FindingFactory(store, resolver)
        finding = factory.create_finding(
            query_name='Kerberoastable',
            row_ids=row_ids,
            severity='Critical',
        )

        # 4. Validate
        validator = ValidationLayer(resolver)
        finding.remediation_steps = [
            {'command': f"Set-ADAccountPassword -Identity '{finding.compromisable_entity}'"}
        ]
        result = validator.validate_finding(finding)

        # Assertions
        assert finding is not None
        assert finding.compromisable_entity == 'SVC_TGS@ACTIVE.HTB'
        assert 'SVC_TGS@ACTIVE.HTB' in finding.sources
        assert result == ValidationResult.PASS

    def test_pipeline_rejects_group_password_reset(self, sample_neo4j_results):
        """Pipeline should reject password reset on group."""
        store = ResultStore()
        row_ids = store.store('TestQuery', sample_neo4j_results)
        resolver = EntityResolver(store)
        factory = FindingFactory(store, resolver)

        finding = factory.create_finding(
            query_name='TestQuery',
            row_ids=row_ids[:1],
            severity='High',
        )

        # Try to reset password on group (INVALID)
        finding.remediation_steps = [
            {'command': "Set-ADAccountPassword -Identity 'DOMAIN ADMINS@ACTIVE.HTB'"}
        ]

        validator = ValidationLayer(resolver)
        result = validator.validate_finding(finding)

        assert result == ValidationResult.REJECT

    def test_deduplication_merges_same_path(self, sample_neo4j_results):
        """Deduplicator should merge findings with same signature."""
        store = ResultStore()
        store.store('Query1', sample_neo4j_results[:1])
        store.store('Query2', sample_neo4j_results[:1])  # Same data

        resolver = EntityResolver(store)
        factory = FindingFactory(store, resolver)

        finding1 = factory.create_finding('Query1', ['Query1:0'], 'High')
        finding2 = factory.create_finding('Query2', ['Query2:0'], 'Critical')

        dedup = Deduplicator()
        unique = dedup.deduplicate([finding1, finding2])

        assert len(unique) == 1
        assert unique[0].severity == 'Critical'  # Takes higher
