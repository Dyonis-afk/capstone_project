"""Tests for EntityResolver - type-safe entity handling."""
import pytest
from routers.attack_paths.services.result_store import ResultStore
from routers.attack_paths.services.entity_resolver import EntityResolver, ResolvedEntity


class TestEntityResolver:
    """Tests for EntityResolver class."""

    @pytest.fixture
    def resolver_with_data(self, sample_neo4j_results):
        """Create resolver with sample data loaded."""
        store = ResultStore()
        store.store('TestQuery', sample_neo4j_results)
        return EntityResolver(store)

    def test_resolve_existing_source_entity(self, resolver_with_data):
        """Should resolve entity that exists as source."""
        entity = resolver_with_data.resolve('SVC_TGS@ACTIVE.HTB')

        assert entity is not None
        assert entity.name == 'SVC_TGS@ACTIVE.HTB'
        assert entity.type == 'User'

    def test_resolve_existing_target_entity(self, resolver_with_data):
        """Should resolve entity that exists as target."""
        entity = resolver_with_data.resolve('DOMAIN ADMINS@ACTIVE.HTB')

        assert entity is not None
        assert entity.name == 'DOMAIN ADMINS@ACTIVE.HTB'
        assert entity.type == 'Group'

    def test_resolve_nonexistent_returns_none(self, resolver_with_data):
        """Should return None for unknown entities."""
        entity = resolver_with_data.resolve('FAKE_USER@FAKE.HTB')

        assert entity is None

    def test_validate_operation_user_reset_password(self, resolver_with_data):
        """Users can have password reset."""
        valid = resolver_with_data.validate_operation(
            'SVC_TGS@ACTIVE.HTB',
            'reset_password'
        )
        assert valid is True

    def test_validate_operation_group_reset_password_invalid(self, resolver_with_data):
        """Groups cannot have password reset."""
        valid = resolver_with_data.validate_operation(
            'DOMAIN ADMINS@ACTIVE.HTB',
            'reset_password'
        )
        assert valid is False

    def test_validate_operation_group_remove_member(self, resolver_with_data):
        """Groups can have members removed."""
        valid = resolver_with_data.validate_operation(
            'DOMAIN ADMINS@ACTIVE.HTB',
            'remove_member'
        )
        assert valid is True

    def test_validate_operation_unknown_entity(self, resolver_with_data):
        """Unknown entities should return False for any operation."""
        valid = resolver_with_data.validate_operation(
            'FAKE@FAKE.HTB',
            'reset_password'
        )
        assert valid is False

    def test_get_remediation_target_kerberoastable(self, kerberoastable_results):
        """Should identify Kerberoastable user as compromisable."""
        store = ResultStore()
        row_ids = store.store('Kerberoastable', kerberoastable_results)
        resolver = EntityResolver(store)

        target = resolver.get_remediation_target(row_ids)

        assert target is not None
        assert target.name == 'SVC_TGS@ACTIVE.HTB'
        assert target.type == 'User'

    def test_caches_resolved_entities(self, resolver_with_data):
        """Should cache resolved entities for performance."""
        # Resolve same entity twice
        entity1 = resolver_with_data.resolve('SVC_TGS@ACTIVE.HTB')
        entity2 = resolver_with_data.resolve('SVC_TGS@ACTIVE.HTB')

        # Should be same object (cached)
        assert entity1 is entity2
