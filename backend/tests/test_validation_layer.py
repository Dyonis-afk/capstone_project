"""Tests for ValidationLayer - final sanity checks."""
import pytest
from routers.attack_paths.services.result_store import ResultStore
from routers.attack_paths.services.entity_resolver import EntityResolver
from routers.attack_paths.services.deduplicator import Finding
from routers.attack_paths.services.validation_layer import (
    ValidationLayer,
    ValidationResult,
    TYPO_CORRECTIONS,
)


class TestValidationLayer:
    """Tests for ValidationLayer class."""

    @pytest.fixture
    def validator(self, sample_neo4j_results):
        """Create validator with sample data."""
        store = ResultStore()
        store.store('TestQuery', sample_neo4j_results)
        resolver = EntityResolver(store)
        return ValidationLayer(resolver)

    def test_validate_finding_passes_valid(self, validator):
        """Valid finding should pass validation."""
        finding = Finding(
            query_name='Test',
            result_row_ids=['TestQuery:0'],
            sources=['SVC_TGS@ACTIVE.HTB'],
            targets=['DOMAIN ADMINS@ACTIVE.HTB'],
            edge_types=['MemberOf'],
            severity='High',
        )
        finding.remediation_steps = [
            {'command': "Set-ADAccountPassword -Identity 'SVC_TGS@ACTIVE.HTB'"}
        ]

        result = validator.validate_finding(finding)

        assert result == ValidationResult.PASS

    def test_validate_finding_rejects_password_reset_on_group(self, validator):
        """Should reject password reset on group."""
        finding = Finding(
            query_name='Test',
            result_row_ids=['TestQuery:0'],
            sources=['SVC_TGS@ACTIVE.HTB'],
            targets=['DOMAIN ADMINS@ACTIVE.HTB'],
            edge_types=['MemberOf'],
            severity='High',
        )
        finding.remediation_steps = [
            {'command': "Set-ADAccountPassword -Identity 'DOMAIN ADMINS@ACTIVE.HTB'"}
        ]

        result = validator.validate_finding(finding)

        assert result == ValidationResult.REJECT

    def test_validate_finding_rejects_unknown_entity(self, validator):
        """Should reject finding with unknown entity."""
        finding = Finding(
            query_name='Test',
            result_row_ids=['TestQuery:0'],
            sources=['FAKE_USER@FAKE.HTB'],  # Not in data
            targets=['DOMAIN ADMINS@ACTIVE.HTB'],
            edge_types=['MemberOf'],
            severity='High',
        )

        result = validator.validate_finding(finding)

        assert result == ValidationResult.REJECT

    def test_fix_typos_impacket(self, validator):
        """Should fix 'Impacted' typo to 'Impacket'."""
        finding = Finding(
            query_name='Test',
            result_row_ids=['TestQuery:0'],
            sources=['SVC_TGS@ACTIVE.HTB'],
            targets=['DOMAIN ADMINS@ACTIVE.HTB'],
            edge_types=['MemberOf'],
            severity='High',
        )
        finding.observation = "Use Impacted tools to exploit this."

        validator.validate_finding(finding)

        assert 'Impacket' in finding.observation
        assert 'Impacted' not in finding.observation

    def test_fix_typos_rubeus(self, validator):
        """Should fix 'Rubens' typo to 'Rubeus'."""
        finding = Finding(
            query_name='Test',
            result_row_ids=['TestQuery:0'],
            sources=['SVC_TGS@ACTIVE.HTB'],
            targets=['DOMAIN ADMINS@ACTIVE.HTB'],
            edge_types=['MemberOf'],
            severity='High',
        )
        finding.attack_steps = [
            {'description': "Use Rubens to kerberoast"}
        ]

        validator.validate_finding(finding)

        assert 'Rubeus' in finding.attack_steps[0]['description']

    def test_typo_corrections_dict(self):
        """Verify typo corrections dictionary exists."""
        assert 'Impacted' in TYPO_CORRECTIONS
        assert TYPO_CORRECTIONS['Impacted'] == 'Impacket'
        assert 'Rubens' in TYPO_CORRECTIONS
        assert TYPO_CORRECTIONS['Rubens'] == 'Rubeus'
        assert 'wmicex' in TYPO_CORRECTIONS
        assert TYPO_CORRECTIONS['wmicex'] == 'wmiexec'


class TestTypoFixesInCommands:
    """Tests for typo corrections in opsec_options commands."""

    @pytest.fixture
    def layer(self):
        """Create ValidationLayer with empty store."""
        store = ResultStore()
        resolver = EntityResolver(store)
        return ValidationLayer(resolver)

    def test_fixes_wmicex_in_command(self, layer):
        """Should fix 'wmicex' -> 'wmiexec' in commands."""
        command = "wmicex.py domain/user@target"
        fixed = layer._apply_typo_fixes(command)

        assert fixed == "wmiexec.py domain/user@target"

    def test_fixes_impacted_in_command(self, layer):
        """Should fix 'Impacted' -> 'Impacket' in commands."""
        command = "Impacted-secretsdump domain/user@target"
        fixed = layer._apply_typo_fixes(command)

        assert fixed == "Impacket-secretsdump domain/user@target"

    def test_fixes_secretdump_in_command(self, layer):
        """Should fix 'secretdump' -> 'secretsdump' in commands."""
        command = "impacket-secretdump domain/user@target"
        fixed = layer._apply_typo_fixes(command)

        assert fixed == "impacket-secretsdump domain/user@target"
