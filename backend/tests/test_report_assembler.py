"""Tests for report_assembler AMSI appendix generation and typo fixes."""
import pytest
from routers.attack_paths.services.report_assembler import generate_amsi_appendix
from routers.attack_paths.constants.edge_templates import AMSI_BYPASS_TECHNIQUES
from routers.attack_paths.services.validation_layer import ValidationLayer
from routers.attack_paths.services.entity_resolver import EntityResolver


class TestAMSIAppendix:
    """Tests for AMSI appendix generation."""

    def test_generates_appendix_with_all_families(self):
        """Should generate appendix with all bypass techniques."""
        appendix = generate_amsi_appendix()

        assert appendix['title'] == 'AMSI Bypass Reference'
        assert 'description' in appendix
        assert 'techniques' in appendix
        assert len(appendix['techniques']) >= 4  # reflection, patching, runspace, downgrade

    def test_appendix_technique_structure(self):
        """Each technique should have required fields."""
        appendix = generate_amsi_appendix()

        for technique in appendix['techniques']:
            assert 'name' in technique
            assert 'family' in technique
            assert 'description' in technique
            assert 'code' in technique
            assert len(technique['code']) > 50  # Real code

    def test_filtered_appendix_by_families(self):
        """Should filter appendix to only include used families."""
        used_families = {'reflection', 'patching'}
        appendix = generate_amsi_appendix(used_families=used_families)

        families_in_appendix = {t['family'] for t in appendix['techniques']}
        assert families_in_appendix <= used_families


class TestTypoFixesInCommands:
    """Tests for typo fixes in command/explanation fields."""

    @pytest.fixture
    def validation_layer(self):
        """Create ValidationLayer for testing typo fixes."""
        resolver = EntityResolver([])
        return ValidationLayer(resolver)

    def test_fixes_typo_in_command(self, validation_layer):
        """Should fix typos like 'secretdump' -> 'secretsdump' in commands."""
        text = "Run secretdump to dump credentials"
        fixed = validation_layer._apply_typo_fixes(text)
        assert 'secretsdump' in fixed
        assert 'secretdump' not in fixed

    def test_fixes_typo_in_explanation(self, validation_layer):
        """Should fix typos in explanation field."""
        text = "Use wmicex to move laterally"
        fixed = validation_layer._apply_typo_fixes(text)
        assert 'wmiexec' in fixed
        assert 'wmicex' not in fixed

    def test_fixes_impacted_to_impacket(self, validation_layer):
        """Should fix 'Impacted' -> 'Impacket' typo."""
        text = "Use Impacted for lateral movement"
        fixed = validation_layer._apply_typo_fixes(text)
        assert 'Impacket' in fixed
        assert 'Impacted' not in fixed

    def test_preserves_correct_text(self, validation_layer):
        """Should not modify already correct text."""
        text = "Use impacket-secretsdump for DCSync"
        fixed = validation_layer._apply_typo_fixes(text)
        assert fixed == text
