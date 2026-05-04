"""
AMSI Bypass Injector - Deterministic injection of pre-validated AMSI bypasses.

Replaces LLM-generated AMSI code with tested templates from edge_templates.py.
This ensures all AMSI bypasses are syntactically valid and functional.

The injector adds references to AMSI bypasses (not inline code). Full bypass
code is included in the report's amsi_appendix section.
"""

from typing import Dict, List, Set
from ..constants import get_amsi_bypass


# Tools that require AMSI bypass before execution
TOOLS_REQUIRING_AMSI = {
    # PowerShell offensive tools
    'PowerView', 'Invoke-', 'PowerUp', 'Rubeus',
    'Mimikatz', 'Seatbelt', 'Certify', 'SharpHound',
    # PowerView cmdlets (these ARE PowerView but don't have "PowerView" in name)
    'Get-Domain', 'Set-Domain', 'Add-Domain', 'Remove-Domain',
    'Get-Net', 'Find-', 'Get-ObjectAcl', 'Add-ObjectAcl',
    'Set-DomainObject', 'Get-DomainObject',
    # Generic PowerShell patterns
    'IEX', 'Invoke-Expression', 'DownloadString',
    'Add-Type', 'Import-Module',
}

# Tools that should NOT get AMSI bypass (Linux/Python tools)
EXCLUDED_TOOLS = {
    'impacket', 'secretsdump', 'GetUserSPNs', 'GetNPUsers',
    'certipy', 'bloodhound-python', 'ldapsearch', 'nxc',
    'evil-winrm',
}


class AMSIInjector:
    """Injects pre-validated AMSI bypass references into attack steps."""

    def __init__(self):
        """Initialize the injector with empty used_families tracking."""
        self.used_families: Set[str] = set()

    def process_attack_steps(self, steps: List[Dict]) -> List[Dict]:
        """Process all attack steps, injecting AMSI bypass references where needed.

        Injects a reference format instead of inline code:
        {required: True, note: "...", family: "..."}

        Full bypass code is moved to the report's amsi_appendix section.
        """
        for step in steps:
            for option in step.get('opsec_options', []):
                if self._needs_amsi(option):
                    bypass = get_amsi_bypass(exclude_used=True)
                    # Track which family was used for appendix generation
                    self.used_families.add(bypass['family'])
                    # Inject reference format (not inline code)
                    option['amsi_bypass'] = {
                        'required': True,
                        'note': 'Run AMSI bypass before executing (see Appendix)',
                        'family': bypass['family'],
                    }
        return steps

    def get_used_families(self) -> Set[str]:
        """Return the set of bypass families that have been used.

        This is used to generate the amsi_appendix with only the relevant
        bypass techniques.
        """
        return self.used_families

    def _needs_amsi(self, option: Dict) -> bool:
        """Determine if a command needs AMSI bypass."""
        combined = f"{option.get('command', '')} {option.get('tool_name', '')}".lower()

        # Exclude Linux/Python tools first (higher priority)
        if any(ex.lower() in combined for ex in EXCLUDED_TOOLS):
            return False

        # Check for PowerShell tools
        return any(tool.lower() in combined for tool in TOOLS_REQUIRING_AMSI)
