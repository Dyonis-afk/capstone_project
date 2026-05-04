"""
ValidationLayer - Final sanity checks before report output.

Catches technical inaccuracies and formatting issues that slipped through.
"""
import re
from enum import Enum
from typing import List, Optional

from .entity_resolver import EntityResolver
from .deduplicator import Finding


class ValidationResult(Enum):
    """Result of validation check."""
    PASS = "pass"
    WARN = "warn"
    REJECT = "reject"


# Known typos and their corrections
# Expanded based on observed LLM errors in report evaluation
TYPO_CORRECTIONS = {
    # Tool name typos
    'Impacted': 'Impacket',
    'Rubens': 'Rubeus',
    'Rubess': 'Rubeus',
    'Rubus': 'Rubeus',
    'wmicex': 'wmiexec',
    'wimexe': 'wmiexec',
    'wmiexe': 'wmiexec',
    'secretdump': 'secretsdump',
    'secretdumps': 'secretsdump',
    'secetsdump': 'secretsdump',
    'GetUsersSPNs': 'GetUserSPNs',
    'GetUserSPN': 'GetUserSPNs',
    'bloodyad': 'bloodyAD',
    'BloodyAd': 'bloodyAD',
    'dacleditedit': 'dacledit',
    'dacleditit': 'dacledit',
    'impacket-dacleditedit': 'impacket-dacledit',
    'impacket-dacleditit': 'impacket-dacledit',
    'impacket-ownereditedit': 'impacket-owneredit',
    'impacket-ownereditit': 'impacket-owneredit',
    'Certify': 'Certipy',  # Common confusion
    'certify': 'Certipy',
    'powerview': 'PowerView',
    'Powerview': 'PowerView',
    'mimkatz': 'Mimikatz',
    'Mimkatz': 'Mimikatz',
    # Command typos
    'whami': 'whoami',
    'whoaim': 'whoami',
    'ipocnfig': 'ipconfig',
    # Environment variable typos
    'KERBCNAME': 'KRB5CCNAME',
    'KERBCCNAME': 'KRB5CCNAME',
    'KRB5CNAME': 'KRB5CCNAME',
    # Technique typos
    'Kerberosating': 'Kerberoasting',
    'Kerberosting': 'Kerberoasting',
    'Kerberoasitng': 'Kerberoasting',
    'DCsync': 'DCSync',
    'DcSync': 'DCSync',
    'dcsync': 'DCSync',
    'Generically': 'GenericAll',  # LLM sometimes says "Generically" instead of GenericAll
    # Common spelling errors
    'credentails': 'credentials',
    'crednetials': 'credentials',
    'priviledge': 'privilege',
    'privilige': 'privilege',
    'adminstrator': 'administrator',
    'administartor': 'administrator',
    'authenication': 'authentication',
    'authentcation': 'authentication',
    'vulernable': 'vulnerable',
    'vulnearble': 'vulnerable',
    'exploitaiton': 'exploitation',
    'escaltaion': 'escalation',
    'escallation': 'escalation',
    'exfiltartion': 'exfiltration',
    'remidiation': 'remediation',
    'remediaion': 'remediation',
}

# PowerShell commands that require specific entity types
TYPE_REQUIRED_OPERATIONS = {
    'Set-ADAccountPassword': ['User', 'Computer'],
    'Set-ADAccountControl': ['User', 'Computer'],
    'Disable-ADAccount': ['User', 'Computer'],
    'Remove-ADGroupMember': ['Group'],
    'Add-ADGroupMember': ['Group'],
    'Set-ADUser': ['User'],
    'Set-ADComputer': ['Computer'],
}


class ValidationLayer:
    """
    Final sanity checks before report output.
    Catches technical inaccuracies and formatting issues.
    """

    def __init__(self, entity_resolver: EntityResolver):
        self.resolver = entity_resolver
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def validate_finding(self, finding: Finding) -> ValidationResult:
        """
        Run all validation checks on a finding.

        Args:
            finding: The finding to validate

        Returns:
            ValidationResult (PASS, WARN, or REJECT)
        """
        self.warnings = []
        self.errors = []

        # 1. Validate all entities exist in ground truth
        self._validate_entities_exist(finding)

        # 2. Check remediation targets
        self._validate_remediation_targets(finding)

        # 3. Fix typos (non-blocking)
        self._fix_typos(finding)

        # 4. Check for nonsensical attack steps
        self._validate_attack_logic(finding)

        if self.errors:
            return ValidationResult.REJECT
        elif self.warnings:
            return ValidationResult.WARN
        return ValidationResult.PASS

    def _validate_entities_exist(self, finding: Finding):
        """Verify all referenced entities exist in ground truth."""
        all_entities = finding.sources + finding.targets

        for entity in all_entities:
            if not self.resolver.resolve(entity):
                self.errors.append(f"Entity '{entity}' not found in query results")

    def _validate_remediation_targets(self, finding: Finding):
        """Ensure remediation scripts target correct entity types."""
        for step in finding.remediation_steps:
            if not isinstance(step, dict):
                continue

            command = step.get('command', '')

            for operation, allowed_types in TYPE_REQUIRED_OPERATIONS.items():
                if operation in command:
                    target = self._extract_command_target(command, operation)
                    if target:
                        entity = self.resolver.resolve(target)
                        if entity and entity.type not in allowed_types:
                            self.errors.append(
                                f"Invalid: {operation} on {entity.type} '{target}' "
                                f"(only valid for {allowed_types})"
                            )

    def _extract_command_target(self, command: str, operation: str) -> Optional[str]:
        """Extract target entity from a PowerShell command."""
        # Match -Identity 'VALUE' or -Identity "VALUE" or -Identity VALUE
        patterns = [
            rf"-Identity\s+'([^']+)'",
            rf'-Identity\s+"([^"]+)"',
            rf"-Identity\s+(\S+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, command)
            if match:
                return match.group(1)

        return None

    def _validate_attack_logic(self, finding: Finding):
        """Check for nonsensical attack steps."""
        for step in finding.attack_steps:
            if not isinstance(step, dict):
                continue

            desc = step.get('description', '').lower()

            # Check for circular logic
            if 'coerce' in desc and ('from the target' in desc or 'on the target' in desc):
                self.warnings.append(
                    "Circular logic: Coercion attack may assume access to target"
                )

    def _fix_typos(self, finding: Finding):
        """Auto-correct known typos in text fields."""
        # Fix observation
        if finding.observation:
            finding.observation = self._apply_typo_fixes(finding.observation)

        # Fix attack steps
        for step in finding.attack_steps:
            if isinstance(step, dict):
                if 'description' in step:
                    step['description'] = self._apply_typo_fixes(step['description'])
                if 'title' in step:
                    step['title'] = self._apply_typo_fixes(step['title'])

        # Fix remediation steps
        for step in finding.remediation_steps:
            if isinstance(step, dict):
                if 'description' in step:
                    step['description'] = self._apply_typo_fixes(step['description'])

    def _apply_typo_fixes(self, text: str) -> str:
        """Apply typo corrections to text."""
        for typo, correction in TYPO_CORRECTIONS.items():
            # Case-insensitive replacement that preserves boundaries
            pattern = rf'\b{re.escape(typo)}\b'
            text = re.sub(pattern, correction, text, flags=re.IGNORECASE)
        return text

    def get_errors(self) -> List[str]:
        """Get list of validation errors."""
        return self.errors.copy()

    def get_warnings(self) -> List[str]:
        """Get list of validation warnings."""
        return self.warnings.copy()
