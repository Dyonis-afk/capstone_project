"""
Deduplicator - Eliminates redundant findings.

Merges findings that cover the same attack path to prevent report bloat.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Finding:
    """A finding that can be deduplicated."""
    query_name: str
    result_row_ids: List[str]
    sources: List[str]
    targets: List[str]
    edge_types: List[str]
    severity: str
    compromisable_entity: Optional[str] = None

    # Fields populated after RAG generation
    observation: Optional[str] = None
    attack_steps: List[Dict] = field(default_factory=list)
    remediation_steps: List[Dict] = field(default_factory=list)


# Edge type normalization for deduplication
EDGE_NORMALIZATION = {
    # ACL abuse edges
    'GENERICALL': 'ACL_ABUSE',
    'GENERICWRITE': 'ACL_ABUSE',
    'WRITEDACL': 'ACL_ABUSE',
    'WRITEOWNER': 'ACL_ABUSE',
    'OWNS': 'ACL_ABUSE',
    # Kerberos edges
    'KERBEROASTABLE': 'KERBEROAST',
    'HASSPN': 'KERBEROAST',
    # AS-REP
    'ASREPROASTABLE': 'ASREP_ROAST',
    'DONTREQPREAUTH': 'ASREP_ROAST',
}

# High-privilege admin groups that should be treated as equivalent for deduplication
# If source is MemberOf multiple of these, they should be one finding
ADMIN_GROUP_CONSOLIDATION = {
    'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS',
    'SCHEMA ADMINS', 'ACCOUNT OPERATORS', 'BACKUP OPERATORS',
    'SERVER OPERATORS', 'PRINT OPERATORS', 'KEY ADMINS',
    'ENTERPRISE KEY ADMINS', 'DNSADMINS',
}


class Deduplicator:
    """
    Merges redundant findings that target the same attack path.
    Key insight: Same (source, target, edge_type) = same finding.
    """

    def __init__(self):
        self._seen_signatures: Dict[str, Finding] = {}

    def get_signature(self, finding: Finding) -> str:
        """
        Generate unique signature for a finding.
        Findings with same signature are duplicates.

        Special handling for MemberOf edges:
        - If source is MemberOf multiple admin groups (DOMAIN ADMINS, ENTERPRISE ADMINS, etc.),
          these are consolidated into one finding since they represent the same security issue:
          "this account has excessive admin privileges"

        Args:
            finding: The finding to generate signature for

        Returns:
            Signature string
        """
        sources = sorted(set(s.upper() for s in finding.sources))
        targets = sorted(set(t.upper() for t in finding.targets))
        edges = sorted(set(self._normalize_edge(e) for e in finding.edge_types))

        # Special case: MemberOf to admin groups should be consolidated
        # "STEPH.COOPER_ADM MemberOf DOMAIN ADMINS" and
        # "STEPH.COOPER_ADM MemberOf ENTERPRISE ADMINS" are essentially the same finding
        if 'MEMBEROF' in edges:
            # Check if ALL targets are admin groups
            targets_upper = {t.upper().split('@')[0] for t in finding.targets}
            if targets_upper and targets_upper.issubset(ADMIN_GROUP_CONSOLIDATION):
                # Consolidate: use "ADMIN_GROUPS" as target instead of specific groups
                # This makes "MemberOf DOMAIN ADMINS" and "MemberOf ENTERPRISE ADMINS" duplicates
                return f"{','.join(sources)}|ADMIN_GROUPS|MEMBEROF_ADMIN"

        return f"{','.join(sources)}|{','.join(targets)}|{','.join(edges)}"

    def _normalize_edge(self, edge: str) -> str:
        """
        Normalize edge types for deduplication.
        Groups similar edges to catch near-duplicates.

        Args:
            edge: Edge type to normalize

        Returns:
            Normalized edge type
        """
        edge_upper = edge.upper()

        # Check explicit normalization map
        if edge_upper in EDGE_NORMALIZATION:
            return EDGE_NORMALIZATION[edge_upper]

        # ADCS edges
        if edge_upper.startswith('ADCSESC'):
            return 'ADCS_ABUSE'

        return edge_upper

    def deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings, keeping the most comprehensive one.

        Args:
            findings: List of findings to deduplicate

        Returns:
            Deduplicated list of findings
        """
        self._seen_signatures.clear()
        unique_findings = []

        for finding in findings:
            sig = self.get_signature(finding)

            if sig in self._seen_signatures:
                self._merge_findings(self._seen_signatures[sig], finding)
            else:
                self._seen_signatures[sig] = finding
                unique_findings.append(finding)

        return unique_findings

    def _merge_findings(self, existing: Finding, new: Finding):
        """
        Merge new finding data into existing finding.
        Combines result_row_ids, takes higher severity.

        Args:
            existing: The existing finding to merge into
            new: The new finding to merge from
        """
        # Combine row IDs (more evidence)
        existing.result_row_ids.extend(new.result_row_ids)
        existing.result_row_ids = list(set(existing.result_row_ids))

        # Take higher severity
        severity_order = ['Critical', 'High', 'Medium', 'Low']
        try:
            existing_idx = severity_order.index(existing.severity)
            new_idx = severity_order.index(new.severity)
            if new_idx < existing_idx:
                existing.severity = new.severity
        except ValueError:
            pass  # Unknown severity, keep existing
