"""Tests for Deduplicator - redundancy elimination."""
import pytest
from routers.attack_paths.services.deduplicator import Deduplicator, Finding


class TestDeduplicator:
    """Tests for Deduplicator class."""

    def test_get_signature_basic(self):
        """Should generate consistent signature for finding."""
        dedup = Deduplicator()
        finding = Finding(
            query_name='Test',
            result_row_ids=['Test:0'],
            sources=['USER@DOMAIN'],
            targets=['GROUP@DOMAIN'],
            edge_types=['MemberOf'],
            severity='High',
        )

        sig = dedup.get_signature(finding)

        assert sig == 'USER@DOMAIN|GROUP@DOMAIN|MEMBEROF'

    def test_get_signature_normalizes_case(self):
        """Signatures should be case-insensitive."""
        dedup = Deduplicator()
        finding1 = Finding(
            query_name='Test',
            result_row_ids=['Test:0'],
            sources=['user@domain'],
            targets=['group@domain'],
            edge_types=['memberof'],
            severity='High',
        )
        finding2 = Finding(
            query_name='Test',
            result_row_ids=['Test:1'],
            sources=['USER@DOMAIN'],
            targets=['GROUP@DOMAIN'],
            edge_types=['MemberOf'],
            severity='High',
        )

        assert dedup.get_signature(finding1) == dedup.get_signature(finding2)

    def test_normalize_edge_acl_abuse(self):
        """ACL abuse edges should normalize to ACL_ABUSE."""
        dedup = Deduplicator()

        assert dedup._normalize_edge('GenericAll') == 'ACL_ABUSE'
        assert dedup._normalize_edge('GenericWrite') == 'ACL_ABUSE'
        assert dedup._normalize_edge('WriteDacl') == 'ACL_ABUSE'
        assert dedup._normalize_edge('WriteOwner') == 'ACL_ABUSE'
        assert dedup._normalize_edge('Owns') == 'ACL_ABUSE'

    def test_normalize_edge_adcs(self):
        """ADCS edges should normalize to ADCS_ABUSE."""
        dedup = Deduplicator()

        assert dedup._normalize_edge('ADCSESC1') == 'ADCS_ABUSE'
        assert dedup._normalize_edge('ADCSESC4') == 'ADCS_ABUSE'
        assert dedup._normalize_edge('ADCSESC9') == 'ADCS_ABUSE'

    def test_normalize_edge_kerberos(self):
        """Kerberos edges should normalize."""
        dedup = Deduplicator()

        assert dedup._normalize_edge('Kerberoastable') == 'KERBEROAST'
        assert dedup._normalize_edge('HasSPN') == 'KERBEROAST'

    def test_deduplicate_removes_duplicates(self):
        """Should merge findings with same signature."""
        dedup = Deduplicator()
        findings = [
            Finding(
                query_name='Query1',
                result_row_ids=['Q1:0'],
                sources=['USER@DOMAIN'],
                targets=['GROUP@DOMAIN'],
                edge_types=['GenericAll'],
                severity='High',
            ),
            Finding(
                query_name='Query2',
                result_row_ids=['Q2:0'],
                sources=['USER@DOMAIN'],
                targets=['GROUP@DOMAIN'],
                edge_types=['WriteDacl'],  # Same as GenericAll after normalization
                severity='Medium',
            ),
        ]

        result = dedup.deduplicate(findings)

        assert len(result) == 1
        # Should have merged row IDs
        assert 'Q1:0' in result[0].result_row_ids
        assert 'Q2:0' in result[0].result_row_ids

    def test_deduplicate_keeps_unique(self):
        """Should keep findings with different signatures."""
        dedup = Deduplicator()
        findings = [
            Finding(
                query_name='Query1',
                result_row_ids=['Q1:0'],
                sources=['USER1@DOMAIN'],
                targets=['GROUP@DOMAIN'],
                edge_types=['MemberOf'],
                severity='High',
            ),
            Finding(
                query_name='Query2',
                result_row_ids=['Q2:0'],
                sources=['USER2@DOMAIN'],  # Different source
                targets=['GROUP@DOMAIN'],
                edge_types=['MemberOf'],
                severity='Medium',
            ),
        ]

        result = dedup.deduplicate(findings)

        assert len(result) == 2

    def test_merge_takes_higher_severity(self):
        """Merged findings should have highest severity."""
        dedup = Deduplicator()
        findings = [
            Finding(
                query_name='Query1',
                result_row_ids=['Q1:0'],
                sources=['USER@DOMAIN'],
                targets=['GROUP@DOMAIN'],
                edge_types=['GenericAll'],
                severity='Medium',
            ),
            Finding(
                query_name='Query2',
                result_row_ids=['Q2:0'],
                sources=['USER@DOMAIN'],
                targets=['GROUP@DOMAIN'],
                edge_types=['WriteDacl'],
                severity='Critical',
            ),
        ]

        result = dedup.deduplicate(findings)

        assert result[0].severity == 'Critical'

    def test_admin_group_consolidation(self):
        """MemberOf to multiple admin groups should be consolidated."""
        dedup = Deduplicator()
        # Same user in DOMAIN ADMINS and ENTERPRISE ADMINS = same finding
        finding1 = Finding(
            query_name='MemberOf DA',
            result_row_ids=['Q1:0'],
            sources=['STEPH.COOPER_ADM@DOMAIN'],
            targets=['DOMAIN ADMINS@DOMAIN'],
            edge_types=['MemberOf'],
            severity='Critical',
        )
        finding2 = Finding(
            query_name='MemberOf EA',
            result_row_ids=['Q2:0'],
            sources=['STEPH.COOPER_ADM@DOMAIN'],
            targets=['ENTERPRISE ADMINS@DOMAIN'],
            edge_types=['MemberOf'],
            severity='Critical',
        )

        sig1 = dedup.get_signature(finding1)
        sig2 = dedup.get_signature(finding2)

        # Both should have same signature (consolidated as ADMIN_GROUPS)
        assert sig1 == sig2
        assert 'ADMIN_GROUPS' in sig1

    def test_admin_group_consolidation_dedup(self):
        """Deduplication should merge admin group MemberOf findings."""
        dedup = Deduplicator()
        findings = [
            Finding(
                query_name='MemberOf DA',
                result_row_ids=['Q1:0'],
                sources=['ADMIN_USER@DOMAIN'],
                targets=['DOMAIN ADMINS@DOMAIN'],
                edge_types=['MemberOf'],
                severity='Critical',
            ),
            Finding(
                query_name='MemberOf EA',
                result_row_ids=['Q2:0'],
                sources=['ADMIN_USER@DOMAIN'],
                targets=['ENTERPRISE ADMINS@DOMAIN'],
                edge_types=['MemberOf'],
                severity='Critical',
            ),
            Finding(
                query_name='MemberOf Admins',
                result_row_ids=['Q3:0'],
                sources=['ADMIN_USER@DOMAIN'],
                targets=['ADMINISTRATORS@DOMAIN'],
                edge_types=['MemberOf'],
                severity='High',
            ),
        ]

        result = dedup.deduplicate(findings)

        # All three should merge into one
        assert len(result) == 1
        # All row IDs should be merged
        assert 'Q1:0' in result[0].result_row_ids
        assert 'Q2:0' in result[0].result_row_ids
        assert 'Q3:0' in result[0].result_row_ids

    def test_non_admin_groups_not_consolidated(self):
        """MemberOf to non-admin groups should not be consolidated."""
        dedup = Deduplicator()
        finding1 = Finding(
            query_name='MemberOf Dev',
            result_row_ids=['Q1:0'],
            sources=['USER@DOMAIN'],
            targets=['DEVELOPERS@DOMAIN'],
            edge_types=['MemberOf'],
            severity='Medium',
        )
        finding2 = Finding(
            query_name='MemberOf IT',
            result_row_ids=['Q2:0'],
            sources=['USER@DOMAIN'],
            targets=['IT STAFF@DOMAIN'],
            edge_types=['MemberOf'],
            severity='Medium',
        )

        sig1 = dedup.get_signature(finding1)
        sig2 = dedup.get_signature(finding2)

        # Different groups = different signatures
        assert sig1 != sig2
        assert 'ADMIN_GROUPS' not in sig1
        assert 'ADMIN_GROUPS' not in sig2
