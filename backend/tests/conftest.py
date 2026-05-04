"""Shared test fixtures for Ground-Truth Anchoring tests."""
import pytest
from typing import List, Dict, Any


@pytest.fixture
def sample_neo4j_results() -> List[Dict[str, Any]]:
    """Sample Neo4j query results for testing."""
    return [
        {
            'source': 'SVC_TGS@ACTIVE.HTB',
            'source_type': 'User',
            'target': 'DOMAIN ADMINS@ACTIVE.HTB',
            'target_type': 'Group',
            'edge_type': 'MemberOf',
            'source_properties': {'hasspn': True, 'enabled': True},
            'target_properties': {'highvalue': True},
        },
        {
            'source': 'ADMINISTRATOR@ACTIVE.HTB',
            'source_type': 'User',
            'target': 'DOMAIN ADMINS@ACTIVE.HTB',
            'target_type': 'Group',
            'edge_type': 'MemberOf',
            'source_properties': {'admincount': True, 'enabled': True},
            'target_properties': {'highvalue': True},
        },
        {
            'source': 'SUPPORT@SUPPORT.HTB',
            'source_type': 'User',
            'target': 'SHARED SUPPORT ACCOUNTS@SUPPORT.HTB',
            'target_type': 'Group',
            'edge_type': 'GenericAll',
            'source_properties': {'enabled': True},
            'target_properties': {},
        },
    ]


@pytest.fixture
def kerberoastable_results() -> List[Dict[str, Any]]:
    """Results from a Kerberoasting query."""
    return [
        {
            'source': 'SVC_TGS@ACTIVE.HTB',
            'source_type': 'User',
            'target': 'DOMAIN ADMINS@ACTIVE.HTB',
            'target_type': 'Group',
            'edge_type': 'MemberOf',
            'source_properties': {
                'hasspn': True,
                'enabled': True,
                'serviceprincipalnames': ['active/CIFS:445'],
            },
            'target_properties': {'highvalue': True},
        },
    ]


@pytest.fixture
def acl_abuse_results() -> List[Dict[str, Any]]:
    """Results from an ACL abuse query."""
    return [
        {
            'source': 'SUPPORT@SUPPORT.HTB',
            'source_type': 'User',
            'target': 'DC01@SUPPORT.HTB',
            'target_type': 'Computer',
            'edge_type': 'GenericAll',
            'source_properties': {'enabled': True},
            'target_properties': {'isdc': True},
        },
    ]
