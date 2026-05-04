"""
Priority and Category Constants for Attack Paths
Location: backend/routers/attack_paths/constants/priority.py
"""

# Priority order for generating queries when multiple edge types found
EDGE_PRIORITY_ORDER = [
    # Critical - Domain compromise paths
    "DCSync", "GetChanges", "GetChangesAll", "GenericAll", "WriteDacl", "WriteOwner", "AddMember",
    # Critical - Credential access
    "HasSession", "ReadGMSAPassword", "AllowedToDelegate", "AllowedToAct", "UnconstrainedDelegation",
    # Critical - ADCS (FULL ESC COVERAGE)
    "ADCSESC1", "ADCSESC4", "ADCSESC6", "ADCSESC9", "ADCSESC10", "ADCSESC13",
    "ManageCA", "ManageCertificates", "Enroll",
    # Critical - Shadow Credentials
    "AddKeyCredentialLink", "WriteAccountRestrictions",
    # Critical - GPO attacks
    "GPLink",
    # High - Kerberos attacks
    "Kerberoastable", "ASREPRoastable",
    # High - Lateral movement
    "AdminTo", "CanPSRemote", "CanRDP", "ExecuteDCOM",
    # High - ACL abuse
    "GenericWrite", "ForceChangePassword", "Owns",
    # Medium - Other edges
    "MemberOf", "ReadLAPSPassword"
]

# Edge type to attack category mapping
ATTACK_CATEGORY_MAP = {
    'MemberOf': 'Privileged Access',
    'AdminTo': 'Privileged Access',
    'HasSIDHistory': 'Privileged Access',
    'CanRDP': 'Privileged Access',
    'CanPSRemote': 'Privileged Access',
    'ExecuteDCOM': 'Privileged Access',
    'HasSPNConfigured': 'Credential Access',
    'DontReqPreAuth': 'Credential Access',
    'DCSync': 'Credential Access',
    'GetChanges': 'Credential Access',
    'GetChangesAll': 'Credential Access',
    'GetChangesInFilteredSet': 'Credential Access',
    'ReadLAPSPassword': 'Credential Access',
    'ReadGMSAPassword': 'Credential Access',
    'GenericAll': 'Privilege Escalation',
    'GenericWrite': 'Privilege Escalation',
    'WriteDacl': 'Privilege Escalation',
    'WriteOwner': 'Privilege Escalation',
    'Owns': 'Privilege Escalation',
    'ForceChangePassword': 'Privilege Escalation',
    'AddMember': 'Privilege Escalation',
    'AddSelf': 'Privilege Escalation',
    'AllExtendedRights': 'Privilege Escalation',
    'AddKeyCredentialLink': 'Persistence',
    'WriteSPN': 'Persistence',
    'TrustedBy': 'Trust Abuse',
    'Contains': 'Structure',
    'GPLink': 'Group Policy',
}


def get_attack_complexity(edges: list) -> str:
    """Determine attack complexity based on edge types."""
    high_complexity = {'DCSync', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet', 'AddKeyCredentialLink', 'TrustedBy', 'ExecuteDCOM'}
    medium_complexity = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'ForceChangePassword'}

    for edge in edges:
        if edge in high_complexity:
            return 'High'
        if edge in medium_complexity:
            return 'Medium'
    return 'Low'


def get_primary_category(edges_used: list) -> str:
    """Get the primary attack category from edges."""
    categories = [ATTACK_CATEGORY_MAP.get(e, 'Misconfiguration') for e in edges_used]
    if 'Credential Access' in categories:
        return 'Credential Access'
    if 'Privilege Escalation' in categories:
        return 'Privilege Escalation'
    if 'Privileged Access' in categories:
        return 'Privileged Access'
    return categories[0] if categories else 'Misconfiguration'


def determine_severity(findings: list, edges_used: list) -> str:
    """Determine finding severity based on edges and targets."""
    critical_edges = {
        'DCSync', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet',
        'GenericAll', 'WriteOwner', 'WriteDacl',
    }
    high_edges = {'ForceChangePassword', 'AddMember', 'AllExtendedRights', 'GenericWrite'}

    # Check for critical targets
    for finding in findings:
        target = finding.get('target', '').upper()
        if any(g in target for g in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS', 'DC=']):
            if any(e in critical_edges for e in edges_used):
                return 'Critical'

    for edge in edges_used:
        if edge in critical_edges:
            return 'Critical'
        if edge in high_edges:
            return 'High'

    if 'MemberOf' in edges_used:
        for finding in findings:
            target = finding.get('target', '').upper()
            if any(g in target for g in ['DOMAIN ADMINS', 'ENTERPRISE ADMINS']):
                return 'Critical'

    return 'Medium'
