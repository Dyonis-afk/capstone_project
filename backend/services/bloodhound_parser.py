"""
BloodHound Parser Service
Parses BloodHound JSON files and extracts security findings
"""

import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

# Set up logger for this module
logger = logging.getLogger(__name__)


class BloodHoundParser:
    """
    Parses BloodHound JSON collector output.
    Extracts relationships (edges) that represent potential attack paths.
    """

    def __init__(self):
        """
        HOW WERE THE RISK LEVELS DETERMINED?
        The risk levels for BloodHound edges were determined based on their potential impact,
        some edges are known to be more dangerous in terms of privilege escalation and lateral movement within an Active Directory environment.
        Some of the most critical and dangerous edges include:

        - DCSync: Allows an attacker to replicate password hashes from a Domain Controller. Effectively gives domain admin level access.

        - AdminTo: Direct administrative access to another object, which can lead to full control over that object.

        - MemberOf: Being a member of privileged groups (like Domain Admins) can lead to significant control over the domain.

        - HasSession: Indicates active sessions on machines, which can be exploited for lateral movement.

        - DCSync - related rights ( GenericAll, GenericWrite, WriteDacl, WriteOwner): Any edge that grants an attacker the ability perform a DCSync attack is extremely dangerous.
        These permissions allow an attacker to impersonate a Domain Controller and extract sensitive information.

        SOURCES USED IN THE COMPILATION:
         - https://bloodhound.specterops.io/get-started/introduction
         - https://specterops.io/blog/2024/09/11/adcs-attack-paths-in-bloodhound-part-3/#:~:text=There%20are%20many%20combinations%20of,Owns
         - https://specterops.io/blog/2018/08/07/bloodhound-2-0/#:~:text=A%20very%20complicated%20attack%20that,during%20the%20ObjectProps%20collection%20method.
         - https://specterops.io/blog/2021/05/25/the-attack-path-management-manifesto/#0ac3

        """
        # High-risk edges that indicate potential security issues
        self.high_risk_edges = {
            'AdminTo', 'MemberOf', 'HasSession', 'DCSync', 'AllowedToDelegate',
            'GetChanges', 'GetChangesAll', 'WriteDacl', 'WriteOwner', 'GenericAll',
            'GenericWrite', 'ForceChangePassword', 'Owns', 'AllExtendedRights',
            'AddKeyCredentialLink', 'WriteAccountRestrictions',
            # ADCS-related high-risk edges
            'ManageCA', 'ManageCertificates', 'WritePKIEnrollmentFlag',
            'WritePKINameFlag', 'WriteSubjectAltName', 'ADCSESC1', 'ADCSESC4',
            'ADCSESC6', 'ADCSESC9', 'ADCSESC10', 'ADCSESC13'
        }

        # Medium-risk edges
        self.medium_risk_edges = {
            'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToAct',
            'AddMember', 'ReadLAPSPassword', 'ReadGMSAPassword', 'Contains',
            'GPLink', 'TrustedBy', 'AddSelf', 'WriteSPN', 'AddAllowedToAct',
            # ADCS-related medium-risk edges
            'Enroll', 'HostsCAService', 'HasSPN', 'PublishesCertTemplate'
        }

        # SID to Name mapping (populated during parsing)
        self.sid_to_name: Dict[str, str] = {}
        self.sid_to_type: Dict[str, str] = {}

        # Well-known SIDs mapping
        self.well_known_sids = {
            'S-1-5-32-544': 'BUILTIN\\Administrators',
            'S-1-5-32-545': 'BUILTIN\\Users',
            'S-1-5-32-548': 'BUILTIN\\Account Operators',
            'S-1-5-32-549': 'BUILTIN\\Server Operators',
            'S-1-5-32-550': 'BUILTIN\\Print Operators',
            'S-1-5-32-551': 'BUILTIN\\Backup Operators',
            'S-1-5-32-552': 'BUILTIN\\Replicators',
            'S-1-5-18': 'NT AUTHORITY\\SYSTEM',
            'S-1-5-19': 'NT AUTHORITY\\LOCAL SERVICE',
            'S-1-5-20': 'NT AUTHORITY\\NETWORK SERVICE',
        }

        # Well-known RIDs (relative identifiers) - last part of SID
        self.well_known_rids = {
            '500': 'Administrator',
            '501': 'Guest',
            '502': 'krbtgt',
            '512': 'Domain Admins',
            '513': 'Domain Users',
            '514': 'Domain Guests',
            '515': 'Domain Computers',
            '516': 'Domain Controllers',
            '517': 'Cert Publishers',
            '518': 'Schema Admins',
            '519': 'Enterprise Admins',
            '520': 'Group Policy Creator Owners',
            '521': 'Read-only Domain Controllers',
            '522': 'Cloneable Domain Controllers',
            '525': 'Protected Users',
            '526': 'Key Admins',
            '527': 'Enterprise Key Admins',
        }

    def reset_sid_cache(self):
        """Reset the SID to name cache for new parsing session."""
        self.sid_to_name = {}
        self.sid_to_type = {}

    def parse_json(self, json_content: str, sid_map: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Parse BloodHound JSON content and extract findings.

        Args:
            json_content: JSON string content
            sid_map: Optional pre-populated SID to name mapping

        Returns:
            Dictionary with categorized findings
        """
        logger.info(f"Parsing BloodHound JSON content ({len(json_content)} characters)")
        try:
            data = json.loads(json_content)
            logger.info(f"JSON parsed successfully, extracting findings...")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format: {e}")
            raise ValueError(f"Invalid JSON format: {e}")

        if sid_map:
            logger.info(f"Using provided SID map with {len(sid_map)} entries")
            self.sid_to_name.update(sid_map)

        findings = self._extract_findings(data)
        logger.info(f"Extracted findings: {findings['summary'].get('high_risk_count', 0)} high, {findings['summary'].get('medium_risk_count', 0)} medium, {findings['summary'].get('low_risk_count', 0)} low risk")
        return findings

    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a BloodHound JSON file.

        Args:
            file_path: Path to the JSON file

        Returns:
            Dictionary with categorized findings
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        return self._extract_findings(data)

    def build_sid_map(self, json_content: str) -> Dict[str, str]:
        """
        Build a SID to Name mapping from BloodHound JSON data.
        This should be called first for all files before extracting findings.

        Args:
            json_content: JSON string content

        Returns:
            Dictionary mapping SIDs to names
        """
        try:
            data = json.loads(json_content)
        except json.JSONDecodeError:
            return {}

        nodes = self._get_nodes(data)
        sid_map = {}

        for node in nodes:
            if not isinstance(node, dict):
                continue

            # Get the object's SID/ObjectIdentifier
            obj_id = node.get('ObjectIdentifier', '')
            properties = node.get('Properties', {})
            name = properties.get('name', '')

            if obj_id and name:
                sid_map[obj_id] = name
                # Also store by domain-prefixed SID if applicable
                domain = properties.get('domain', '')
                if domain and not obj_id.startswith(domain):
                    domain_sid = f"{domain}-{obj_id}"
                    sid_map[domain_sid] = name

            # Also check for samaccountname as fallback
            sam_name = properties.get('samaccountname', '')
            if obj_id and sam_name and obj_id not in sid_map:
                domain = properties.get('domain', '')
                if domain:
                    sid_map[obj_id] = f"{sam_name}@{domain}"
                else:
                    sid_map[obj_id] = sam_name

        # Update instance cache
        self.sid_to_name.update(sid_map)

        # Also extract type information
        for node in nodes:
            if not isinstance(node, dict):
                continue
            obj_id = node.get('ObjectIdentifier', '')
            # Determine type from file structure or properties
            if obj_id:
                # Check for explicit type indicators
                if node.get('IsDC'):
                    self.sid_to_type[obj_id] = 'Computer'
                elif 'PrimaryGroupSID' in node:
                    # Users and computers have PrimaryGroupSID
                    props = node.get('Properties', {})
                    if props.get('samaccountname', '').endswith('$'):
                        self.sid_to_type[obj_id] = 'Computer'
                    else:
                        self.sid_to_type[obj_id] = 'User'
                elif 'Members' in node:
                    self.sid_to_type[obj_id] = 'Group'

        return sid_map

    def _get_nodes(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract nodes list from various BloodHound JSON formats."""
        # Format 1: Direct data structure with 'data' key
        if 'data' in data:
            return data.get('data', [])
        # Format 2: Data is a list itself
        elif isinstance(data, list):
            return data
        else:
            # Try to find nodes in any key that contains a list
            for key in data.keys():
                if isinstance(data[key], list) and len(data[key]) > 0:
                    return data[key]
        return []

    def resolve_sid(self, sid: str, principal_type: str = 'Unknown') -> str:
        """
        Resolve a SID to a human-readable name.

        Args:
            sid: The SID to resolve
            principal_type: Type hint from the ACE

        Returns:
            Human-readable name or formatted SID
        """
        # Check our cached mapping first
        if sid in self.sid_to_name:
            return self.sid_to_name[sid]

        # Check well-known SIDs
        if sid in self.well_known_sids:
            return self.well_known_sids[sid]

        # Handle domain-prefixed SIDs (e.g., "MARVEL.LOCAL-S-1-5-32-544")
        if '-S-1-' in sid:
            parts = sid.split('-S-1-')
            domain = parts[0]
            actual_sid = 'S-1-' + parts[1]

            if actual_sid in self.well_known_sids:
                return self.well_known_sids[actual_sid]

            # Check for well-known RID
            rid = actual_sid.split('-')[-1]
            if rid in self.well_known_rids:
                return f"{self.well_known_rids[rid]}@{domain}"

        # Check for well-known RID in regular SIDs
        if sid.startswith('S-1-5-21-'):
            rid = sid.split('-')[-1]
            if rid in self.well_known_rids:
                return self.well_known_rids[rid]

        # Return a formatted version with type hint
        if principal_type != 'Unknown':
            # Extract RID for context
            rid = sid.split('-')[-1] if '-' in sid else sid
            return f"{principal_type}(RID:{rid})"

        return sid

    def _extract_findings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract security findings from BloodHound data.

        Args:
            data: Parsed BloodHound JSON data

        Returns:
            Dictionary with categorized findings
        """
        findings = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'summary': {
                'total_nodes': 0,
                'total_edges': 0,
                'high_risk_count': 0,
                'medium_risk_count': 0,
                'low_risk_count': 0
            }
        }

        nodes = self._get_nodes(data)

        # First pass: build SID map from this data
        for node in nodes:
            if not isinstance(node, dict):
                continue

            obj_id = node.get('ObjectIdentifier', '')
            properties = node.get('Properties', {})
            name = properties.get('name', '')

            if obj_id and name:
                self.sid_to_name[obj_id] = name

        # Second pass: extract findings with resolved names
        for node in nodes:
            if not isinstance(node, dict):
                continue

            properties = node.get('Properties', {})
            node_name = properties.get('name', 'Unknown')

            # Determine node type from context
            node_type = 'Unknown'
            if node.get('IsDC'):
                node_type = 'DomainController'
            elif properties.get('samaccountname', '').endswith('$'):
                node_type = 'Computer'
            elif 'Members' in node:
                node_type = 'Group'
            elif 'PrimaryGroupSID' in node:
                node_type = 'User'
            elif 'GPOLocalGroups' in node or 'Links' in node:
                node_type = 'GPO'
            elif 'ChildObjects' in node:
                node_type = 'OU'

            findings['summary']['total_nodes'] += 1

            # Extract ACEs (Access Control Entries)
            aces = node.get('Aces', [])
            if aces:
                for ace in aces:
                    if not isinstance(ace, dict):
                        continue

                    edge_type = ace.get('RightName', 'Unknown')
                    principal_sid = ace.get('PrincipalSID', '')
                    principal_type = ace.get('PrincipalType', 'Unknown')
                    is_inherited = ace.get('IsInherited', False)

                    # Resolve the principal SID to a name
                    source_name = self.resolve_sid(principal_sid, principal_type)

                    findings['summary']['total_edges'] += 1

                    finding = {
                        'edge_type': edge_type,
                        'source': source_name,
                        'source_type': principal_type,
                        'target': node_name,
                        'target_type': node_type,
                        'risk_level': self._assess_risk(edge_type),
                        'is_inherited': is_inherited,
                        'principal_sid': principal_sid
                    }

                    # Categorize by risk level
                    risk = finding['risk_level']
                    if risk == 'High':
                        findings['high_risk'].append(finding)
                        findings['summary']['high_risk_count'] += 1
                    elif risk == 'Medium':
                        findings['medium_risk'].append(finding)
                        findings['summary']['medium_risk_count'] += 1
                    else:
                        findings['low_risk'].append(finding)
                        findings['summary']['low_risk_count'] += 1

            # Extract AllowedToDelegate relationships
            delegates = node.get('AllowedToDelegate', [])
            if delegates:
                for delegate in delegates:
                    if isinstance(delegate, str):
                        # Simple SPN string
                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'AllowedToDelegate',
                            'source': node_name,
                            'source_type': node_type,
                            'target': delegate,
                            'target_type': 'Service',
                            'risk_level': 'High',
                            'is_inherited': False
                        }
                        findings['high_risk'].append(finding)
                        findings['summary']['high_risk_count'] += 1

            # Extract AllowedToAct (RBCD)
            allowed_to_act = node.get('AllowedToAct', [])
            if allowed_to_act:
                for actor in allowed_to_act:
                    if isinstance(actor, dict):
                        actor_sid = actor.get('ObjectIdentifier', '')
                        actor_type = actor.get('ObjectType', 'Unknown')
                        actor_name = self.resolve_sid(actor_sid, actor_type)

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'AllowedToAct',
                            'source': actor_name,
                            'source_type': actor_type,
                            'target': node_name,
                            'target_type': node_type,
                            'risk_level': 'Medium',
                            'is_inherited': False
                        }
                        findings['medium_risk'].append(finding)
                        findings['summary']['medium_risk_count'] += 1

            # Extract HasSIDHistory
            sid_history = node.get('HasSIDHistory', [])
            if sid_history:
                for hist in sid_history:
                    if isinstance(hist, dict):
                        hist_sid = hist.get('ObjectIdentifier', '')
                        hist_type = hist.get('ObjectType', 'Unknown')
                        hist_name = self.resolve_sid(hist_sid, hist_type)

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'HasSIDHistory',
                            'source': node_name,
                            'source_type': node_type,
                            'target': hist_name,
                            'target_type': hist_type,
                            'risk_level': 'High',
                            'is_inherited': False
                        }
                        findings['high_risk'].append(finding)
                        findings['summary']['high_risk_count'] += 1

            # Extract Members (for groups)
            members = node.get('Members', [])
            if members:
                for member in members:
                    if isinstance(member, dict):
                        member_sid = member.get('ObjectIdentifier', '')
                        member_type = member.get('ObjectType', 'Unknown')
                        member_name = self.resolve_sid(member_sid, member_type)

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'MemberOf',
                            'source': member_name,
                            'source_type': member_type,
                            'target': node_name,
                            'target_type': 'Group',
                            'risk_level': self._assess_risk('MemberOf'),
                            'is_inherited': False
                        }
                        risk = finding['risk_level']
                        if risk == 'High':
                            findings['high_risk'].append(finding)
                            findings['summary']['high_risk_count'] += 1
                        elif risk == 'Medium':
                            findings['medium_risk'].append(finding)
                            findings['summary']['medium_risk_count'] += 1
                        else:
                            findings['low_risk'].append(finding)
                            findings['summary']['low_risk_count'] += 1

            # Extract Sessions
            sessions = node.get('Sessions', {})
            if isinstance(sessions, dict):
                session_results = sessions.get('Results', [])
                for session in session_results:
                    if isinstance(session, dict):
                        user_sid = session.get('UserSID', '')
                        computer_sid = session.get('ComputerSID', '')
                        user_name = self.resolve_sid(user_sid, 'User')

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'HasSession',
                            'source': user_name,
                            'source_type': 'User',
                            'target': node_name,
                            'target_type': 'Computer',
                            'risk_level': 'High',
                            'is_inherited': False
                        }
                        findings['high_risk'].append(finding)
                        findings['summary']['high_risk_count'] += 1

            # Extract LocalGroups (AdminTo, etc.)
            local_groups = node.get('LocalGroups', [])
            if local_groups:
                for lg in local_groups:
                    if isinstance(lg, dict):
                        group_name = lg.get('Name', '')
                        members_list = lg.get('Results', [])

                        # Determine edge type based on group name
                        edge_type = 'LocalAdmin'
                        if 'admin' in group_name.lower():
                            edge_type = 'AdminTo'
                        elif 'rdp' in group_name.lower() or 'remote desktop' in group_name.lower():
                            edge_type = 'CanRDP'
                        elif 'dcom' in group_name.lower():
                            edge_type = 'ExecuteDCOM'
                        elif 'psremote' in group_name.lower() or 'winrm' in group_name.lower():
                            edge_type = 'CanPSRemote'

                        for member in members_list:
                            if isinstance(member, dict):
                                member_sid = member.get('ObjectIdentifier', '')
                                member_type = member.get('ObjectType', 'Unknown')
                                member_name = self.resolve_sid(member_sid, member_type)

                                findings['summary']['total_edges'] += 1
                                finding = {
                                    'edge_type': edge_type,
                                    'source': member_name,
                                    'source_type': member_type,
                                    'target': node_name,
                                    'target_type': 'Computer',
                                    'risk_level': self._assess_risk(edge_type),
                                    'is_inherited': False
                                }
                                risk = finding['risk_level']
                                if risk == 'High':
                                    findings['high_risk'].append(finding)
                                    findings['summary']['high_risk_count'] += 1
                                elif risk == 'Medium':
                                    findings['medium_risk'].append(finding)
                                    findings['summary']['medium_risk_count'] += 1
                                else:
                                    findings['low_risk'].append(finding)
                                    findings['summary']['low_risk_count'] += 1

            # Extract CA Registry Data (Enterprise CA security)
            ca_registry = node.get('CARegistryData', {})
            if ca_registry:
                ca_security = ca_registry.get('CASecurity', {})
                if isinstance(ca_security, dict):
                    ca_aces = ca_security.get('Data', [])
                    for ace in ca_aces:
                        if isinstance(ace, dict):
                            edge_type = ace.get('RightName', '')
                            if edge_type in ['ManageCA', 'ManageCertificates', 'Enroll']:
                                principal_sid = ace.get('PrincipalSID', '')
                                principal_type = ace.get('PrincipalType', 'Unknown')
                                source_name = self.resolve_sid(principal_sid, principal_type)

                                findings['summary']['total_edges'] += 1
                                risk_level = 'High' if edge_type in ['ManageCA', 'ManageCertificates'] else 'Medium'
                                finding = {
                                    'edge_type': edge_type,
                                    'source': source_name,
                                    'source_type': principal_type,
                                    'target': node_name,
                                    'target_type': 'EnterpriseCA',
                                    'risk_level': risk_level,
                                    'is_inherited': ace.get('IsInherited', False)
                                }
                                if risk_level == 'High':
                                    findings['high_risk'].append(finding)
                                    findings['summary']['high_risk_count'] += 1
                                else:
                                    findings['medium_risk'].append(finding)
                                    findings['summary']['medium_risk_count'] += 1

            # Extract Enabled Certificate Templates (for Enterprise CAs)
            enabled_templates = node.get('EnabledCertTemplates', [])
            if enabled_templates:
                for template in enabled_templates:
                    if isinstance(template, dict):
                        template_id = template.get('ObjectIdentifier', '')
                        template_name = self.resolve_sid(template_id, 'CertTemplate')

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'PublishesCertTemplate',
                            'source': node_name,
                            'source_type': 'EnterpriseCA',
                            'target': template_name,
                            'target_type': 'CertTemplate',
                            'risk_level': 'Low',
                            'is_inherited': False
                        }
                        findings['low_risk'].append(finding)
                        findings['summary']['low_risk_count'] += 1

            # Extract GPO Links
            links = node.get('Links', [])
            if links:
                for link in links:
                    if isinstance(link, dict):
                        gpo_guid = link.get('GUID', '')
                        is_enforced = link.get('IsEnforced', False)
                        gpo_name = self.resolve_sid(gpo_guid, 'GPO')

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'GPLink',
                            'source': gpo_name,
                            'source_type': 'GPO',
                            'target': node_name,
                            'target_type': node_type,
                            'risk_level': 'Medium',
                            'is_inherited': False,
                            'is_enforced': is_enforced
                        }
                        findings['medium_risk'].append(finding)
                        findings['summary']['medium_risk_count'] += 1

            # Extract HostingComputer relationship (for Enterprise CAs)
            hosting_computer = node.get('HostingComputer', '')
            if hosting_computer:
                computer_name = self.resolve_sid(hosting_computer, 'Computer')
                findings['summary']['total_edges'] += 1
                finding = {
                    'edge_type': 'HostsCAService',
                    'source': computer_name,
                    'source_type': 'Computer',
                    'target': node_name,
                    'target_type': 'EnterpriseCA',
                    'risk_level': 'Medium',
                    'is_inherited': False
                }
                findings['medium_risk'].append(finding)
                findings['summary']['medium_risk_count'] += 1

            # Extract Trusts (for domains)
            trusts = node.get('Trusts', [])
            if trusts:
                for trust in trusts:
                    if isinstance(trust, dict):
                        target_domain_sid = trust.get('TargetDomainSid', '')
                        target_domain_name = trust.get('TargetDomainName', self.resolve_sid(target_domain_sid, 'Domain'))
                        trust_direction = trust.get('TrustDirection', 'Unknown')
                        trust_type = trust.get('TrustType', 'Unknown')

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': f'TrustedBy',
                            'source': node_name,
                            'source_type': 'Domain',
                            'target': target_domain_name,
                            'target_type': 'Domain',
                            'risk_level': 'Medium',
                            'is_inherited': False,
                            'trust_direction': trust_direction,
                            'trust_type': trust_type
                        }
                        findings['medium_risk'].append(finding)
                        findings['summary']['medium_risk_count'] += 1

            # Extract SPNTargets (for Kerberoasting)
            spn_targets = node.get('SPNTargets', [])
            if spn_targets:
                for spn in spn_targets:
                    if isinstance(spn, dict):
                        target_sid = spn.get('ObjectIdentifier', '')
                        target_type_hint = spn.get('ObjectType', 'Computer')
                        target_name = self.resolve_sid(target_sid, target_type_hint)

                        findings['summary']['total_edges'] += 1
                        finding = {
                            'edge_type': 'HasSPN',
                            'source': node_name,
                            'source_type': node_type,
                            'target': target_name,
                            'target_type': target_type_hint,
                            'risk_level': 'Medium',
                            'is_inherited': False
                        }
                        findings['medium_risk'].append(finding)
                        findings['summary']['medium_risk_count'] += 1

        return findings

    def _assess_risk(self, edge_type: str) -> str:
        """
        Assess the risk level of an edge type.

        Args:
            edge_type: BloodHound edge type

        Returns:
            Risk level: 'High', 'Medium', or 'Low'
        """
        if edge_type in self.high_risk_edges:
            return 'High'
        elif edge_type in self.medium_risk_edges:
            return 'Medium'
        else:
            return 'Low'

    def get_findings_by_edge_type(self, findings: Dict[str, Any], edge_type: str) -> List[Dict[str, Any]]:
        """
        Filter findings by specific edge type.

        Args:
            findings: Parsed findings from extract_findings
            edge_type: Edge type to filter (e.g., 'AdminTo')

        Returns:
            List of findings matching the edge type
        """
        results = []

        for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
            for finding in findings.get(risk_level, []):
                if finding['edge_type'] == edge_type:
                    results.append(finding)

        return results

    def get_attack_paths_to_target(self, findings: Dict[str, Any], target_name: str) -> List[Dict[str, Any]]:
        """
        Find all attack paths leading to a specific target.

        Args:
            findings: Parsed findings
            target_name: Target node name

        Returns:
            List of findings where target matches
        """
        results = []

        for risk_level in ['high_risk', 'medium_risk', 'low_risk']:
            for finding in findings.get(risk_level, []):
                if target_name.lower() in finding['target'].lower():
                    results.append(finding)

        return results
