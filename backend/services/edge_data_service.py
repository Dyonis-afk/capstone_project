"""
Edge Data Service
Loads and provides access to structured BloodHound edge data.

This service provides accurate, curated data for:
- Attack command templates
- Remediation steps and scripts
- Detection event IDs
- MITRE ATT&CK mappings

The structured data is used instead of RAG for technical accuracy,
while RAG is used for contextual narrative generation.
"""

import json
import os
import re
from typing import Dict, List, Optional, Any
from functools import lru_cache


class EdgeDataService:
    """Service for accessing structured BloodHound edge data."""

    def __init__(self, data_path: str = None):
        """Initialize the service with path to edge data JSON."""
        if data_path is None:
            # Default path relative to this file (goes up to backend/ folder)
            # This works both locally and in production (Render deployment)
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_path = os.path.join(base_dir, 'data', 'bloodhound_edges_enhanced.json')

        self.data_path = data_path
        self._edge_data: Dict[str, Any] = {}
        self._load_data()

    def _load_data(self):
        """Load edge data from JSON file."""
        try:
            if os.path.exists(self.data_path):
                with open(self.data_path, 'r') as f:
                    self._edge_data = json.load(f)
                print(f"[EdgeDataService] Loaded {len(self._edge_data)} edge types")
            else:
                print(f"[EdgeDataService] Warning: Data file not found at {self.data_path}")
                self._edge_data = {}
        except Exception as e:
            print(f"[EdgeDataService] Error loading data: {e}")
            self._edge_data = {}

    def get_edge_data(self, edge_type: str) -> Optional[Dict[str, Any]]:
        """Get all data for an edge type."""
        return self._edge_data.get(edge_type)

    def get_description(self, edge_type: str) -> str:
        """Get the description for an edge type."""
        edge = self._edge_data.get(edge_type, {})
        return edge.get('description', f'{edge_type} relationship in Active Directory')

    def get_abuse_info(self, edge_type: str) -> str:
        """Get abuse information for an edge type."""
        edge = self._edge_data.get(edge_type, {})
        return edge.get('abuse', f'Abuse {edge_type} permissions')

    def get_opsec_level(self, edge_type: str) -> str:
        """Get operational security level (Low/Medium/High)."""
        edge = self._edge_data.get(edge_type, {})
        opsec = edge.get('opsec', 'Medium')
        # Extract just the level if it's a longer string
        if isinstance(opsec, str):
            if opsec.lower().startswith('low'):
                return 'Low'
            elif opsec.lower().startswith('high'):
                return 'High'
            elif opsec.lower().startswith('medium'):
                return 'Medium'
        return 'Medium'

    def get_mitre_mappings(self, edge_type: str) -> List[Dict[str, str]]:
        """Get MITRE ATT&CK mappings with URLs."""
        edge = self._edge_data.get(edge_type, {})
        mitre_ids = edge.get('mitre_mapping', [])

        mappings = []
        for technique_id in mitre_ids:
            # Build real MITRE URL
            if '.' in technique_id:
                # Sub-technique like T1558.003
                base, sub = technique_id.split('.')
                url = f"https://attack.mitre.org/techniques/{base}/{sub}/"
            else:
                url = f"https://attack.mitre.org/techniques/{technique_id}/"

            mappings.append({
                'tag': 'MITRE',
                'title': f'{technique_id} - {self._get_mitre_name(technique_id)}',
                'url': url
            })

        return mappings

    def _get_mitre_name(self, technique_id: str) -> str:
        """Get human-readable name for MITRE technique."""
        # Common technique names
        names = {
            'T1098': 'Account Manipulation',
            'T1098.001': 'Additional Cloud Credentials',
            'T1003': 'OS Credential Dumping',
            'T1003.001': 'LSASS Memory',
            'T1003.006': 'DCSync',
            'T1003.008': 'LSASS Password Dump',
            'T1558': 'Steal or Forge Kerberos Tickets',
            'T1558.003': 'Kerberoasting',
            'T1558.002': 'Silver Ticket',
            'T1222': 'File and Directory Permissions Modification',
            'T1222.001': 'Windows File and Directory Permissions Modification',
            'T1484': 'Domain Policy Modification',
            'T1484.001': 'Group Policy Modification',
            'T1078': 'Valid Accounts',
            'T1078.002': 'Domain Accounts',
            'T1078.003': 'Local Accounts',
            'T1021': 'Remote Services',
            'T1021.001': 'Remote Desktop Protocol',
            'T1021.002': 'SMB/Windows Admin Shares',
            'T1021.006': 'Windows Remote Management',
            'T1187': 'Forced Authentication',
            'T1134': 'Access Token Manipulation',
            'T1134.005': 'SID-History Injection',
            'T1543.003': 'Windows Service',
            'T1550.003': 'Pass the Ticket',
            'T1649': 'Steal or Forge Authentication Certificates',
            'T1482': 'Domain Trust Discovery',
        }
        return names.get(technique_id, 'Attack Technique')

    def get_detection_event_ids(self, edge_type: str) -> List[Dict[str, str]]:
        """Get detection event IDs for an edge type."""
        edge = self._edge_data.get(edge_type, {})

        # Check for structured format first
        if 'detection_event_ids' in edge:
            return edge['detection_event_ids']

        # Parse from string format
        detection_str = edge.get('detection', '')
        event_ids = []

        # Extract event IDs like "4662", "4728", etc.
        ids_found = re.findall(r'\b(\d{4})\b', detection_str)
        for eid in ids_found:
            event_ids.append({
                'id': eid,
                'description': self._get_event_description(eid)
            })

        return event_ids if event_ids else [
            {'id': '4662', 'description': 'Directory Service Access'},
            {'id': '5136', 'description': 'Directory object modified'}
        ]

    def _get_event_description(self, event_id: str) -> str:
        """Get description for Windows event ID."""
        descriptions = {
            '4624': 'Successful logon',
            '4625': 'Failed logon',
            '4648': 'Explicit credential logon',
            '4662': 'Directory Service Access',
            '4670': 'Permissions changed on object',
            '4672': 'Special privileges assigned',
            '4688': 'Process creation',
            '4697': 'Service installed',
            '4724': 'Password reset attempt',
            '4728': 'Member added to security-enabled global group',
            '4729': 'Member removed from security-enabled global group',
            '4732': 'Member added to security-enabled local group',
            '4733': 'Member removed from security-enabled local group',
            '4738': 'User account changed',
            '4756': 'Member added to security-enabled universal group',
            '4768': 'Kerberos TGT requested',
            '4769': 'Kerberos service ticket requested',
            '4778': 'Session reconnected',
            '4779': 'Session disconnected',
            '5136': 'Directory object modified',
            '5137': 'Directory object created',
            '5141': 'Directory object deleted',
        }
        return descriptions.get(event_id, 'Security event')

    def get_remediation_steps(self, edge_type: str) -> List[str]:
        """Get remediation steps for an edge type."""
        edge = self._edge_data.get(edge_type, {})

        # Check for structured format
        if 'remediation_steps' in edge:
            return edge['remediation_steps']

        # Parse from string
        remediation_str = edge.get('remediation', '')
        if remediation_str:
            # Split by comma or period, clean up
            steps = [s.strip() for s in re.split(r'[,.]', remediation_str) if s.strip()]
            return steps[:5]  # Limit to 5 steps

        return ['Review and remediate the identified relationship', 'Implement least privilege']

    def get_powershell_remediation(self, edge_type: str, context: Dict[str, str] = None) -> str:
        """Get PowerShell remediation script with substitutions."""
        edge = self._edge_data.get(edge_type, {})
        script = edge.get('powershell_remediation', '')

        if context and script:
            script = self._substitute_placeholders(script, context)

        return script

    def get_command_templates(
        self,
        edge_type: str,
        target_type: str = None,
        context: Dict[str, str] = None
    ) -> List[Dict[str, str]]:
        """
        Get attack command templates for an edge type.

        Args:
            edge_type: The BloodHound edge type (e.g., 'GenericAll', 'DCSync')
            target_type: Optional target object type (User, Computer, Group, Domain)
            context: Dictionary with substitution values (SOURCE, TARGET, DOMAIN, DC, etc.)

        Returns:
            List of command dictionaries with title, tool, command, explanation
        """
        edge = self._edge_data.get(edge_type, {})
        templates = []

        # Check for target-type specific templates
        if target_type and 'command_templates_by_target' in edge:
            target_templates = edge['command_templates_by_target'].get(target_type, [])
            templates.extend(target_templates)

        # Also get general templates
        if 'command_templates' in edge:
            templates.extend(edge['command_templates'])

        # If no templates found, generate basic one from abuse field
        if not templates:
            abuse = edge.get('abuse', f'Abuse {edge_type}')
            templates = [{
                'title': f'Exploit {edge_type}',
                'tool': 'Various',
                'command': f'# {abuse}',
                'explanation': abuse
            }]

        # Substitute placeholders if context provided
        if context:
            templates = [self._substitute_template(t, context) for t in templates]

        return templates

    def _substitute_template(self, template: Dict[str, str], context: Dict[str, str]) -> Dict[str, str]:
        """Substitute placeholders in a template."""
        result = {}
        for key, value in template.items():
            if isinstance(value, str):
                result[key] = self._substitute_placeholders(value, context)
            else:
                result[key] = value
        return result

    def _substitute_placeholders(self, text: str, context: Dict[str, str]) -> str:
        """Replace {{PLACEHOLDER}} with actual values."""
        result = text
        for key, value in context.items():
            placeholder = '{{' + key + '}}'
            result = result.replace(placeholder, value)
        return result

    def build_attack_steps_from_path(
        self,
        path: List[Dict[str, Any]],
        domain: str = None,
        dc: str = None
    ) -> List[Dict[str, Any]]:
        """
        Build sequential attack steps from a BloodHound path.

        Args:
            path: List of path nodes with source, target, edge_type, etc.
            domain: Domain name for substitution
            dc: Domain controller for substitution

        Returns:
            List of numbered attack steps with commands
        """
        attack_steps = []
        step_number = 1

        for node in path:
            edge_type = node.get('edge_type', node.get('relationship', ''))
            source = node.get('source', node.get('start_node', ''))
            target = node.get('target', node.get('end_node', ''))
            target_type = node.get('target_type', node.get('end_type', 'Unknown'))

            # Clean up names (remove @DOMAIN if present)
            source_name = source.split('@')[0] if '@' in source else source
            target_name = target.split('@')[0] if '@' in target else target

            # Infer domain from names
            if not domain and '@' in source:
                domain = source.split('@')[-1]

            # Build context for substitution
            context = {
                'SOURCE': source_name,
                'TARGET': target_name,
                'DOMAIN': domain or 'DOMAIN.LOCAL',
                'DC': dc or 'DC01',
                'DC_IP': '<DC_IP>',
                'ATTACKER': source_name,
                'ATTACKER_IP': '<ATTACKER_IP>',
                'DOMAIN_DN': f"DC={domain.split('.')[0]},DC={domain.split('.')[-1]}" if domain and '.' in domain else 'DC=domain,DC=com',
                'TARGET_DN': f'CN={target_name},DC=domain,DC=com'
            }

            # Get templates for this edge type
            templates = self.get_command_templates(edge_type, target_type, context)

            # Take the first/best template for each step
            if templates:
                best_template = templates[0]
                attack_steps.append({
                    'step_number': step_number,
                    'title': best_template.get('title', f'Exploit {edge_type}'),
                    'tool': best_template.get('tool', 'Various'),
                    'command': best_template.get('command', ''),
                    'explanation': best_template.get('explanation', ''),
                    'edge_type': edge_type,
                    'source': source,
                    'target': target
                })
                step_number += 1

        return attack_steps

    def get_siem_queries(self, edge_types: List[str]) -> List[Dict[str, str]]:
        """Generate SIEM queries for detecting the given edge types."""
        # Collect all relevant event IDs
        event_ids = set()
        for edge_type in edge_types:
            for event in self.get_detection_event_ids(edge_type):
                event_ids.add(event['id'])

        event_list = ','.join(sorted(event_ids))

        return [
            {
                'platform': 'Splunk',
                'query': f'index=windows EventCode IN ({event_list}) | stats count by EventCode, Account_Name, Computer | sort -count'
            },
            {
                'platform': 'Microsoft Sentinel (KQL)',
                'query': f'SecurityEvent | where EventID in ({event_list}) | summarize count() by EventID, Account, Computer | order by count_ desc'
            }
        ]

    def get_iocs(self, edge_types: List[str]) -> List[str]:
        """Get indicators of compromise for edge types."""
        iocs = set()

        ioc_map = {
            'DCSync': [
                'Replication traffic from non-DC systems',
                'Event 4662 with replication GUIDs from workstations'
            ],
            'GenericAll': [
                'ACL modifications on privileged objects',
                'Unexpected permission changes outside change windows'
            ],
            'AdminTo': [
                'PsExec service creation (Event 4697)',
                'LSASS memory access from unexpected processes'
            ],
            'HasSession': [
                'Credential dumping tool signatures',
                'LSASS memory access attempts'
            ],
            'HasSPNConfigured': [
                'High volume TGS requests from single user',
                'RC4 encryption requests (0x17) for service tickets'
            ],
            'ForceChangePassword': [
                'Password resets by non-helpdesk accounts',
                'Password resets of privileged accounts'
            ]
        }

        for edge_type in edge_types:
            if edge_type in ioc_map:
                iocs.update(ioc_map[edge_type])

        # Add generic IOCs
        iocs.add('Unusual LDAP queries from non-DC systems')
        iocs.add('PowerShell execution with encoded commands')

        return list(iocs)[:7]


# Singleton instance
_edge_data_service: Optional[EdgeDataService] = None


def get_edge_data_service() -> EdgeDataService:
    """Get or create the singleton EdgeDataService instance."""
    global _edge_data_service
    if _edge_data_service is None:
        _edge_data_service = EdgeDataService()
    return _edge_data_service
