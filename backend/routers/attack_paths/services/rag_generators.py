"""
RAG-Based Generation Functions for Attack Path Analysis
Location: backend/routers/attack_paths/services/rag_generators.py

Simplified version - trusts the model's inherent knowledge of AD security.
No fallbacks, no hand-holding. Just provide data, let the model generate.
"""

import json
import re
import logging
from typing import List, Dict, Any

from ..utils import parse_llm_json
from ..constants.prompt_templates import format_remediation_context

logger = logging.getLogger(__name__)


# =============================================================================
# FIX 4: Step Sequencing Logic
# Commands that require prior credential access - should NOT be Step 1
# =============================================================================
HIGH_PRIV_COMMANDS = [
    # DCSync - requires GetChanges/GetChangesAll rights (need to compromise account first)
    'secretsdump',
    'lsadump::dcsync',
    'dcsync',
    # Golden Ticket - requires krbtgt hash (from DCSync)
    'kerberos::golden',
    'ticketer.py',
    'golden ticket',
    # Pass-the-Hash/Ticket - requires obtained hash/ticket
    'psexec.py',
    'wmiexec.py',
    'smbexec.py',
    'evil-winrm',
    'pass-the-hash',
    'pth-',
    'sekurlsa::pth',
    'kerberos::ptt',
    # LSASS dumping - requires admin on target
    'sekurlsa::logonpasswords',
    'procdump',
    'mimikatz',  # Generally requires elevated access
    'nanodump',
    'comsvcs.dll',
]

# Commands that are valid as Step 1 (enumeration, initial access)
VALID_STEP1_COMMANDS = [
    # Enumeration
    'get-aduser',
    'get-adgroup',
    'get-domainuser',
    'get-domaingroup',
    'ldapsearch',
    'bloodhound',
    'sharphound',
    # Kerberoasting/AS-REP (credential access from low priv)
    'getuserspns',
    'getnpusers',
    'rubeus kerberoast',
    'rubeus asreproast',
    'invoke-kerberoast',
    # Password attacks
    'kerbrute',
    'spray',
    # ACL enumeration
    'get-acl',
    'get-domainobjectacl',
]

# =============================================================================
# FIX 5: Tool Cleanup - Hallucinated Tool Corrections
# Maps commonly hallucinated tool names to their correct equivalents
# =============================================================================
HALLUCINATED_TOOL_FIXES = {
    # Deprecated tools → modern replacements
    'crackmapexec': 'nxc',
    'cme ': 'nxc ',
    'cme.exe': 'nxc',

    # Non-existent Impacket scripts → correct names
    'impacket-dcsync': 'impacket-secretsdump',
    'dcsync.py': 'secretsdump.py',
    'dvcsync.py': 'secretsdump.py',
    'replication.py': 'secretsdump.py',
    'impacket-kerberoast': 'impacket-GetUserSPNs',
    'kerberoast.py': 'GetUserSPNs.py',
    'impacket-asreproast': 'impacket-GetNPUsers',
    'asreproast.py': 'GetNPUsers.py',
    'impacket-golden': 'impacket-ticketer',
    'golden.py': 'ticketer.py',
    'impacket-silver': 'impacket-ticketer',
    'silver.py': 'ticketer.py',
    'impacket-pth': 'impacket-psexec',  # PTH is done via psexec -hashes
    'pth.py': 'psexec.py',
    'passthehash.py': 'psexec.py',
    'impacket-dacl': 'impacket-dacledit',
    'dacl.py': 'dacledit.py',
    'impacket-owner': 'impacket-owneredit',
    'owner.py': 'owneredit.py',
    'impacket-addcomputer': 'impacket-addcomputer',  # This one exists
    'impacket-rbcd': 'impacket-rbcd',  # This one exists

    # Wrong Rubeus syntax
    'rubeus.exe kerberoast': 'Rubeus.exe kerberoast',
    'rubeus.exe asreproast': 'Rubeus.exe asreproast',

    # Non-existent tools
    'sharphound.exe': 'SharpHound.exe',
    'bloodhound.exe': 'SharpHound.exe',  # BloodHound is the GUI, SharpHound is collector
    'invoke-dcsync': 'Invoke-Mimikatz -Command "lsadump::dcsync',
    'invoke-golden': 'Invoke-Mimikatz -Command "kerberos::golden',

    # Certipy corrections
    'certipy.py': 'certipy',
    'certify.py': 'Certify.exe',  # Certify is C#, not Python

    # Case sensitivity fixes
    'Bloodyad': 'bloodyAD',
    'BloodyAD': 'bloodyAD',
    'BLOODYAD': 'bloodyAD',

    # bloodyAD wrong subcommands (add spn doesn't exist)
    'bloodyAD add spn': "bloodyAD set object TARGET servicePrincipalName -v 'fake/kerberoast'",
    'bloodyad add spn': "bloodyAD set object TARGET servicePrincipalName -v 'fake/kerberoast'",
}

# Tools that don't exist at all - should be removed or replaced with explanation
NONEXISTENT_TOOLS = [
    'dvcsync',
    'replicator.py',
    'adreplication.py',
    'kerberoaster.py',
    'asreproaster.py',
    'goldenticket.py',
    'silverticket.py',
    'pth-toolkit',
    'invoke-dcsync',
    'invoke-golden',
    'invoke-silver',
]


def _build_available_attack_vectors(environment_analysis: Dict, findings: List[Dict]) -> str:
    """
    Build a context string describing what attack vectors are ACTUALLY available
    in the environment, so the model only suggests techniques that can work.
    """
    vectors = []

    # Check environment_analysis first (from extractFindings)
    if environment_analysis:
        # Check for Kerberoastable users
        kerberoastable = environment_analysis.get('kerberoastable_users', [])
        if kerberoastable:
            vectors.append(f"- **Kerberoastable users found**: {', '.join(kerberoastable[:5])}")
            vectors.append("  → Use Kerberoasting (GetUserSPNs.py, Rubeus kerberoast) to crack their passwords")

        # Check for AS-REP roastable users
        asrep_users = environment_analysis.get('asrep_roastable_users', [])
        if asrep_users:
            vectors.append(f"- **AS-REP Roastable users found**: {', '.join(asrep_users[:5])}")
            vectors.append("  → Use AS-REP Roasting (GetNPUsers.py, Rubeus asreproast) to crack their passwords")

        # Check environment summary for other vectors
        env_summary = environment_analysis.get('environment_summary', {})
        if env_summary:
            if env_summary.get('unconstrained_delegation'):
                vectors.append(f"- **Unconstrained delegation systems found**")
            if env_summary.get('dcsync_principals'):
                vectors.append(f"- **DCSync capable principals exist**")

    # CRITICAL: Check finding node properties directly for attack vectors
    # This catches Kerberoastable/AS-REP roastable when node properties are available
    kerberoast_users = []
    asrep_users_from_props = []
    delegation_systems = []

    for f in findings:
        source = f.get('source', '').split('@')[0] if f.get('source') else ''
        source_props = f.get('source_properties', {})

        # Check hasspn property - indicates Kerberoastable
        if source_props.get('hasspn'):
            spns = source_props.get('serviceprincipalnames', [])
            if source and source not in kerberoast_users:
                kerberoast_users.append(source)
                if spns and isinstance(spns, list):
                    vectors.append(f"- **{source}** has SPNs: {', '.join(spns[:2])} (Kerberoastable)")

        # Check dontreqpreauth - indicates AS-REP roastable
        if source_props.get('dontreqpreauth'):
            if source and source not in asrep_users_from_props:
                asrep_users_from_props.append(source)
                vectors.append(f"- **{source}** has no Kerberos pre-auth required (AS-REP Roastable)")

        # Check delegation properties
        if source_props.get('unconstraineddelegation'):
            if source:
                vectors.append(f"- **{source}** has unconstrained delegation")
        if source_props.get('trustedtoauth'):
            if source:
                vectors.append(f"- **{source}** has constrained delegation (S4U abuse possible)")

    # Dedupe and summarize
    if kerberoast_users and not any('Kerberoastable users found' in v for v in vectors):
        vectors.append(f"  → Use GetUserSPNs.py or Rubeus kerberoast to crack these accounts")

    if asrep_users_from_props and not any('AS-REP Roastable users found' in v for v in vectors):
        vectors.append(f"  → Use GetNPUsers.py or Rubeus asreproast to crack these accounts")

    # Check edge types for additional context
    edge_types = set()
    for f in findings:
        edge = f.get('edge_type', '')
        if edge:
            edge_types.add(edge)

    # Map edge types to available techniques (fallback if no properties found)
    if ('HasSPN' in edge_types or 'Kerberoastable' in edge_types) and not kerberoast_users:
        vectors.append("- **Service accounts with SPNs detected in path** → Kerberoasting is viable")

    # CRITICAL: Add NEGATIVE signals for common techniques that are NOT available
    # Without these, the LLM defaults to suggesting Kerberoasting/AS-REP even when
    # zero kerberoastable or AS-REP roastable users exist in the environment.
    unavailable = []

    has_kerberoast = bool(kerberoast_users) or any('Kerberoastable' in v for v in vectors)
    has_asrep = bool(asrep_users_from_props) or any('AS-REP' in v for v in vectors)

    if not has_kerberoast:
        unavailable.append("- Kerberoasting is NOT available — zero users with SPNs found in this environment")
    if not has_asrep:
        unavailable.append("- AS-REP Roasting is NOT available — zero users without pre-authentication found")

    if not vectors and not unavailable:
        return ""

    result = ""
    if vectors:
        result += "\n## AVAILABLE ATTACK VECTORS IN THIS ENVIRONMENT\nThese attack techniques are CONFIRMED to work based on the data:\n" + "\n".join(vectors)

    if unavailable:
        result += "\n\n## TECHNIQUES NOT AVAILABLE IN THIS ENVIRONMENT\n" + "\n".join(unavailable)
        result += "\n\n**Do NOT suggest Kerberoasting or AS-REP Roasting if listed as unavailable above.**"

    result += "\n\n**ONLY suggest techniques that match the available vectors. Do NOT speculate about unavailable attack vectors.**"
    return result


def generate_observation_rag(finding_context: Dict, rag_service, add_log=None) -> str:
    """Generate observation text using RAG. Model knows AD security - just provide the data."""
    domain = finding_context.get('domain', 'the domain')
    query_name = finding_context.get('query_name', finding_context.get('attack_technique_name', 'security issue'))
    primary_edge = finding_context.get('primary_edge', '')
    sources = finding_context.get('sources', [])
    targets = finding_context.get('targets', [])
    count = finding_context.get('finding_count', 0)

    # Extract entity roles for remediation targeting
    compromisable_entities = finding_context.get('compromisable_entities', [])
    privilege_targets = finding_context.get('privilege_targets', [])
    remediation_context = format_remediation_context(compromisable_entities, privilege_targets)

    # T0 context - this is specific to user's data
    t0_info = ""
    t0_targets = finding_context.get('t0_target_assets', [])
    if t0_targets:
        t0_info = f"\n⚠️ CRITICAL: Targets Tier 0 assets: {', '.join(t0_targets)}"

    # Build remediation context section if available (helps LLM understand entity roles)
    remediation_section = ""
    if remediation_context:
        remediation_section = f"\n\n{remediation_context}"

    # Determine the key vulnerable entity (compromisable_entities takes priority)
    key_vulnerable = compromisable_entities[0] if compromisable_entities else (sources[0] if sources else 'affected principals')

    # Build explicit per-edge relationship descriptions so the LLM knows
    # WHICH source connects to WHICH target via WHICH edge.
    # Without this, the LLM sees flattened lists and misattributes edges
    # (e.g., "OLIVIA has ForceChangePassword over BENJAMIN" when actually
    # OLIVIA→MICHAEL is GenericAll and MICHAEL→BENJAMIN is ForceChangePassword)
    relationship_context = ""
    sample_descriptions = finding_context.get('sample_path_descriptions', [])
    if sample_descriptions and len(sample_descriptions) > 1:
        relationship_context = "\nEXACT RELATIONSHIPS (attribute each edge to the correct source→target pair):\n"
        for desc in sample_descriptions[:5]:
            relationship_context += f"- {desc}\n"
        relationship_context += "IMPORTANT: Each edge belongs to a SPECIFIC source→target pair above. Do NOT mix them up."

    # For chain discoveries, add the full chain path so the observation describes
    # the multi-hop nature accurately (who connects to whom via which edge)
    chain_context = ""
    if finding_context.get('is_chain_discovery'):
        chain_rag = finding_context.get('chain_rag_context', '')
        if chain_rag:
            chain_context = f"\nMULTI-HOP ATTACK CHAIN:\n{chain_rag}\nDescribe this as a chain — each edge belongs to the node before the arrow."

    prompt = f"""Write a BRIEF security observation for a pentest report (exactly 3-4 sentences MAX).

Finding: {query_name}
Domain: {domain}
Edge type: {primary_edge}
Count: {count} instances
VULNERABLE ENTITY: {key_vulnerable} (THIS is the account with the security issue - focus on this)
All Sources: {', '.join(sources[:3]) if sources else 'various principals'}
All Targets: {', '.join(targets[:3]) if targets else 'various targets'}{t0_info}{relationship_context}{chain_context}{remediation_section}

STRICT RULES:
- Write ONLY 3-4 sentences
- NO code blocks or commands
- NO markdown headers (no "###", "**Bold:**" headers)
- NO step-by-step instructions
- NO remediation advice
- Just describe WHAT was found and WHY it's risky

Example format:
"The DOMAIN exhibits X instances of [finding] affecting [sources]. This configuration allows [risk]. An attacker could [impact]. The severity is [level] due to [reason]."

Write the observation now:"""

    try:
        # Use fast model (DeepSeek-Chat) for observation - simple summary task
        response = rag_service.query_fast(prompt)
        result = response.get('result', '').strip()
        if result and len(result) > 50:
            # Post-process: Remove any code blocks that snuck in
            result = _clean_observation(result)
            return result

        # Fast model failed - retry with R1 (slower but reliable)
        if add_log:
            add_log("DEBUG", "Chat returned empty/short observation, retrying with R1...", debug_only=True)
        response = rag_service.query(prompt)
        result = response.get('result', '').strip()
        if result:
            return _clean_observation(result)
    except Exception as e:
        if add_log:
            add_log("DEBUG", f"RAG observation failed: {e}", debug_only=True)

    # Model failed - return minimal observation (no elaborate fallback)
    return f"During analysis of {domain}, {count} instances of {query_name} were identified affecting {', '.join(sources[:2]) if sources else 'multiple principals'}."


def _fix_markdown_spacing(text: str) -> str:
    """Fix spacing issues around markdown bold markers.

    Ensures there's always a space before and after **bold** text when adjacent to words.
    This prevents text like "**GetChangesAll**permissions" from rendering incorrectly.
    """
    if not text:
        return text

    # Use a function-based replacement to handle both before and after spacing in one pass
    def add_spacing(match):
        before = match.group(1) or ''
        content = match.group(2)
        after = match.group(3) or ''

        # Add space before ** if preceded by letter
        if before and before.isalpha():
            before = before + ' '

        # Add space after ** if followed by letter
        if after and after.isalpha():
            after = ' ' + after

        return f'{before}**{content}**{after}'

    # Match: optional char before, **, content, **, optional char after
    # This handles **bold** surrounded by various characters
    text = re.sub(r'(.)?(\*\*)([^*]+?)(\*\*)(.)?',
                  lambda m: (m.group(1) or '') +
                            (' ' if m.group(1) and m.group(1).isalpha() else '') +
                            '**' + m.group(3) + '**' +
                            (' ' if m.group(5) and m.group(5).isalpha() else '') +
                            (m.group(5) or ''),
                  text)

    # Fix double spaces that might have been introduced
    text = re.sub(r' {2,}', ' ', text)

    return text


def _clean_observation(text: str) -> str:
    """Clean observation text - remove code blocks, headers, and truncate if too long."""

    # Remove code blocks
    text = re.sub(r'```[\s\S]*?```', '', text)
    text = re.sub(r'`[^`]+`', '', text)

    # Remove markdown headers
    text = re.sub(r'^#+\s+.*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\*\*[^:]+:\*\*\s*', '', text, flags=re.MULTILINE)

    # Remove lines that look like commands
    lines = text.split('\n')
    clean_lines = []
    for line in lines:
        # Skip lines that look like commands or code
        if any(pattern in line.lower() for pattern in [
            'ps >', '$ ', 'mimikatz', 'powerview', 'rubeus',
            'get-ad', 'set-ad', 'invoke-', '-identity', '-filter',
            'secretsdump', 'impacket', 'crackmapexec'
        ]):
            continue
        clean_lines.append(line)

    text = '\n'.join(clean_lines).strip()

    # Remove excessive whitespace
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {2,}', ' ', text)

    # Fix spacing around bold markers
    text = _fix_markdown_spacing(text)

    # Truncate if still too long (>1000 chars is way too much for an observation)
    if len(text) > 1000:
        # Find sentence boundary near 800 chars
        truncate_point = text.rfind('. ', 0, 900)
        if truncate_point > 400:
            text = text[:truncate_point + 1]
        else:
            text = text[:900] + '...'

    return text.strip()


def generate_understanding_qa(finding_context: Dict, rag_service, add_log=None) -> List[Dict]:
    """Generate Q&A explanations. Model knows attack techniques - just ask for Q&A."""
    query_name = finding_context.get('query_name', finding_context.get('attack_technique_name', 'this attack'))
    primary_edge = finding_context.get('primary_edge', '')
    domain = finding_context.get('domain', 'the domain')
    sources = finding_context.get('sources', [])
    targets = finding_context.get('targets', [])

    key_source = sources[0].split('@')[0] if sources else 'the source'
    key_target = targets[0].split('@')[0] if targets else 'the target'

    # Include per-edge relationships for multi-hop findings
    relationship_info = ""
    if finding_context.get('is_chain_discovery'):
        chain_rag = finding_context.get('chain_rag_context', '')
        if chain_rag:
            relationship_info = f"\nMulti-hop chain path:\n{chain_rag}\nEach edge belongs to the node before the arrow — attribute correctly in Q3."
    else:
        sample_descriptions = finding_context.get('sample_path_descriptions', [])
        if sample_descriptions and len(sample_descriptions) > 1:
            relationship_info = "\nExact relationships:\n" + "\n".join(f"- {d}" for d in sample_descriptions[:5])
            relationship_info += "\nIMPORTANT: Each edge belongs to a specific source→target pair. Attribute correctly in Q3."

    prompt = f"""Generate 3 Q&A pairs explaining this Active Directory security finding.

Finding: {query_name}
Edge type: {primary_edge}
Domain: {domain}
Example source: {key_source}
Example target: {key_target}{relationship_info}

Return JSON array:
[
  {{"question": "What is [attack technique name]?", "answer": "2-3 sentences explaining the attack..."}},
  {{"question": "Why is it dangerous?", "answer": "2-3 sentences on security risk..."}},
  {{"question": "How does it apply here?", "answer": "2-3 sentences specific to {key_source} and {key_target}..."}}
]

Use **bold** for important terms. Use proper attack technique names, not just edge names.
Return ONLY valid JSON."""

    def _try_parse_qa(result_text):
        """Try to parse Q&A JSON from LLM response."""
        json_match = re.search(r'\[[\s\S]*?\]', result_text)
        if json_match:
            qa_list = json.loads(json_match.group())
            if isinstance(qa_list, list) and len(qa_list) >= 3:
                cleaned_qa = []
                for qa in qa_list[:3]:
                    cleaned_qa.append({
                        'question': qa.get('question', ''),
                        'answer': _clean_qa_answer(qa.get('answer', ''))
                    })
                return cleaned_qa
        return None

    try:
        # Use fast model (DeepSeek-Chat) for Q&A - educational content task
        response = rag_service.query_fast(prompt)
        result = response.get('result', '')
        parsed = _try_parse_qa(result)
        if parsed:
            return parsed

        # Fast model failed/malformed JSON - retry with R1
        if add_log:
            add_log("DEBUG", "Q&A fast model failed, retrying with R1...", debug_only=True)
        response = rag_service.query(prompt)
        result = response.get('result', '')
        parsed = _try_parse_qa(result)
        if parsed:
            return parsed
    except Exception as e:
        # First attempt failed - try R1 as fallback
        if add_log:
            add_log("DEBUG", f"RAG Q&A failed: {e}, retrying with R1...", debug_only=True)
        try:
            response = rag_service.query(prompt)
            result = response.get('result', '')
            parsed = _try_parse_qa(result)
            if parsed:
                return parsed
        except Exception as e2:
            if add_log:
                add_log("DEBUG", f"RAG Q&A retry also failed: {e2}", debug_only=True)

    # Minimal fallback - model failed
    return [
        {'question': f'What is {query_name}?', 'answer': f'This finding involves **{primary_edge}** relationships that could be exploited for privilege escalation.'},
        {'question': 'Why is it dangerous?', 'answer': 'It enables attackers to **escalate privileges** or move laterally within the domain.'},
        {'question': 'How does it apply here?', 'answer': f'In **{domain}**, {key_source} has exploitable relationships to **{key_target}**.'}
    ]


def _clean_qa_answer(text: str) -> str:
    """Clean Q&A answer text to ensure markdown renders properly."""
    if not text:
        return text

    # Fix escaped asterisks (from JSON encoding issues)
    text = text.replace('\\*\\*', '**')
    text = text.replace('\\*', '*')

    # Fix double-escaped newlines
    text = text.replace('\\n', '\n')

    # Use shared function for markdown spacing fixes
    text = _fix_markdown_spacing(text)

    # Remove any leftover HTML entities
    text = text.replace('&quot;', '"')
    text = text.replace('&amp;', '&')
    text = text.replace('&lt;', '<')
    text = text.replace('&gt;', '>')

    return text.strip()


def generate_attack_chain_r1(
    findings: List[Dict[str, Any]],
    finding_context: Dict,
    rag_service,
    add_log: callable = None,
    live_graph_data: str = ""
) -> List[Dict]:
    """
    Generate narrative attack chain using DYNAMIC EDGE-SPECIFIC PROMPTS.

    LLM-FIRST APPROACH: Let the LLM generate detailed, context-aware attack chains.
    Only fall back to templates if LLM generation or parsing fails completely.

    Args:
        findings: List of finding dictionaries from the query
        finding_context: Context about the finding (domain, edges, sources, targets, etc.)
        rag_service: RAG service for LLM queries
        add_log: Optional logging callback
        live_graph_data: Pre-fetched context data string from client-side Neo4j queries

    Returns list of attack steps with opsec_options for frontend compatibility.
    """
    from ..constants.prompt_templates import build_t0_context, format_attack_path
    from ..constants.dynamic_prompts import get_prompt_for_edges

    domain = finding_context.get('domain', '')  # Never use placeholder domain
    edges = finding_context.get('edges', [])
    sources = finding_context.get('sources', [])
    targets = finding_context.get('targets', [])
    t0_targets = finding_context.get('t0_target_assets', [])
    environment_analysis = finding_context.get('environment_analysis', {})
    attack_indicators = finding_context.get('attack_indicators', [])
    # Use actual DC hostname or derive from domain if available
    dc_hostname = finding_context.get('dc_hostname', f'DC.{domain}' if domain else '')

    # Build attack path visualization
    attack_path = format_attack_path(findings)

    # Build T0 context
    t0_context = build_t0_context(t0_targets)

    # Build available attack vectors context from environment analysis
    available_vectors = _build_available_attack_vectors(environment_analysis, findings)

    # Add specific attack indicators from node properties (hasspn, dontreqpreauth, etc.)
    if attack_indicators:
        available_vectors += "\n\n## CONFIRMED ATTACK VECTORS FROM NODE PROPERTIES\n"
        available_vectors += "These are CONFIRMED from BloodHound node data:\n"
        for indicator in attack_indicators[:10]:
            available_vectors += f"- {indicator}\n"

    # live_graph_data is now passed in directly from client-side pre-fetched context
    if live_graph_data and add_log:
        add_log("DEBUG", f"  📊 Using pre-fetched live graph data ({len(live_graph_data)} chars)", debug_only=True)

    # Build context for dynamic prompt selection (include query_name so prompt can match finding intent)
    query_name = finding_context.get('query_name', '') or finding_context.get('attack_technique_name', '')

    # Extract source/target types for entity context (Fix 1: Entity Name Threading)
    source_types = finding_context.get('source_types', [])
    target_types = finding_context.get('target_types', [])

    # Fallback: extract from findings if not in finding_context
    if not source_types and findings:
        for f in findings:
            st = f.get('source_type', '')
            if st and st not in source_types:
                source_types.append(st)
    if not target_types and findings:
        for f in findings:
            tt = f.get('target_type', '')
            if tt and tt not in target_types:
                target_types.append(tt)

    # Get primary types for the entity context block
    source_type = source_types[0] if source_types else 'Principal'
    target_type = target_types[0] if target_types else 'Object'

    # Extract entity roles EARLY so we can use compromisable_entities in prompt_context
    # This is critical for Kerberoasting/AS-REP where the vulnerable entity needs to be highlighted
    compromisable_entities = finding_context.get('compromisable_entities', [])
    privilege_targets = finding_context.get('privilege_targets', [])

    # Determine primary_source: WHO the attacker authenticates as.
    # For credential attacks (Kerberoasting, AS-REP): the compromisable entity IS the source
    #   e.g., SVC_TGS has an SPN → attack SVC_TGS (source = compromisable entity)
    # For ACL abuse (GenericAll, WriteDacl): the compromisable entity is the TARGET —
    #   the source is the rights holder who runs the attack commands.
    #   e.g., SHARED SUPPORT ACCOUNTS -[GenericAll]-> DC → source = SHARED SUPPORT ACCOUNTS
    # If primary_source == target, the LLM will use the target name as the auth username.
    acl_edges = {'GENERICALL', 'GENERICWRITE', 'WRITEDACL', 'WRITEOWNER', 'OWNS',
                 'FORCECHANGEPASSWORD', 'ADDMEMBER', 'ADDSELF', 'ADDKEYCREDENTIALLINK',
                 'WRITESPN', 'ALLEXTENDEDRIGHTS', 'WRITEACCOUNTRESTRICTIONS'}
    primary_edge_upper = edges[0].upper() if edges else ''
    is_acl_abuse = primary_edge_upper in acl_edges

    if is_acl_abuse:
        # For ACL abuse: source is the rights holder (the group/user WITH the permission)
        primary_source = sources[0] if sources else 'compromised principal'
    else:
        # For credential attacks: source is the compromisable entity (the vulnerable account)
        primary_source = compromisable_entities[0] if compromisable_entities else (sources[0] if sources else 'compromised principal')

    # Chain discovery detection
    is_chain = finding_context.get('is_chain_discovery', False)

    if is_chain and findings:
        # CHAIN DISCOVERY: Use dedicated chain prompt instead of edge-specific prompts.
        # Edge-specific prompts focus on ONE technique (e.g., DCSync), but chains need
        # ordered steps across multiple hops. The old approach caused:
        # - DCSync chain: LLM tried to grant entry point DCSync rights instead of pivoting
        # - ACL chain: LLM generated steps out of order (reset target before compromising intermediate)
        from ..constants.dynamic_prompts import CHAIN_DISCOVERY_PROMPT, _format_prompt

        chain_rag = finding_context.get('chain_rag_context', '')

        # Build consolidation context if this scenario was merged from multiple chains
        # KEEP IT MINIMAL — long consolidation context pushes key instructions to the middle
        # of the prompt where R1 loses focus, causing hallucinations (Golden Ticket, etc.)
        consolidation_context = ""
        consolidated_from = finding_context.get('consolidated_from', [])
        if consolidated_from and len(consolidated_from) > 1:
            unique_chains = list(set(consolidated_from))
            consolidation_context = (
                f"\n\n## CONSOLIDATED SCENARIO\n"
                f"This finding was consolidated from {len(consolidated_from)} related chains "
                f"({', '.join(unique_chains[:3])}). "
                f"Generate one coherent attack chain covering the full path.\n"
            )

        # Calculate minimum step count from exploitation edges
        skip_edges = {'MEMBEROF', 'CONTAINS', 'GPLINK', 'GETCHANGES', 'GETCHANGESALL', 'GETCHANGESINFILTEREDSET'}
        exploit_edges = [e for e in edges if e.upper() not in skip_edges]
        # DCSync edges (GetChanges/GetChangesAll) count as ONE step, not three
        has_dcsync = any(e.upper() in {'GETCHANGES', 'GETCHANGESALL', 'GETCHANGESINFILTEREDSET', 'DCSYNC'} for e in edges)
        min_steps = max(3, len(exploit_edges) + (1 if has_dcsync else 0))

        prompt_context = {
            'domain': domain,
            'attack_path': attack_path,
            'query_name': query_name,
            'source': primary_source,  # Keep entry point as source (don't override to rights holder)
            'target': targets[0] if targets else 'target objective',
            'source_type': source_type,
            'target_type': target_type,
            'edge_types': ', '.join(set(edges)) if edges else 'various relationships',
            't0_context': t0_context,
            'available_vectors': available_vectors,
            'dc_hostname': dc_hostname,
            'chain_rag_context': chain_rag,
            'consolidation_context': consolidation_context,
            'min_steps': min_steps,
        }

        prompt = _format_prompt(CHAIN_DISCOVERY_PROMPT, prompt_context)
        attack_name = "Multi-Hop Chain"

        if add_log:
            add_log("DEBUG", f"  📋 Using chain discovery prompt for edges: {edges[:3]}" +
                    (f" (consolidated from {len(consolidated_from)} chains)" if consolidated_from else ""),
                    debug_only=True)
    else:
        # Standard (non-chain) findings: use edge-specific prompt selection
        prompt_context = {
            'domain': domain,
            'attack_path': attack_path,
            'query_name': query_name,
            'source': primary_source,
            'target': targets[0] if targets else 'target objective',
            'source_type': source_type,
            'target_type': target_type,
            'edge_types': ', '.join(set(edges)) if edges else 'various relationships',
            't0_context': t0_context,
            'available_vectors': available_vectors,
            'dc_hostname': dc_hostname
        }

        prompt, attack_name = get_prompt_for_edges(edges, prompt_context)

        # For multi-result static findings, inject per-edge relationship descriptions
        # so the LLM knows which source has which edge on which target
        sample_descriptions = finding_context.get('sample_path_descriptions', [])
        if sample_descriptions and len(sample_descriptions) > 1:
            rel_section = "\n\n## EXACT RELATIONSHIPS\n"
            for desc in sample_descriptions[:5]:
                rel_section += f"- {desc}\n"
            rel_section += "CRITICAL: Each edge belongs to a SPECIFIC source→target pair. Match each attack step to the correct relationship above."
            prompt = prompt + rel_section

    if add_log:
        add_log("DEBUG", f"  📋 Selected prompt type: {attack_name} for edges: {edges[:3]}", debug_only=True)

    # Inject query-specific RAG context from static_queries.py into the attack chain prompt
    # This contains edge-specific command examples (e.g., correct bloodyAD syntax for AddSelf,
    # RBCD step-by-step, CoerceToTGT prerequisites) that the generic prompt templates don't have.
    # The rag_context is defined per-query in DISCOVERY_QUERIES but needs to be passed through.
    # Check finding_context for it (set by parallel_processor from query_info)
    query_rag = finding_context.get('query_rag_context', '')
    if not query_rag:
        # Fallback: try to find it from the query name in DISCOVERY_QUERIES
        from ..constants.static_queries import DISCOVERY_QUERIES
        for q in DISCOVERY_QUERIES:
            if q['name'] == query_name and q.get('rag_context'):
                query_rag = q['rag_context']
                break
    if query_rag and len(query_rag) > 50:
        prompt = prompt + "\n\n## QUERY-SPECIFIC ATTACK GUIDANCE\n" + query_rag

    # Inject pre-fetched graph data into the prompt
    if live_graph_data:
        prompt = prompt + "\n\n" + live_graph_data + "\n\nUse the LIVE GRAPH DATA above to populate commands with real entity names, hostnames, and SPNs. Do NOT generate Cypher queries as attack commands."

    # Inject web search threat intelligence (if available from parallel_processor)
    web_attack_context = finding_context.get('web_attack_context', '')
    if web_attack_context:
        prompt = prompt + "\n\n" + web_attack_context

    # Use already-extracted entity roles for remediation targeting
    # (compromisable_entities and privilege_targets were extracted earlier for prompt_context)
    remediation_context = format_remediation_context(compromisable_entities, privilege_targets)

    # Inject remediation context into prompt
    if remediation_context:
        prompt = prompt + "\n\n" + remediation_context + """

IMPORTANT: When generating attack steps, the TARGET of the attack is one of the COMPROMISABLE entities above.
When generating remediation, fix the COMPROMISABLE entity, NOT the privilege target groups."""

    # CRITICAL: Reinforce key formatting rules at END of prompt so they're
    # seen last by the LLM, regardless of how much context was injected above.
    # Without this, web search and live graph data push rules to the middle
    # of the prompt where R1 is less likely to follow them.
    prompt += """

## FINAL REMINDERS (MUST FOLLOW)
1. evil-winrm -H takes ONLY the NT hash, NOT LM:NT pair format
2. Machine account names MUST include $ suffix (e.g., ATTACKERPC$)
3. impacket-secretsdump with -k MUST include domain/user@ prefix (e.g., SUPPORT.HTB/DC$@DC.SUPPORT.HTB)
4. Step 1 must be an ATTACK action (addcomputer, Kerberoast, etc.) — NOT enumeration
5. Each exploitation edge needs its OWN step with full commands
6. NEVER use bloodhound-python, SharpHound, or ANY data collection as an attack step — the data is ALREADY collected
7. When cleaning up fake SPNs, use: bloodyAD ... set object TARGET servicePrincipalName -v '' (the -v '' is REQUIRED to clear it)
8. EVERY step MUST contain a ```bash code block with executable commands. Steps without code blocks will be DROPPED from the report. Do NOT generate steps that only have descriptions — every step needs at least one command.
9. Do NOT add "Refresh Kerberos Ticket" or "Renew TGT" as a separate step. When using bloodyAD/impacket with password auth, the tool handles authentication automatically — no manual ticket refresh needed.
10. For GenericAll on User targets: password reset (bloodyAD set password) is the SAFE option, targeted kerberoasting is the RISKY option.
11. bloodyAD syntax: use --attr (DOUBLE dash), NOT -attr. For domain objects use DN format: 'DC=DOMAIN,DC=TLD' not 'DOMAIN.TLD'
12. NEVER fabricate NTLM hashes, passwords, or credentials in commands. Use placeholders ONLY:
    - For -hashes flag: `-hashes <LM_HASH>:<NT_HASH>` (NOT aad3b435b51404eeaad3b435b51404ee:<hash>)
    - For passwords: `'<PASSWORD>'`
    - For NT hash only: `-H <NT_HASH>`
    - ❌ WRONG: `-hashes aad3b435b51404eeaad3b435b51404ee:579da618cfaa...` (looks like real hash)
    - ✅ CORRECT: `-hashes <LM_HASH>:<NT_HASH>`
13. Impacket syntax — NEVER invent flags. Username goes AFTER domain slash:
    - GetNPUsers.py DOMAIN/USERNAME -dc-ip DC -no-pass -format hashcat (NOT -user USERNAME)
    - GetUserSPNs.py -dc-ip DC DOMAIN/user:'pass' -request (NOT -user or -username)
    - secretsdump.py DOMAIN/user:'pass'@DC (NOT -u user -p pass)
    - If unsure about a flag, OMIT it rather than guessing"""

    # Edge-specific reinforcement at the END where R1 pays most attention
    edges_upper = {e.upper() for e in edges}
    dcsync_edges = {'DCSYNC', 'GETCHANGES', 'GETCHANGESALL', 'GETCHANGESINFILTEREDSET'}
    genericwrite_edges = {'GENERICWRITE', 'GENERICALL'}

    if edges_upper & dcsync_edges:
        prompt += """
6. The attack chain ENDS at DCSync (impacket-secretsdump). DCSync proves domain compromise.
7. Do NOT add Golden Ticket, krbtgt extraction, ticketer.py, or kerberos::golden as steps
8. Do NOT add any "persistence" or "post-exploitation" steps after DCSync
9. The LAST step must be: DCSync → dump Administrator hash → authenticate with it"""

    if 'GENERICWRITE' in edges_upper and target_type.upper() == 'USER':
        prompt += """
6. The GenericWrite exploitation step MUST show BOTH techniques as OPSEC options:
   SAFE: Targeted Kerberoasting (bloodyAD set SPN → GetUserSPNs → hashcat)
   RISKY: Shadow Credentials (certipy shadow auto)
7. Do NOT present two variants of the same technique — show one of EACH"""

    if ('GENERICALL' in edges_upper or 'ALLEXTENDEDRIGHTS' in edges_upper) and target_type.upper() == 'USER':
        prompt += """
6. For GenericAll/AllExtendedRights on a USER: password reset is the FASTEST option.
   SAFE: bloodyAD -d DOMAIN -u SOURCE -p PASS --host DC set password TARGET 'NewP@ss123!'
   RISKY: Targeted Kerberoasting (bloodyAD set SPN → GetUserSPNs → hashcat) — avoids password change
7. Password reset gives INSTANT access. Targeted Kerberoasting requires cracking."""

    if ('WRITEDACL' in edges_upper or 'WRITEOWNER' in edges_upper or 'OWNS' in edges_upper):
        if target_type.upper() == 'DOMAIN':
            prompt += """
6. WriteDacl/WriteOwner on DOMAIN: grant DCSync rights, then secretsdump.
   Step 1: impacket-dacledit -action write -rights DCSync -principal SOURCE -target DOMAIN
   Step 2: impacket-secretsdump DOMAIN/SOURCE:PASS@DC"""
        elif target_type.upper() == 'USER':
            prompt += """
6. WriteDacl/WriteOwner on USER: grant FullControl, then reset password.
   Step 1: impacket-dacledit -action write -rights FullControl -principal SOURCE -target TARGET
   Step 2: bloodyAD set password TARGET 'NewP@ss123!'"""

    if is_chain:
        skip = {'MEMBEROF', 'CONTAINS', 'GPLINK'}
        exploit = [e for e in edges if e.upper() not in skip]
        min_steps = max(3, len(exploit))
        prompt += f"\n{8 if edges_upper & dcsync_edges else 6}. You MUST generate AT LEAST {min_steps} attack steps"

    # Retry logic for LLM non-determinism
    # Sometimes the model returns empty/malformed results; a retry usually succeeds
    MAX_RETRIES = 2
    primary_edge = edges[0] if edges else 'Unknown'

    # Log prompt size for debugging test vs report differences
    prompt_len = len(prompt)
    has_web = 'EXTERNAL THREAT INTELLIGENCE' in prompt
    has_live_graph = 'LIVE GRAPH DATA' in prompt
    logger.info(f"Attack chain prompt: {prompt_len} chars, web_search={has_web}, live_graph={has_live_graph}")
    if add_log:
        add_log("DEBUG", f"  📝 Prompt size: {prompt_len} chars (web={has_web}, graph={has_live_graph})", debug_only=True)

    for attempt in range(MAX_RETRIES + 1):
        try:
            if add_log:
                retry_suffix = f" (attempt {attempt + 1}/{MAX_RETRIES + 1})" if attempt > 0 else ""
                add_log("INFO", f"  🧠 Generating narrative attack chain...{retry_suffix}")

            response = rag_service.query(prompt)
            result = response.get('result', '')

            if result and len(result) > 200:
                logger.info(f"Attack chain LLM response: {len(result)} chars")
                if add_log:
                    add_log("DEBUG", f"  📄 LLM response: {len(result)} chars", debug_only=True)
                # Parse markdown narrative into structured steps for frontend
                steps = _parse_narrative_to_steps(result, edges, domain, sources, targets)

                # Determine minimum acceptable steps
                # For chains with multiple exploitation edges, we need at least 2 steps
                # (compromise intermediate + exploit final target)
                skip_edges = {'MEMBEROF', 'CONTAINS', 'GPLINK'}
                exploit_edge_count = len([e for e in edges if e.upper() not in skip_edges])
                min_acceptable = max(1, min(exploit_edge_count, 3))

                if steps and len(steps) >= min_acceptable:
                    if add_log:
                        add_log("INFO", f"  ✅ Generated {len(steps)} attack steps")
                    return steps
                elif steps and len(steps) >= 1 and attempt >= MAX_RETRIES:
                    # Last attempt — return whatever we have rather than nothing
                    if add_log:
                        add_log("WARNING", f"  ⚠️ Only {len(steps)}/{min_acceptable} steps parsed for {primary_edge}, returning partial")
                    return steps
                else:
                    # Not enough steps parsed — retry
                    if attempt < MAX_RETRIES:
                        if add_log:
                            add_log("WARNING", f"  ⚠️ Only {len(steps) if steps else 0}/{min_acceptable} steps parsed for {primary_edge}, retrying...")
                        continue
            else:
                # LLM returned insufficient content - retry if we have attempts left
                if attempt < MAX_RETRIES:
                    if add_log:
                        add_log("WARNING", f"  ⚠️ LLM returned insufficient content for {primary_edge}, retrying...")
                    continue

        except Exception as e:
            if add_log:
                add_log("WARNING", f"  ⚠️ Attack chain generation failed: {str(e)[:100]}")
            # On exception, retry if we have attempts left
            if attempt < MAX_RETRIES:
                continue

    # All retries exhausted - return empty
    if add_log:
        add_log("WARNING", f"  ⚠️ No attack steps generated for {primary_edge} after {MAX_RETRIES + 1} attempts")
    return []  # Return empty - let calling code handle this


def _parse_narrative_to_steps(narrative: str, edges: List[str], domain: str, sources: List[str], targets: List[str]) -> List[Dict]:
    """
    Parse markdown narrative into structured steps for frontend compatibility.
    Extracts step titles, objectives, prerequisites, descriptions, and code blocks with OPSEC labels.
    More resilient parsing to handle various LLM output formats.

    CRITICAL: Only parses steps from the ATTACK section, not the Remediation section.
    """
    import re

    steps = []

    # CRITICAL FIX: Truncate narrative BEFORE remediation/detection sections
    # This prevents parsing remediation steps as attack steps
    attack_narrative = narrative
    for cutoff_pattern in [
        r'\n##\s*Remediation',           # ## Remediation Strategy
        r'\n##\s*Detection',             # ## Detection Methods
        r'\n\*\*Remediation',            # **Remediation:
        r'\n---\s*\n.*?remediat',        # --- followed by remediation
    ]:
        cutoff_match = re.search(cutoff_pattern, attack_narrative, re.IGNORECASE)
        if cutoff_match:
            attack_narrative = attack_narrative[:cutoff_match.start()]
            logger.debug(f"Truncated narrative at remediation section (pattern: {cutoff_pattern})")
            break

    # Try multiple step header patterns (LLMs don't always follow exact format)
    step_patterns = [
        r'###\s*Step\s*(\d+)[:\s-]+([^\n]+)',           # ### Step 1: Title
        r'\*\*Step\s*(\d+)[:\s-]+([^\n*]+)\*\*',        # **Step 1: Title**
        r'^Step\s*(\d+)[:\s-]+([^\n]+)',                # Step 1: Title (no ###)
        r'^(\d+)\.\s+\*\*([^\n*]+)\*\*',               # 1. **Title**
        r'^(\d+)\)\s+([^\n]+)',                         # 1) Title
    ]

    step_matches = []
    for pattern in step_patterns:
        matches = list(re.finditer(pattern, attack_narrative, re.MULTILINE | re.IGNORECASE))
        if matches and len(matches) >= 1:
            step_matches = matches
            logger.debug(f"Matched step pattern: {pattern}, found {len(matches)} steps")
            break

    # If no structured steps found, log and return empty (will use fallback templates)
    if not step_matches:
        logger.warning("No structured steps found in narrative - will use fallback templates")

    # VALIDATION: Check if steps look like attack steps (not remediation)
    # Remediation keywords indicate wrong section was parsed
    remediation_keywords = ['remove', 'implement', 'monitor', 'review', 'audit', 'disable', 'rotate',
                           'remediate', 'harden', 'patch', 'update', 'configure', 'restrict']
    attack_keywords = ['compromise', 'execute', 'dump', 'extract', 'crack', 'authenticate',
                      'enumerate', 'escalate', 'move', 'access', 'exploit', 'abuse', 'request',
                      'kerberoast', 'dcsync', 'ticket', 'hash', 'credential', 'password']

    if step_matches:
        # Check first few step titles
        remediation_count = 0
        attack_count = 0
        for match in step_matches[:3]:
            title_lower = match.group(2).lower()
            if any(kw in title_lower for kw in remediation_keywords):
                remediation_count += 1
            if any(kw in title_lower for kw in attack_keywords):
                attack_count += 1

        # If more remediation keywords than attack keywords, these are wrong steps
        if remediation_count > attack_count:
            logger.warning(f"Parsed steps appear to be remediation, not attack steps (remed={remediation_count}, attack={attack_count}). Using fallback.")
            return []  # Return empty to trigger fallback

    for i, match in enumerate(step_matches):
        step_num = int(match.group(1))
        title = match.group(2).strip()

        # Get content between this step and next step (or end of attack_narrative)
        start = match.end()
        end = step_matches[i + 1].start() if i + 1 < len(step_matches) else len(attack_narrative)
        step_content = attack_narrative[start:end]

        # Extract objective - look for **Objective:** pattern
        obj_match = re.search(r'\*\*Objective:\*\*\s*([^\n]+)', step_content, re.IGNORECASE)
        objective = obj_match.group(1).strip() if obj_match else ''

        # Extract prerequisites - look for **Prerequisites:** section with bullet points
        prereq_match = re.search(
            r'\*\*Prerequisites:\*\*\s*([\s\S]*?)(?=\n\*\*(?:OPSEC|Objective|Output)|```|$)',
            step_content, re.IGNORECASE
        )
        prerequisites = []
        if prereq_match:
            prereq_text = prereq_match.group(1).strip()
            # Parse bullet points (- item or * item)
            prereq_items = re.findall(r'^[\s]*[-*]\s*(.+)$', prereq_text, re.MULTILINE)
            prerequisites = [p.strip() for p in prereq_items if p.strip()]

        # Use objective as description, or title if no objective found
        description = objective if objective else title

        # Extract OPSEC-SAFE tool name from header: **OPSEC-SAFE Option: [Tool Name]**
        safe_tool_match = re.search(
            r'\*\*OPSEC-SAFE[^:]*(?:Option)?[:\s]*([^*\n]+)\*\*',
            step_content, re.IGNORECASE
        )
        safe_tool_name = safe_tool_match.group(1).strip() if safe_tool_match else 'Native PowerShell'
        # Clean up tool name
        safe_tool_name = safe_tool_name.strip(':').strip()
        if not safe_tool_name or safe_tool_name.lower() in ['option', ':']:
            safe_tool_name = 'Native PowerShell'

        # Extract OPSEC-SAFE code block - try multiple patterns for resilience
        safe_command = ''
        # Pattern 1: Standard format with header immediately followed by code block
        safe_match = re.search(
            r'\*\*OPSEC-SAFE[^*]*\*\*[^\n]*\n```(?:powershell|bash|cmd)?\n([\s\S]*?)```',
            step_content, re.IGNORECASE
        )
        if safe_match:
            safe_command = safe_match.group(1).strip()
        else:
            # Pattern 2: Allow whitespace/newlines between header and code block
            safe_match = re.search(
                r'\*\*OPSEC-SAFE[^*]*\*\*[\s\S]*?```(?:powershell|bash|cmd)?\s*\n([\s\S]*?)```',
                step_content, re.IGNORECASE
            )
            if safe_match:
                safe_command = safe_match.group(1).strip()
            else:
                # Pattern 3: Find first code block after OPSEC-SAFE mention
                safe_section = re.search(r'OPSEC-SAFE([\s\S]*?)(?:AGGRESSIVE|$)', step_content, re.IGNORECASE)
                if safe_section:
                    code_match = re.search(r'```(?:powershell|bash|cmd|python|sh)?\s*\n([\s\S]*?)```', safe_section.group(1))
                    if code_match:
                        safe_command = code_match.group(1).strip()
        # Filter out any Cypher queries from the command
        safe_command = _filter_cypher_from_command(safe_command)

        # Extract safe explanation - look for "Why safer" or "Why this is safer"
        safe_why = re.search(r'>\s*\*\*Why[^:]*:\*\*\s*([^\n]+)', step_content)
        safe_explanation = safe_why.group(1).strip() if safe_why else 'Uses native tools, blends with normal activity'

        # Extract AGGRESSIVE tool name from header: **AGGRESSIVE Option: [Tool Name]**
        risky_tool_match = re.search(
            r'\*\*AGGRESSIVE[^:]*(?:Option)?[:\s]*([^*\n⚠]+)',
            step_content, re.IGNORECASE
        )
        risky_tool_name = risky_tool_match.group(1).strip() if risky_tool_match else 'Offensive Tool'
        # Clean up tool name
        risky_tool_name = risky_tool_name.strip(':').strip('*').strip()
        if not risky_tool_name or risky_tool_name.lower() in ['option', ':']:
            risky_tool_name = 'Offensive Tool'

        # Extract AGGRESSIVE code block - try multiple patterns for resilience
        risky_command = ''
        # Pattern 1: Standard format with header immediately followed by code block
        risky_match = re.search(
            r'\*\*AGGRESSIVE[^*]*\*\*[^\n]*\n```(?:powershell|bash|cmd)?\n([\s\S]*?)```',
            step_content, re.IGNORECASE
        )
        if risky_match:
            risky_command = risky_match.group(1).strip()
        else:
            # Pattern 2: Allow whitespace/newlines between header and code block
            risky_match = re.search(
                r'\*\*AGGRESSIVE[^*]*\*\*[\s\S]*?```(?:powershell|bash|cmd)?\s*\n([\s\S]*?)```',
                step_content, re.IGNORECASE
            )
            if risky_match:
                risky_command = risky_match.group(1).strip()
            else:
                # Pattern 3: Find first code block after AGGRESSIVE mention
                risky_section = re.search(r'AGGRESSIVE([\s\S]*?)(?:What happens next|Output|---|\Z)', step_content, re.IGNORECASE)
                if risky_section:
                    code_match = re.search(r'```(?:powershell|bash|cmd|python|sh)?\s*\n([\s\S]*?)```', risky_section.group(1))
                    if code_match:
                        risky_command = code_match.group(1).strip()
        # Filter out any Cypher queries from the command
        risky_command = _filter_cypher_from_command(risky_command)

        # Extract risky explanation
        risky_why = re.search(r'>\s*\*\*Detection Risk:\*\*\s*([^\n]+)', step_content)
        risky_explanation = risky_why.group(1).strip() if risky_why else 'May trigger AV/EDR alerts'

        # Determine category from title/content
        category = 'Privilege Escalation'
        title_lower = title.lower()
        if 'enum' in title_lower or 'discover' in title_lower or 'verify' in title_lower:
            category = 'Discovery'
        elif 'credential' in title_lower or 'dump' in title_lower or 'dcsync' in title_lower:
            category = 'Credential Access'
        elif 'lateral' in title_lower or 'session' in title_lower or 'remote' in title_lower:
            category = 'Lateral Movement'
        elif 'persist' in title_lower or 'golden' in title_lower:
            category = 'Persistence'

        # Build step structure matching frontend expectations
        step = {
            'step_number': step_num,
            'title': title,
            'category': category,
            'objective': objective,
            'prerequisites': prerequisites,
            'description': description,
            'opsec_options': []
        }

        # Add safe option only if it has an actual executable command (not just comments)
        if safe_command and _has_executable_command(safe_command):
            display_tool_name = safe_tool_name
            if display_tool_name == 'Native PowerShell':
                display_tool_name = _get_descriptive_tool_name(safe_command, safe_tool_name, edges)

            safe_option = {
                'opsec_level': 'safe',
                'tool_name': display_tool_name,
                'command': safe_command,
                'explanation': safe_explanation
            }
            safe_option = _fix_opsec_level_for_offline_tools(safe_option)
            step['opsec_options'].append(safe_option)

        # Add risky option only if it has an actual executable command
        if risky_command and _has_executable_command(risky_command):
            display_tool_name = risky_tool_name
            if display_tool_name == 'Offensive Tool':
                display_tool_name = _get_descriptive_tool_name(risky_command, risky_tool_name, edges)

            risky_option = {
                'opsec_level': 'risky',
                'tool_name': display_tool_name,
                'command': risky_command,
                'explanation': risky_explanation
            }
            risky_option = _fix_opsec_level_for_offline_tools(risky_option)
            step['opsec_options'].append(risky_option)

        # FALLBACK: If no labeled options found, try to extract ANY code blocks from step content
        if not step['opsec_options']:
            # Find all code blocks in this step
            all_code_blocks = re.findall(r'```(?:powershell|bash|cmd|python|sh)?\s*\n([\s\S]*?)```', step_content)
            if all_code_blocks:
                for i, code_block in enumerate(all_code_blocks[:2]):  # Max 2 blocks
                    filtered_code = _filter_cypher_from_command(code_block.strip())
                    # Must have substantial, executable content (no comment-only or Cypher)
                    if filtered_code and len(filtered_code) > 10 and _has_executable_command(filtered_code):
                        tool_name = _get_descriptive_tool_name(filtered_code, 'Command', edges)
                        fallback_option = {
                            'opsec_level': 'safe' if i == 0 else 'risky',
                            'tool_name': tool_name,
                            'command': filtered_code,
                            'explanation': 'Extracted from step narrative'
                        }
                        # Apply OPSEC fix for offline tools
                        fallback_option = _fix_opsec_level_for_offline_tools(fallback_option)
                        step['opsec_options'].append(fallback_option)

        if step['opsec_options']:
            # Check for tier bleed (SAFE and RISKY using same tool)
            step = _detect_tier_bleed(step)
            steps.append(step)
        else:
            logger.debug(f"Skipping step {step_num} - no parseable commands found")

    # Fix 3.5: Sort steps by LLM-assigned step_number to fix out-of-order generation
    # The LLM sometimes writes steps in wrong document order (e.g., Step 3 appears before Step 1)
    # The regex parser captures them in document order, but we should respect the LLM's numbering
    if len(steps) > 1:
        step_numbers = [s.get('step_number', 0) for s in steps]
        has_unique_numbers = len(set(step_numbers)) == len(step_numbers) and all(n > 0 for n in step_numbers)

        if has_unique_numbers:
            # LLM assigned unique step numbers — sort by them
            original_order = [s.get('step_number') for s in steps]
            steps.sort(key=lambda s: s.get('step_number', 999))
            sorted_order = [s.get('step_number') for s in steps]
            if original_order != sorted_order:
                logger.info(f"Reordered steps by LLM numbering: {original_order} → {sorted_order}")

        # Renumber sequentially (1, 2, 3...) regardless of what LLM assigned
        for idx, s in enumerate(steps):
            s['step_number'] = idx + 1

    # Fix 4: Validate step sequencing (high-priv commands shouldn't be Step 1)
    steps = _validate_step_sequencing(steps)

    # Fix 5: Correct hallucinated tool names
    steps = _fix_hallucinated_tools(steps)

    return steps


def _get_descriptive_tool_name(command: str, default: str, edges: List[str] = None) -> str:
    """Generate a descriptive tool name based on command content and edge types."""
    command_lower = command.lower()
    edges_str = ' '.join(edges or []).lower()

    # Map of keywords to descriptive names
    descriptive_names = {
        ('dcsync', 'secretsdump', 'lsadump::dcsync'): 'DCSync - Domain Credential Extraction',
        ('kerberoast', 'get-domainspnticket', 'getuserspns'): 'Kerberoasting - Service Account Compromise',
        ('asreproast', 'getnpusers'): 'AS-REP Roasting - Pre-Auth Disabled Accounts',
        ('s4u', 'delegation', 'constrained'): 'Kerberos Delegation Abuse',
        ('rbcd', 'allowedtoact', 'msds-allowedtoact'): 'Resource-Based Constrained Delegation',
        ('shadow', 'keycredential', 'whisker'): 'Shadow Credentials Attack',
        ('writedacl', 'set-domainobjectowner', 'add-domainobjectacl'): 'ACL Manipulation',
        ('genericwrite', 'genericall', 'set-domainobject'): 'Domain Object Manipulation',
        ('add-domaingroupmember', 'addmember'): 'Group Membership Modification',
        ('golden', 'ticketer', 'krbtgt'): 'Golden Ticket - Domain Persistence',
        ('certipy', 'certify', 'adcs', 'esc'): 'AD Certificate Services Abuse',
        ('mimikatz', 'sekurlsa'): 'Credential Extraction via Mimikatz',
        ('psexec', 'wmiexec', 'smbexec'): 'Remote Execution',
        ('enter-pssession', 'invoke-command', 'winrm'): 'PowerShell Remoting',
        ('get-aduser', 'get-adcomputer', 'get-adobject'): 'Native AD Enumeration',
        ('hashcat', 'john'): 'Offline Password Cracking',
        ('laps', 'ms-mcs-admpwd'): 'LAPS Password Retrieval',
        ('gmsa', 'msds-groupmsa'): 'gMSA Password Extraction',
    }

    # Check command against keyword patterns
    for keywords, name in descriptive_names.items():
        if any(kw in command_lower for kw in keywords):
            return name

    # Check edges for additional context
    if edges_str:
        edge_based_names = {
            'writedacl': 'ACL Permission Modification',
            'writeowner': 'Object Ownership Takeover',
            'genericall': 'Full Object Control Exploitation',
            'genericwrite': 'Object Attribute Manipulation',
            'forcechangepassword': 'Password Reset Attack',
            'dcsync': 'DCSync Replication Attack',
            'addmember': 'Group Membership Manipulation',
            'allowedtodelegate': 'Constrained Delegation Abuse',
            'allowedtoact': 'RBCD Attack Chain',
        }
        for edge_key, name in edge_based_names.items():
            if edge_key in edges_str:
                return name

    return default


def _fix_opsec_level_for_offline_tools(opsec_option: Dict) -> Dict:
    """
    Fix OPSEC levels for both risky tools (always risky) and offline tools (always safe).

    PRIORITY ORDER:
    1. Risky tools ALWAYS override - Mimikatz/Rubeus can't be made "safe" by claiming offline
    2. Offline tools (hashcat, john) are safe only if no risky tools present

    - Risky tools (mimikatz, rubeus, secretsdump, powerview, psexec): ALWAYS risky
    - Offline tools (hashcat, john, ticketer.py alone): Safe if no risky tools in command
    """
    if not opsec_option:
        return opsec_option

    command = opsec_option.get('command', '').lower()
    tool_name = opsec_option.get('tool_name', '').lower()
    combined = command + ' ' + tool_name

    # Tools that are ALWAYS risky - these OVERRIDE any "offline" claims
    # These tools run ON the target network and are signatured
    always_risky_tools = [
        'mimikatz',
        '.\\rubeus',
        'rubeus.exe',
        'rubeus ',  # Rubeus with space after
        ' rubeus',  # Rubeus with space before
        'secretsdump',
        'psexec.py',
        'wmiexec.py',
        'smbexec.py',
        'dcomexec.py',
        'powerview',
        'invoke-powerview',
        'sharphound',
        'invoke-bloodhound',
        'invoke-mimikatz',
        'invoke-kerberoast',
        'lsadump::',
        'sekurlsa::',
        'kerberos::golden',
        'kerberos::ptt',
    ]

    # Check risky tools FIRST - they take absolute priority
    is_risky_tool = any(tool in combined for tool in always_risky_tools)

    # Special case: "Rubeus" in tool name (case variations)
    if 'rubeus' in tool_name:
        is_risky_tool = True

    if is_risky_tool:
        if opsec_option.get('opsec_level') == 'safe':
            logger.debug(f"Fixing OPSEC: risky tool '{tool_name}' incorrectly marked safe")
            opsec_option['opsec_level'] = 'risky'
            explanation = opsec_option.get('explanation', '').lower()
            if 'detect' not in explanation and 'alert' not in explanation and 'edr' not in explanation:
                opsec_option['explanation'] = 'Known offensive tool - may trigger AV/EDR alerts. Use with caution.'
        return opsec_option

    # Tools that are ALWAYS safe because they run offline on attacker machine
    # Only apply if NO risky tools were found above
    offline_safe_tools = [
        'hashcat',
        'john ',
        'john the ripper',
        '-m 13100',    # hashcat mode for TGS-REP
        '-m 18200',    # hashcat mode for AS-REP
        '--format=krb5tgs',
        '--format=krb5asrep',
    ]

    # ticketer.py is safe ONLY if psexec/wmiexec not in same command
    is_ticketer_only = 'ticketer.py' in combined and 'psexec' not in combined and 'wmiexec' not in combined

    is_offline_tool = any(tool in combined for tool in offline_safe_tools) or is_ticketer_only

    if is_offline_tool and opsec_option.get('opsec_level') != 'safe':
        logger.debug(f"Fixing OPSEC: offline tool '{tool_name}' should be safe")
        opsec_option['opsec_level'] = 'safe'
        if 'offline' not in opsec_option.get('explanation', '').lower():
            opsec_option['explanation'] = 'Entirely offline activity on attacker machine. No network alerts generated.'

    return opsec_option


def _detect_tier_bleed(step: Dict) -> Dict:
    """
    Detect and fix tier bleed - when SAFE and RISKY options use the same primary tool.

    Tier bleed occurs when the LLM generates two options that are essentially the same
    command with minor variations (e.g., bloodyAD for both SAFE and RISKY).

    This function:
    1. Extracts primary tool from each option's command
    2. Compares tools between SAFE and RISKY
    3. If same tool, removes the SAFE option (keep RISKY as it's usually more reliable)
    4. Logs a warning for debugging

    Args:
        step: Step dict with opsec_options list

    Returns:
        Modified step dict with tier bleed fixed
    """
    options = step.get('opsec_options', [])
    if len(options) < 2:
        return step  # Need at least 2 options to have tier bleed

    safe_options = [o for o in options if o.get('opsec_level') == 'safe']
    risky_options = [o for o in options if o.get('opsec_level') == 'risky']

    if not safe_options or not risky_options:
        return step  # Need both types to compare

    # Extract primary tool from command
    def get_primary_tool(command: str) -> str:
        """Extract the primary tool name from a command."""
        if not command:
            return ''
        command_lower = command.lower().strip()

        # Known tool patterns (order matters - check specific first)
        tool_patterns = [
            ('bloodyad', 'bloodyAD'),
            ('impacket-', 'Impacket'),
            ('secretsdump', 'secretsdump'),
            ('psexec.py', 'psexec'),
            ('wmiexec.py', 'wmiexec'),
            ('smbexec.py', 'smbexec'),
            ('certipy', 'Certipy'),
            ('mimikatz', 'Mimikatz'),
            ('rubeus', 'Rubeus'),
            ('powerview', 'PowerView'),
            ('pywhisker', 'pywhisker'),
            ('whisker', 'Whisker'),
            ('nxc ', 'NetExec'),
            ('netexec', 'NetExec'),
            ('crackmapexec', 'CrackMapExec'),
            ('evil-winrm', 'evil-winrm'),
            ('hashcat', 'hashcat'),
            ('john ', 'john'),
            ('get-ad', 'Native-AD'),
            ('set-ad', 'Native-AD'),
            ('get-domainuser', 'PowerView'),
            ('get-domaingroup', 'PowerView'),
            ('add-domainobjectacl', 'PowerView'),
            ('set-domainobject', 'PowerView'),
            ('net user', 'net.exe'),
            ('net group', 'net.exe'),
            ('dsquery', 'dsquery'),
            ('ldapsearch', 'ldapsearch'),
        ]

        for pattern, tool_name in tool_patterns:
            if pattern in command_lower:
                return tool_name

        # Fallback: first word that looks like a tool
        first_word = command_lower.split()[0] if command_lower.split() else ''
        # Remove common prefixes
        for prefix in ['ps >', '$ ', 'mimikatz # ', '# ']:
            if first_word.startswith(prefix):
                first_word = first_word[len(prefix):]
        return first_word

    # Get tools from first option of each tier
    safe_tool = get_primary_tool(safe_options[0].get('command', ''))
    risky_tool = get_primary_tool(risky_options[0].get('command', ''))

    # Check for tier bleed (same tool AND same operation = true bleed)
    if safe_tool and risky_tool and safe_tool.lower() == risky_tool.lower():
        # Same tool — but check if they do DIFFERENT operations
        # e.g., "bloodyAD set password" vs "bloodyAD set object servicePrincipalName" is valid differentiation
        safe_cmd = safe_options[0].get('command', '').lower()
        risky_cmd = risky_options[0].get('command', '').lower()

        # Extract the operation (first 3 significant words after the tool name)
        def get_operation(cmd):
            # Remove comments and get first command line
            for line in cmd.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    words = line.split()[:5]
                    return ' '.join(words)
            return cmd[:50]

        safe_op = get_operation(safe_cmd)
        risky_op = get_operation(risky_cmd)

        # Only flag as tier bleed if the operations are very similar
        # "set password" vs "set object servicePrincipalName" = different = NOT tier bleed
        if safe_op == risky_op or (len(safe_op) > 10 and safe_op[:30] == risky_op[:30]):
            logger.warning(
                f"Tier bleed detected in step '{step.get('title', 'Unknown')}': "
                f"Both SAFE and RISKY use '{safe_tool}' for same operation. Removing SAFE option."
            )
            step['opsec_options'] = risky_options
            step['_tier_bleed_detected'] = True
        else:
            logger.debug(
                f"Same tool '{safe_tool}' but different operations — not tier bleed"
            )

    return step


def _validate_step_sequencing(steps: List[Dict]) -> List[Dict]:
    """
    Validate and fix step sequencing - high-privilege commands shouldn't be Step 1.

    Fix 4: Step Sequencing Logic
    - DCSync, secretsdump, Golden Ticket require credentials obtained in prior steps
    - If Step 1 contains high-priv commands, either:
      1. Find a valid enumeration step to promote to Step 1
      2. Remove the problematic Step 1 entirely

    Args:
        steps: List of parsed attack steps

    Returns:
        Reordered/fixed list of steps
    """
    if not steps:
        return steps

    def contains_high_priv_command(step: Dict) -> bool:
        """Check if step contains commands requiring prior credential access."""
        for option in step.get('opsec_options', []):
            command = option.get('command', '').lower()
            for high_priv in HIGH_PRIV_COMMANDS:
                if high_priv in command:
                    return True
        return False

    def is_valid_step1(step: Dict) -> bool:
        """Check if step is valid as Step 1 (enumeration, initial access)."""
        for option in step.get('opsec_options', []):
            command = option.get('command', '').lower()
            # Check for valid Step 1 commands
            for valid_cmd in VALID_STEP1_COMMANDS:
                if valid_cmd in command:
                    return True
            # Also valid: no high-priv commands at all
            has_high_priv = False
            for high_priv in HIGH_PRIV_COMMANDS:
                if high_priv in command:
                    has_high_priv = True
                    break
            if not has_high_priv:
                return True
        return False

    # Check if Step 1 has high-privilege commands
    if len(steps) > 0 and contains_high_priv_command(steps[0]):
        step1_title = steps[0].get('title', 'Step 1')
        logger.warning(
            f"Step sequencing issue: Step 1 '{step1_title}' contains high-privilege "
            f"commands that require prior credential access"
        )

        # Try to find a better Step 1 candidate
        for i, step in enumerate(steps[1:], start=1):
            if is_valid_step1(step):
                logger.info(f"Reordering: Moving step {i+1} '{step.get('title')}' to Step 1")
                # Swap steps
                steps[0], steps[i] = steps[i], steps[0]
                # Renumber
                for idx, s in enumerate(steps):
                    s['step_number'] = idx + 1
                break
        else:
            # No valid Step 1 found - mark the issue but don't remove
            # (better to have imperfect steps than none)
            steps[0]['_sequencing_warning'] = (
                'This step contains high-privilege commands that typically '
                'require credentials obtained from prior steps'
            )
            logger.warning("No valid Step 1 candidate found - keeping current order with warning")

    return steps


def _fix_hallucinated_tools(steps: List[Dict]) -> List[Dict]:
    """
    Fix hallucinated tool names in attack steps.

    Fix 5: Tool Cleanup
    - Replaces deprecated tools (crackmapexec → nxc)
    - Fixes non-existent Impacket scripts (dcsync.py → secretsdump.py)
    - Corrects case sensitivity issues (Bloodyad → bloodyAD)
    - Logs warnings for tools that can't be fixed

    Args:
        steps: List of attack steps with opsec_options

    Returns:
        Steps with corrected tool names
    """
    fixes_applied = 0

    for step in steps:
        for option in step.get('opsec_options', []):
            command = option.get('command', '')
            if not command:
                continue

            original_command = command

            # Apply all hallucinated tool fixes
            for wrong, correct in HALLUCINATED_TOOL_FIXES.items():
                if wrong.lower() in command.lower():
                    # Case-insensitive replacement
                    import re
                    command = re.sub(re.escape(wrong), correct, command, flags=re.IGNORECASE)

            # Check for completely non-existent tools and log warning
            command_lower = command.lower()
            for nonexistent in NONEXISTENT_TOOLS:
                if nonexistent in command_lower:
                    logger.warning(
                        f"Non-existent tool '{nonexistent}' found in step "
                        f"'{step.get('title', 'Unknown')}' - may need manual review"
                    )
                    step['_tool_warning'] = f"Contains potentially non-existent tool: {nonexistent}"

            # Strip hallucinated base64-encoded PowerShell commands
            # The LLM fabricates fake base64 blobs — they decode to garbage
            # and are unverifiable. Remove the -enc payload, keep the base command.
            if 'powershell' in command.lower() and '-enc' in command.lower():
                import re
                # Remove: powershell -enc <base64blob> or -encodedcommand <base64blob>
                command = re.sub(
                    r"['\"]?powershell(?:\.exe)?['\"]?\s+(?:-enc(?:odedcommand)?)\s+\S+",
                    '',
                    command,
                    flags=re.IGNORECASE
                ).strip()
                if not command:
                    # Entire command was just the encoded PS — flag for removal
                    command = original_command.split('powershell')[0].strip().rstrip("'\"")
                logger.warning("Stripped hallucinated base64-encoded PowerShell from command")

            # Update command if changed
            if command != original_command:
                option['command'] = command
                fixes_applied += 1
                logger.debug(f"Fixed hallucinated tool in command")

            # Also fix tool_name field if needed
            tool_name = option.get('tool_name', '')
            for wrong, correct in HALLUCINATED_TOOL_FIXES.items():
                if wrong.lower() in tool_name.lower():
                    import re
                    option['tool_name'] = re.sub(re.escape(wrong), correct, tool_name, flags=re.IGNORECASE)

    if fixes_applied > 0:
        logger.info(f"Fix 5: Corrected {fixes_applied} hallucinated tool references")

    return steps


def _is_cypher_query(command: str) -> bool:
    """Check if a command is actually a Cypher/Neo4j query (not a valid attack command)."""
    if not command:
        return False

    command_lower = command.lower().strip()

    # Cypher query indicators
    cypher_indicators = [
        'match ',
        'match(',
        'return ',
        'where ',
        'create ',
        'merge ',
        'optional match',
        '-[:',      # Cypher relationship syntax
        ']->()',    # Cypher node pattern
        'p=(n)',    # Common BloodHound pattern
        'shortestpath',
        'allshortestpaths',
        '.name =',  # Cypher property access
        '{name:',   # Cypher property map
    ]

    # Check for Cypher patterns
    for indicator in cypher_indicators:
        if indicator in command_lower:
            return True

    # Also check if it starts with common Cypher keywords
    if command_lower.startswith(('match', 'optional', 'return', 'with', 'unwind', 'call')):
        return True

    return False


# Patterns that indicate Neo4j/BloodHound connection code (forbidden as attack commands - user already has the graph)
_NEO4J_BLOODHOUND_CONNECTION_INDICATORS = [
    'invoke-neo4jquery', 'neo4jquery', 'bolt://', 'neo4jcred', 'neo4jconnection',
    'from bloodhound', 'import bloodhound', 'adauthentication', 'bloodhound(',
    'bloodhound.', 'bh.connect', 'bh.run', 'neo4j', 'graph database',
]


def _filter_cypher_from_command(command: str) -> str:
    """Remove Cypher queries and Neo4j/BloodHound connection code, keeping only actual attack commands."""
    if not command:
        return command

    lines = command.split('\n')
    filtered_lines = []
    skip_until_blank = False

    for line in lines:
        line_stripped = line.strip()
        line_lower = line_stripped.lower()

        # Skip blank lines after a Cypher block
        if skip_until_blank:
            if not line_stripped:
                skip_until_blank = False
            continue

        # Check if this line starts a Cypher query
        if _is_cypher_query(line_stripped):
            skip_until_blank = True
            continue

        # Skip lines that are Neo4j/BloodHound connection (user already has graph in AEGIS)
        if any(ind in line_lower for ind in _NEO4J_BLOODHOUND_CONNECTION_INDICATORS):
            continue

        # Skip comment lines that mention Cypher/BloodHound queries
        if line_stripped.startswith('#') and any(kw in line_lower for kw in [
            'cypher', 'bloodhound', 'neo4j', 'match ', 'query:', 'analyze in'
        ]):
            continue

        filtered_lines.append(line)

    result = '\n'.join(filtered_lines).strip()

    if not result or result == '#':
        return ''

    return result


def _has_executable_command(command: str) -> bool:
    """Check if a command string has at least one non-comment executable line."""
    if not command or not command.strip():
        return False
    for line in command.split('\n'):
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('//'):
            return True
    return False


def _extract_tool_name(command: str, default: str) -> str:
    """Extract tool name from command for display."""
    command_lower = command.lower()

    tools = [
        ('mimikatz', 'Mimikatz'),
        ('rubeus', 'Rubeus'),
        ('powerview', 'PowerView'),
        ('whisker', 'Whisker'),
        ('certipy', 'Certipy'),
        ('impacket', 'Impacket'),
        ('secretsdump', 'Impacket secretsdump'),
        ('psexec', 'PsExec'),
        ('get-ad', 'Native PowerShell'),
        ('set-ad', 'Native PowerShell'),
        ('get-acl', 'Native PowerShell'),
        ('invoke-command', 'PowerShell Remoting'),
        ('enter-pssession', 'PowerShell Remoting'),
        ('net ', 'net.exe'),
        ('crackmapexec', 'CrackMapExec'),
    ]

    for keyword, name in tools:
        if keyword in command_lower:
            return name

    return default


_RISK_DESC_MAX_LENGTH = 600
_RISK_DESC_OVERFLOW_MARKERS = [
    'attack chain', 'remediation', 'detection method', 'mitre att&ck',
    'powershell', 'event id', 'exploitation', '```', 'step-by-step',
    'reconnaissance', 'example attack command',
]


def _sanitize_risk_description(text: str, severity: str, domain: str) -> str:
    """Guard against R1 returning a full analysis instead of a 2-3 sentence risk description."""
    if not text:
        return f"This {severity.lower()} severity finding could allow privilege escalation in {domain}. Immediate remediation recommended."

    text_lower = text.lower()
    has_overflow = any(marker in text_lower for marker in _RISK_DESC_OVERFLOW_MARKERS)

    if has_overflow or len(text) > _RISK_DESC_MAX_LENGTH:
        _SECTION_HEADERS = [
            'technical analysis', 'attack chain', 'reconnaissance', 'example',
            'remediation', 'detection', 'powershell', 'mitre', 'event id',
            'exploitation', 'warning', 'step-by-step', 'specific tool',
            'impact assessment', '```',
        ]
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip() and not p.strip().startswith('```')]
        # Find first paragraph that isn't a section header -- prefer impact/risk language
        for p in paragraphs:
            p_lower = p.lower()
            if any(p_lower.startswith(h) for h in _SECTION_HEADERS):
                continue
            # Found a non-header paragraph
            if len(p) > _RISK_DESC_MAX_LENGTH:
                p = p[:_RISK_DESC_MAX_LENGTH].rsplit('.', 1)[0] + '.'
            return p

        # All paragraphs were section headers -- extract first sentence from the longest one
        if paragraphs:
            longest = max(paragraphs, key=len)
            sentences = longest.split('. ')
            risk_sentence = '. '.join(sentences[:2]) + ('.' if not sentences[1].endswith('.') else '') if len(sentences) > 1 else sentences[0]
            return risk_sentence[:_RISK_DESC_MAX_LENGTH]

    return text


def validate_remediation_targets(
    remediation_steps: List[Dict],
    compromisable_entities: List[str],
    tier0_config = None
) -> List[Dict]:
    """
    Validate that remediation targets compromisable entities, not T0 groups.
    Uses auto-detected T0 assets from tier0_config - NO hardcoding.

    Args:
        remediation_steps: List of remediation step dicts with 'command' field
        compromisable_entities: List of entities that should be remediation targets
        tier0_config: Optional Tier0Config with auto-detected T0 assets

    Returns:
        Same list with 'validation_warning' added to flagged steps
    """
    if not tier0_config or not getattr(tier0_config, 'enabled', False):
        return remediation_steps

    comp_upper = {e.upper() for e in compromisable_entities}

    for step in remediation_steps:
        # Skip non-dict steps (some may be strings)
        if not isinstance(step, dict):
            continue
        command = step.get('command', '')
        if not command:
            continue

        command_upper = command.upper()

        # Check each T0 asset
        for domain_config in tier0_config.domains.values():
            for asset in domain_config.assets:
                asset_name = asset.name.split('@')[0].upper()

                # Flag if command mentions T0 Group that isn't compromisable
                if (asset_name in command_upper and
                    asset.type.value == 'Group' and
                    asset_name not in comp_upper):

                    logger.warning(
                        f"Remediation may incorrectly target T0 group '{asset_name}' "
                        f"instead of compromisable entities: {compromisable_entities}"
                    )
                    step['validation_warning'] = f"May incorrectly target {asset_name} (group)"

    return remediation_steps


def generate_risk_description_rag(finding_context: Dict, rag_service, add_log=None) -> str:
    """Generate risk description. Model knows risk assessment - just provide context."""
    severity = finding_context.get('severity', 'Medium')
    edges = finding_context.get('edges', [])
    domain = finding_context.get('domain', 'the domain')
    sources = finding_context.get('sources', [])
    targets = finding_context.get('targets', [])

    t0_info = ""
    t0_targets = finding_context.get('t0_target_assets', [])
    if t0_targets:
        t0_info = f"\n⚠️ Targets Tier 0 assets: {', '.join(t0_targets)}"

    prompt = f"""Write a risk description (2-3 sentences ONLY) for a pentest report.

Severity: {severity}
Attack type: {', '.join(edges[:2])}
Domain: {domain}
Affected: {', '.join(sources[:3]) if sources else 'multiple accounts'}
Targets: {', '.join(targets[:3]) if targets else 'sensitive objects'}{t0_info}

RULES:
- ONLY 2-3 sentences about business impact
- Do NOT include technical analysis, attack chains, remediation, or code
- Do NOT use markdown formatting, headers, or bullet points
- State business impact, what attacker could achieve, urgency level"""

    # Inject web remediation intelligence if available
    web_remediation = finding_context.get('web_remediation_context', '')
    if web_remediation:
        prompt = prompt + "\n\n" + web_remediation

    try:
        # Use fast model (DeepSeek-Chat) for risk description - simple summary task
        response = rag_service.query_fast(prompt)
        result = response.get('result', '').strip()
        if result and len(result) > 30:
            return _sanitize_risk_description(result, severity, domain)
    except Exception as e:
        if add_log:
            add_log("DEBUG", f"RAG risk description failed: {e}", debug_only=True)

    return f"This {severity.lower()} severity finding could allow privilege escalation in {domain}. Immediate remediation recommended."
