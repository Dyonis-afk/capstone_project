# AEGIS Future Phases & Feature Roadmap

This document outlines planned features and enhancements for AEGIS (AI-Enhanced Guardian for Enterprise Infrastructure Security). Each phase builds upon the existing foundation to create a comprehensive Active Directory security analysis platform.

---

## Table of Contents

1. [Completed Phases (1-9)](#completed-phases-1-9)
2. [Phase 10: Natural Language to Cypher Query](#phase-10-natural-language-to-cypher-query)
3. [Phase 11: Additional Findings Export](#phase-11-additional-findings-export)
4. [Phase 12: Interactive Graph Exploration](#phase-12-interactive-graph-exploration)
5. [Phase 13: Remediation Progress Tracker](#phase-13-remediation-progress-tracker)
6. [Phase 14: Scan Comparison (Before/After)](#phase-14-scan-comparison-beforeafter)
7. [Phase 15: Attack Simulation Walkthrough](#phase-15-attack-simulation-walkthrough)
8. [Phase 16: Learning Mode / Glossary](#phase-16-learning-mode--glossary)
9. [Phase 17: Compliance Framework Mapping](#phase-17-compliance-framework-mapping)
10. [Phase 18: Ticketing System Integration](#phase-18-ticketing-system-integration)
11. [Phase 19: Risk Scoring Dashboard](#phase-19-risk-scoring-dashboard)
12. [Phase 20: AI Security Advisor (Proactive)](#phase-20-ai-security-advisor-proactive)
13. [Priority Matrix](#priority-matrix)
14. [Implementation Recommendations](#implementation-recommendations)

---

## Completed Phases (1-9)

| Phase | Feature | Status |
|-------|---------|--------|
| 1-6 | Core Infrastructure | ✅ Complete |
| 7 | Hybrid Flow Architecture | ✅ Complete |
| 8 | ChatScreen Neo4j Query Integration | ✅ Complete |
| 9 | Embedded Graph Data | ✅ Complete |

These phases established the foundation:
- Local Neo4j data import and isolation
- RAG-powered attack path analysis
- Hybrid query execution (local + backend)
- Embedded graph visualization with offline support
- Automated remediation script generation

---

## Phase 10: Natural Language to Cypher Query

### Description

Enables users to request Active Directory queries using plain English, which AEGIS then translates into Cypher queries via RAG, executes on the local Neo4j database, and returns formatted results. Instead of typing `MATCH (u:User)-[:AdminTo]->(c:Computer) WHERE c.name CONTAINS 'DC' RETURN u.name, c.name`, the user simply asks "Show me all users with admin rights to domain controllers" and AEGIS handles the translation and execution automatically.

### Problem Solved

The current implementation requires users to either know Cypher syntax or rely on pre-built suggestion chips. This creates two gaps:

1. Users who understand what they want but can't express it in Cypher
2. Questions that don't match the pre-built suggestions

Natural language querying bridges this gap by leveraging the RAG model's understanding of BloodHound schemas and Cypher syntax to translate intent into executable queries.

### User Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                      │
│  User: "Show me service accounts that have admin rights to any       │
│         domain controller"                                           │
│                                                                      │
│                              ↓                                       │
│                                                                      │
│  AEGIS (thinking):                                                   │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 🧠 Analyzing intent...                                      │     │
│  │ 📝 Generating Cypher query...                               │     │
│  │ ▶️ Executing on local Neo4j...                              │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│                              ↓                                       │
│                                                                      │
│  AEGIS Response:                                                     │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ I found 3 service accounts with admin rights to domain      │     │
│  │ controllers:                                                 │     │
│  │                                                              │     │
│  │ | Service Account        | Domain Controller    |           │     │
│  │ |------------------------|----------------------|           │     │
│  │ | SVC_BACKUP@CORP.LOCAL  | DC01.CORP.LOCAL     |           │     │
│  │ | SVC_SQL@CORP.LOCAL     | DC02.CORP.LOCAL     |           │     │
│  │ | SVC_ADMIN@CORP.LOCAL   | DC01.CORP.LOCAL     |           │     │
│  │                                                              │     │
│  │ ⚠️ This is a critical finding! Service accounts with DC     │     │
│  │ admin rights can be used for domain compromise.             │     │
│  │                                                              │     │
│  │ Query used:                                                  │     │
│  │ ```cypher                                                    │     │
│  │ MATCH (u:User)-[:AdminTo]->(c:Computer)                     │     │
│  │ WHERE u.name CONTAINS 'SVC' AND c.name CONTAINS 'DC'        │     │
│  │ RETURN u.name, c.name                                        │     │
│  │ ```                                                          │     │
│  │                                                              │     │
│  │ [📥 Add to Report]  [🔄 Refine Query]  [📋 Copy]            │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| Intent Detector | Determines if user message is a query request vs general question |
| RAG Query Generator | Prompts RAG to generate Cypher from natural language |
| Query Validator | Validates generated Cypher syntax before execution |
| Local Neo4j Executor | Runs query on local database with project filtering |
| Result Formatter | Presents results in readable format with context |
| Query Transparency | Shows the generated Cypher so users can learn |

### Example Translations

| Natural Language | Generated Cypher |
|------------------|------------------|
| "Who are the domain admins?" | `MATCH (u)-[:MemberOf*1..]->(g:Group) WHERE g.name CONTAINS 'DOMAIN ADMINS' RETURN u.name` |
| "Show me kerberoastable users" | `MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name, u.serviceprincipalnames` |
| "Which computers have unconstrained delegation?" | `MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c.name` |
| "Find paths from John to Domain Admins" | `MATCH p=shortestPath((u:User)-[*1..5]->(g:Group)) WHERE u.name CONTAINS 'JOHN' AND g.name CONTAINS 'DOMAIN ADMINS' RETURN p` |
| "List users who can DCSync" | `MATCH (n)-[:GetChanges\|GetChangesAll]->(d:Domain) RETURN n.name, labels(n)` |

### Backend Integration

```python
@router.post("/api/chat/query")
async def natural_language_query(request: NLQueryRequest):
    """
    1. Detect if this is a query request
    2. Use RAG to generate Cypher
    3. Validate the query
    4. Execute on Neo4j (local or return for frontend execution)
    5. Format and return results with explanation
    """
    
    # Step 1: RAG generates Cypher from natural language
    cypher_prompt = f"""
    Convert this natural language request into a Cypher query for BloodHound data:
    
    User request: {request.message}
    
    Available node types: User, Group, Computer, Domain, GPO, OU
    Available edges: MemberOf, AdminTo, HasSession, GenericAll, WriteDacl, 
                     Owns, ForceChangePassword, GetChanges, GetChangesAll, etc.
    
    Return ONLY the Cypher query, nothing else.
    """
    
    cypher_query = rag_service.query(cypher_prompt)
    
    # Step 2: Validate syntax
    # Step 3: Execute or return for frontend execution
    # Step 4: RAG explains results
```

### User Benefit

Democratizes AD security analysis by removing the Cypher syntax barrier entirely. Junior analysts can investigate complex attack paths using the same natural language they'd use to describe the problem to a colleague. The transparency of showing the generated query also serves as an educational tool, helping users learn Cypher over time.

### Integration with Other Phases

| Phase | Integration |
|-------|-------------|
| Phase 8 | Uses local Neo4j execution infrastructure |
| Phase 11 | Results can be added to report as Additional Findings |
| Phase 12 | Graph clicks could trigger natural language explanations |

---

## Phase 11: Additional Findings Export

### Description

Enables users to capture discoveries made during chat-based query exploration and permanently add them to the security report. When a user runs a Cypher query in the chat and finds something significant, they can click "Add to Report" to create an Additional Finding entry with a custom title, risk level, and description. These user-added findings are stored alongside the auto-generated attack paths in SQLite, creating a living document that grows as the user investigates their Active Directory environment.

### Problem Solved

Currently, insights discovered through ad-hoc chat queries are lost when the user scrolls past them or closes the application. Security analysts often discover important misconfigurations beyond the initial 6 auto-generated attack paths, but have no way to formally document these within AEGIS. This feature bridges the gap between exploratory analysis and formal reporting.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Chat Message                                                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  You: MATCH (u:User)-[:AdminTo]->(c:Computer)                       │
│       WHERE c.name CONTAINS 'DC' RETURN u.name, c.name              │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │ 🏠 Local Query Results                                      │     │
│  │                                                             │     │
│  │ Found 3 results:                                            │     │
│  │ ┌──────────────────────────────────────────────────────┐   │     │
│  │ │ { "u.name": "SVC_BACKUP@CORP.LOCAL",                 │   │     │
│  │ │   "c.name": "DC01.CORP.LOCAL" }                      │   │     │
│  │ │ ...                                                   │   │     │
│  │ └──────────────────────────────────────────────────────┘   │     │
│  │                                                             │     │
│  │ [📥 Add to Report]  [📊 Visualize]  [📋 Copy]              │     │
│  │        ↑                                                    │     │
│  │    NEW BUTTON                                               │     │
│  └────────────────────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Add Finding Modal

```
┌─────────────────────────────────────────┐
│  Add Finding to Report                   │
├─────────────────────────────────────────┤
│                                          │
│  Title: [Users with DC Admin Access   ]  │
│                                          │
│  Risk Level: [High ▼]                    │
│                                          │
│  Description:                            │
│  [Service accounts with local admin    ] │
│  [rights to domain controllers pose... ] │
│                                          │
│  [Cancel]  [Add to Report]               │
│                                          │
└─────────────────────────────────────────┘
```

### Updated Report View

```
┌─────────────────────────────────────────────────────────────────────┐
│  Security Report                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  📋 Executive Summary                                                │
│  ...                                                                 │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  🔴 Critical Attack Paths (Auto-Generated)                          │
│  ├─ #1 Shortest Paths to Domain Admins                              │
│  ├─ #2 DCSync Attack Paths                                          │
│  └─ ...                                                              │
│                                                                      │
│  ─────────────────────────────────────────────────────────────────  │
│                                                                      │
│  📌 Additional Findings (User-Added)              ← NEW SECTION     │
│  ├─ Users with DC Admin Access (High)                               │
│  │   Added: Jan 3, 2026 at 2:45 PM                                  │
│  │   Query: MATCH (u:User)-[:AdminTo]->(c:Computer)...              │
│  │   Found: 3 results                                                │
│  │   [View Details] [Remove]                                         │
│  │                                                                   │
│  └─ Nested Group Memberships (Medium)                               │
│      Added: Jan 3, 2026 at 3:12 PM                                  │
│      ...                                                             │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| "Add to Report" Button | Appears below query results in chat messages |
| AddFindingModal | Form dialog for title, risk level, description input |
| AdditionalFindingsSection | New report section displaying user-added findings |
| Database Schema Update | Extend report structure to include `additional_findings[]` array |
| Export Integration | Include additional findings in PDF/Markdown exports |

### Data Structure

```typescript
interface Report {
    // Existing fields
    critical_attack_paths: AttackPath[];
    executive_summary: string;
    recommendations: Recommendation[];
    graph: GraphData;
    
    // NEW: User-added findings from chat queries
    additional_findings: AdditionalFinding[];
}

interface AdditionalFinding {
    id: string;
    title: string;
    description: string;
    risk_level: 'Critical' | 'High' | 'Medium' | 'Low';
    cypher_query: string;
    results: any[];
    result_count: number;
    added_at: string;
    added_by: 'user';
}
```

### User Benefit

Transforms AEGIS from a static report generator into a dynamic investigation tool where every discovery can be formally documented, creating a comprehensive audit trail of the security assessment process.

---

## Phase 12: Interactive Graph Exploration

### Description

Transforms the attack path graph from a passive visualization into an interactive exploration tool. When users click on any node (User, Group, Computer, Domain) or edge (MemberOf, AdminTo, etc.), a context menu appears with relevant pre-built queries specific to that entity type. Selecting an action automatically executes the corresponding Cypher query against the local Neo4j database and displays results in a side panel or chat. This enables point-and-click security investigation without requiring Cypher knowledge.

### Problem Solved

Users can see attack paths visualized but cannot easily explore beyond what's shown. To investigate a suspicious node, they must manually write Cypher queries, which requires syntax knowledge and is error-prone. This creates a barrier for junior security analysts who understand the concepts but not the query language. Interactive graphs remove this barrier entirely.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attack Path Graph                                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│      [SVC_BACKUP]                                                    │
│           │                                                          │
│           │ AdminTo                                                  │
│           ▼                                                          │
│       [DC01] ◄─── User clicks this node                             │
│           │                                                          │
│           │                                                          │
│           ▼                                                          │
│   ┌─────────────────────────────────────────┐                       │
│   │  DC01.CORP.LOCAL                        │                       │
│   │  Type: Computer                         │                       │
│   │  ──────────────────────────────────     │                       │
│   │  Quick Actions:                         │                       │
│   │                                         │                       │
│   │  [👥 Who has admin here?]               │                       │
│   │  [🔗 What can this reach?]              │                       │
│   │  [📊 Show all sessions]                 │                       │
│   │  [🔍 Full node details]                 │                       │
│   │                                         │                       │
│   └─────────────────────────────────────────┘                       │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Click Actions by Node Type

#### User Node
```
┌─────────────────────────────────────┐
│  JOHN.DOE@CORP.LOCAL                │
│  Type: User                         │
│  ─────────────────────────────────  │
│  Quick Actions:                     │
│                                     │
│  [👥 Group memberships]             │  → MATCH (u:User {name:'...'})-[:MemberOf*1..3]->(g:Group) RETURN g
│  [💻 Admin on which computers?]    │  → MATCH (u:User {name:'...'})-[:AdminTo]->(c:Computer) RETURN c
│  [🎯 Paths to Domain Admin]        │  → MATCH p=shortestPath((u:User {name:'...'})-[*1..5]->(g:Group {name:'DOMAIN ADMINS@...'})) RETURN p
│  [🔑 Has SPN? (Kerberoastable)]    │  → MATCH (u:User {name:'...'}) RETURN u.hasspn, u.serviceprincipalnames
│  [📋 All properties]               │  → MATCH (u:User {name:'...'}) RETURN u
│                                     │
└─────────────────────────────────────┘
```

#### Computer Node
```
┌─────────────────────────────────────┐
│  DC01.CORP.LOCAL                    │
│  Type: Computer                     │
│  ─────────────────────────────────  │
│  Quick Actions:                     │
│                                     │
│  [👥 Local admins]                  │  → MATCH (n)-[:AdminTo]->(c:Computer {name:'...'}) RETURN n
│  [🔗 Outbound access]              │  → MATCH (c:Computer {name:'...'})-[r]->(target) RETURN type(r), target
│  [👤 Active sessions]              │  → MATCH (c:Computer {name:'...'})<-[:HasSession]-(u:User) RETURN u
│  [⚠️ Unconstrained delegation?]    │  → MATCH (c:Computer {name:'...'}) RETURN c.unconstraineddelegation
│  [📋 All properties]               │  → MATCH (c:Computer {name:'...'}) RETURN c
│                                     │
└─────────────────────────────────────┘
```

#### Group Node
```
┌─────────────────────────────────────┐
│  DOMAIN ADMINS@CORP.LOCAL           │
│  Type: Group                        │
│  ─────────────────────────────────  │
│  Quick Actions:                     │
│                                     │
│  [👥 Direct members]                │  → MATCH (n)-[:MemberOf]->(g:Group {name:'...'}) RETURN n
│  [👥 All members (nested)]          │  → MATCH (n)-[:MemberOf*1..5]->(g:Group {name:'...'}) RETURN n
│  [🎯 Who can reach this?]          │  → MATCH p=shortestPath((n)-[*1..5]->(g:Group {name:'...'})) WHERE n<>g RETURN p
│  [📋 All properties]               │  → MATCH (g:Group {name:'...'}) RETURN g
│                                     │
└─────────────────────────────────────┘
```

### Click Actions on Edges

```
User clicks on edge: [SVC_BACKUP] --AdminTo--> [DC01]

┌─────────────────────────────────────────┐
│  Relationship: AdminTo                   │
│  From: SVC_BACKUP@CORP.LOCAL            │
│  To: DC01.CORP.LOCAL                    │
│  ─────────────────────────────────────  │
│                                          │
│  [📖 What is AdminTo?]                  │  → Show RAG explanation
│  [🔧 How to remediate?]                 │  → Show remediation steps
│  [🔍 Others with same access?]          │  → MATCH (n)-[:AdminTo]->(c:Computer {name:'DC01...'}) RETURN n
│  [⚡ Exploitation steps]                │  → Show attack techniques
│                                          │
└─────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| NodeContextMenu | Popup menu on node click |
| EdgeContextMenu | Popup menu on edge click |
| QueryTemplates | Pre-built queries per node/edge type |
| QueryExecutor | Run query on local Neo4j |
| ResultsPanel | Display query results |
| RAG Integration | Explain edges and suggest remediations |

### UI Integration Options

#### Option A: Side Panel
```
┌────────────────────────────────────┬─────────────────────────┐
│                                    │  Node Details           │
│         GRAPH VIEW                 │  ─────────────────────  │
│                                    │  SVC_BACKUP@CORP.LOCAL  │
│    [User1] ──► [Group] ──► [DC]   │  Type: User             │
│                   ▲                │                         │
│                   │                │  Properties:            │
│              [User2]               │  • enabled: true        │
│                                    │  • hasspn: true         │
│                                    │                         │
│                                    │  Query Results:         │
│                                    │  ┌───────────────────┐  │
│                                    │  │ 5 group members   │  │
│                                    │  │ ...               │  │
│                                    │  └───────────────────┘  │
│                                    │                         │
└────────────────────────────────────┴─────────────────────────┘
```

#### Option B: Results in Chat
```
Clicking node sends query to chat automatically:

┌─────────────────────────────────────────────────────────────┐
│  Chat                                                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  🤖 AEGIS: You clicked on SVC_BACKUP@CORP.LOCAL             │
│                                                              │
│  Here are the group memberships:                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ • DOMAIN ADMINS@CORP.LOCAL                          │    │
│  │ • BACKUP OPERATORS@CORP.LOCAL                       │    │
│  │ • IT ADMINS@CORP.LOCAL                              │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ⚠️ This service account has Domain Admin membership!       │
│                                                              │
│  [🔍 Explore further]  [📥 Add to Report]                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### User Benefit

Enables intuitive "click to investigate" workflows where analysts can follow their curiosity through the graph without writing queries. Dramatically lowers the skill barrier for AD security analysis while accelerating investigation speed for experienced analysts.

---

## Phase 13: Remediation Progress Tracker

### Description

Track the status of each finding (Open → In Progress → Resolved → Verified). Analysts can mark findings as remediated, add notes, and assign owners. When a new scan is imported, AEGIS automatically compares against previous findings to verify fixes.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Remediation Tracker                                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Overall Progress: ████████░░░░░░░░ 47% (8/17 findings resolved)    │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │ Finding                      │ Status      │ Owner    │ Due    │ │
│  ├────────────────────────────────────────────────────────────────┤ │
│  │ 🔴 DCSync Rights (3 users)   │ 🟡 In Progress │ John   │ Jan 10 │ │
│  │ 🔴 Paths to DA (12 paths)    │ 🔴 Open        │ -      │ -      │ │
│  │ 🟠 Kerberoastable (5 users)  │ ✅ Resolved    │ Sarah  │ Done   │ │
│  │ 🟠 Unconstrained Deleg (2)   │ ✅ Verified    │ Mike   │ Done   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  [Export Status Report]  [Send Reminder Emails]                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| Status Workflow | Open → In Progress → Resolved → Verified |
| Owner Assignment | Assign team members to findings |
| Due Dates | Set and track remediation deadlines |
| Notes & Comments | Add context and updates to findings |
| Progress Dashboard | Visual overview of remediation status |
| Auto-Verification | Compare new scans to verify fixes |

### Data Structure

```typescript
interface RemediationTracking {
    finding_id: string;
    status: 'open' | 'in_progress' | 'resolved' | 'verified';
    owner: string | null;
    due_date: string | null;
    notes: RemediationNote[];
    created_at: string;
    updated_at: string;
    resolved_at: string | null;
    verified_at: string | null;
}

interface RemediationNote {
    id: string;
    author: string;
    content: string;
    created_at: string;
}
```

### User Benefit

Transforms AEGIS from assessment tool to continuous security management platform. Enables teams to track progress, assign accountability, and demonstrate improvement over time.

---

## Phase 14: Scan Comparison (Before/After)

### Description

Import a new BloodHound scan and compare it against a previous baseline. AEGIS highlights what's improved, what's worse, and what's new. Perfect for demonstrating remediation progress to management.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Scan Comparison: Dec 2025 vs Jan 2026                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Summary:                                                            │
│  ✅ 5 findings RESOLVED                                              │
│  🔴 2 findings NEW                                                   │
│  ⚪ 10 findings UNCHANGED                                            │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ ✅ RESOLVED                                                  │    │
│  │ • Kerberoastable users: 5 → 0                               │    │
│  │ • AS-REP Roastable: 3 → 0                                   │    │
│  │ • Unconstrained Delegation: 2 → 0                           │    │
│  ├─────────────────────────────────────────────────────────────┤    │
│  │ 🔴 NEW FINDINGS                                              │    │
│  │ • New path to DA via IT-ADMIN group                         │    │
│  │ • SVC_NEW account has DCSync rights                         │    │
│  ├─────────────────────────────────────────────────────────────┤    │
│  │ 📊 METRICS                                                   │    │
│  │ • Risk Score: 78 → 52 (↓ 33%)                               │    │
│  │ • Paths to DA: 15 → 8 (↓ 47%)                               │    │
│  │ • Privileged Users: 45 → 38 (↓ 16%)                         │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  [Generate Progress Report]  [View Side-by-Side]                     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| Scan Storage | Store multiple scans per environment |
| Diff Engine | Compare findings between scans |
| Trend Tracking | Track metrics over time |
| Regression Detection | Alert on new/worsened findings |
| Progress Report | Generate management-friendly reports |

### User Benefit

Proves ROI of security efforts and catches regressions. Essential for demonstrating value to management and maintaining security posture over time.

---

## Phase 15: Attack Simulation Walkthrough

### Description

Animated step-by-step visualization showing how an attacker would exploit a discovered attack path. Each step shows the command, what happens, and what the attacker gains. Helps junior analysts understand *why* a path is dangerous.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Attack Simulation: Path to Domain Admin                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Step 2 of 5                                              [▶ Play]  │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                                                              │    │
│  │    [ATTACKER] ──► [SVC_BACKUP] ──► [???] ──► [???] ──► [DA] │    │
│  │        ✓             ⬤                                      │    │
│  │    Compromised    Current                                    │    │
│  │                                                              │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  📍 Current Step: Kerberoast SVC_BACKUP                             │
│                                                                      │
│  What's happening:                                                   │
│  The attacker requests a service ticket for SVC_BACKUP's SPN.       │
│  This ticket is encrypted with the service account's password       │
│  hash, which can be cracked offline.                                │
│                                                                      │
│  Command:                                                            │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ GetUserSPNs.py corp.local/john:password -request            │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Attacker gains: Service account credentials                         │
│                                                                      │
│  [◀ Previous]  [Next ▶]  [Skip to End]                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| Step Breakdown | Decompose attack path into discrete steps |
| Animation Engine | Animate progression through graph |
| Command Database | Real attack commands for each technique |
| Impact Explanation | What attacker gains at each step |
| MITRE Mapping | Link to ATT&CK techniques |

### User Benefit

Educational tool that helps analysts understand attack chains, not just see them. Massive "wow factor" for demos and presentations.

---

## Phase 16: Learning Mode / Glossary

### Description

Integrated knowledge base explaining AD security concepts. Clicking on any term (Kerberoasting, DCSync, WriteDacl, etc.) shows a popup with explanation, real-world examples, and links to learn more. RAG-powered contextual explanations.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  📖 What is "DCSync"?                                        [✕]   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  DCSync is an attack technique that abuses domain controller        │
│  replication permissions to extract password hashes from AD.        │
│                                                                      │
│  ⚠️ Risk Level: CRITICAL                                            │
│                                                                      │
│  Required Permissions:                                               │
│  • DS-Replication-Get-Changes                                        │
│  • DS-Replication-Get-Changes-All                                    │
│                                                                      │
│  Attack Impact:                                                      │
│  Attacker can extract ANY user's password hash, including           │
│  krbtgt (enabling Golden Ticket attacks).                           │
│                                                                      │
│  Common Tools:                                                       │
│  • Mimikatz: lsadump::dcsync                                        │
│  • Impacket: secretsdump.py                                         │
│                                                                      │
│  MITRE ATT&CK: T1003.006                                            │
│                                                                      │
│  [View Remediation Steps]  [See in Your Environment]                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Description |
|-----------|-------------|
| Glossary Database | Definitions for AD security terms |
| Contextual Tooltips | Hover/click to see explanations |
| RAG Integration | Dynamic explanations based on context |
| MITRE Mapping | Link terms to ATT&CK framework |
| Learning Paths | Suggested reading for skill development |

### User Benefit

Built-in training that levels up junior analysts while they work. Reduces onboarding time and improves team knowledge.

---

## Phase 17: Compliance Framework Mapping

### Description

Map discovered findings to compliance frameworks (NIST, CIS, MITRE ATT&CK, ISO 27001). Generate compliance-ready reports showing which controls are failing and why.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Compliance Mapping                                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Framework: [CIS Controls v8 ▼]                                      │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Control                        │ Status │ Findings         │    │
│  ├─────────────────────────────────────────────────────────────┤    │
│  │ 5.1 Establish Secure Config    │ 🔴 Fail │ 3 issues        │    │
│  │ 5.2 Admin Privilege Management │ 🔴 Fail │ 12 paths to DA  │    │
│  │ 5.3 Service Account Security   │ 🟡 Warn │ 5 kerberoastable│    │
│  │ 5.4 Privileged Access Mgmt     │ 🔴 Fail │ 8 issues        │    │
│  │ 6.1 Audit Log Management       │ ✅ Pass │ -               │    │
│  │ 6.2 Centralized Log Collection │ ✅ Pass │ -               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  Compliance Score: 62%                                               │
│                                                                      │
│  [Generate Compliance Report]  [Export for Auditors]                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Supported Frameworks

| Framework | Description |
|-----------|-------------|
| CIS Controls v8 | Center for Internet Security benchmarks |
| NIST 800-53 | Federal security controls |
| MITRE ATT&CK | Adversary tactics and techniques |
| ISO 27001 | International security standard |
| SOC 2 | Service organization controls |

### User Benefit

Bridges security findings to compliance requirements for audits. Essential for regulated industries and enterprise adoption.

---

## Phase 18: Ticketing System Integration

### Description

One-click creation of tickets in Jira, ServiceNow, or other ITSM platforms. Pre-populates ticket with finding details, remediation steps, and priority.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Create Jira Ticket                                          [✕]   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Project:     [SEC - Security Team     ▼]                           │
│  Issue Type:  [Security Vulnerability  ▼]                           │
│  Priority:    [Critical                ▼]                           │
│                                                                      │
│  Summary:                                                            │
│  [DCSync Rights Detected - 3 Principals                         ]   │
│                                                                      │
│  Description:                                                        │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ ## Finding                                                   │    │
│  │ 3 principals have DCSync rights on CORP.LOCAL domain.       │    │
│  │                                                              │    │
│  │ ## Affected Entities                                         │    │
│  │ - SVC_BACKUP@CORP.LOCAL                                     │    │
│  │ - IT-ADMINS@CORP.LOCAL                                      │    │
│  │ - JOHN.DOE@CORP.LOCAL                                       │    │
│  │                                                              │    │
│  │ ## Remediation Steps                                         │    │
│  │ 1. Review and remove unnecessary replication rights         │    │
│  │ 2. [See attached PowerShell script]                         │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ☑ Attach remediation script                                        │
│  ☑ Link to AEGIS report                                             │
│                                                                      │
│  [Cancel]  [Create Ticket]                                           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Supported Integrations

| Platform | Integration Type |
|----------|------------------|
| Jira | REST API |
| ServiceNow | REST API |
| Azure DevOps | REST API |
| GitHub Issues | REST API |
| Email | SMTP |

### User Benefit

Integrates security findings into existing IT workflows. Reduces friction between security assessment and remediation action.

---

## Phase 19: Risk Scoring Dashboard

### Description

Overall security posture score calculated from all findings, weighted by severity and exploitability. Trend chart showing score over time. Gamification element that motivates improvement.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  Security Posture Dashboard                                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────────┐   Risk Score Trend (90 days)                  │
│  │                  │   ┌────────────────────────────────────────┐  │
│  │       52         │   │    78                                  │  │
│  │      ━━━━        │   │     ╲                                  │  │
│  │     /    \       │   │      ╲___                              │  │
│  │    Risk Score    │   │          ╲___52                        │  │
│  │                  │   │              ╲___                      │  │
│  │   ⬆ 26 pts       │   │                  Target: 30            │  │
│  │   from last scan │   └────────────────────────────────────────┘  │
│  └──────────────────┘                                               │
│                                                                      │
│  Risk Breakdown:                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ Privilege Escalation  ████████████████░░░░  35 pts          │    │
│  │ Credential Exposure   ████████░░░░░░░░░░░░  10 pts          │    │
│  │ Lateral Movement      ███████░░░░░░░░░░░░░   7 pts          │    │
│  │ Persistence Risks     ░░░░░░░░░░░░░░░░░░░░   0 pts          │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  🏆 Achievement Unlocked: "Clean Sweep" - Removed all Kerberoast!   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Scoring Algorithm

```
Risk Score = Σ (Finding Weight × Severity × Exploitability)

Where:
- Finding Weight: Based on finding type (DCSync=10, Kerberoast=7, etc.)
- Severity: Critical=4, High=3, Medium=2, Low=1
- Exploitability: Easy=3, Medium=2, Hard=1
```

### Key Components

| Component | Description |
|-----------|-------------|
| Score Calculator | Weighted risk scoring algorithm |
| Trend Tracking | Historical score over time |
| Category Breakdown | Score by risk category |
| Achievements | Gamification for improvements |
| Executive Reports | High-level posture summaries |

### User Benefit

Executive-friendly metrics and motivation for security teams. Makes security progress visible and measurable.

---

## Phase 20: AI Security Advisor (Proactive)

### Description

RAG-powered proactive recommendations that analyze your environment and suggest security improvements you haven't asked about. Like having a senior security consultant reviewing your AD.

### User Interface

```
┌─────────────────────────────────────────────────────────────────────┐
│  🤖 AI Security Advisor                                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Based on my analysis of your environment, here are my top          │
│  recommendations:                                                    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ 💡 Recommendation #1                              Priority: 1 │    │
│  │                                                              │    │
│  │ I noticed SVC_BACKUP has both DCSync rights AND is          │    │
│  │ Kerberoastable. This is an extremely dangerous combination: │    │
│  │ an attacker could Kerberoast the account, crack the         │    │
│  │ password offline, then use DCSync to extract all domain     │    │
│  │ credentials.                                                 │    │
│  │                                                              │    │
│  │ [View Attack Path]  [Generate Fix]  [Dismiss]               │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │ 💡 Recommendation #2                              Priority: 2 │    │
│  │                                                              │    │
│  │ You have 12 users in Domain Admins but only 3 appear to be  │    │
│  │ active IT staff. Consider reviewing:                        │    │
│  │ • SERVICE_ACCT_OLD (last logon: 2 years ago)               │    │
│  │ • TEMP_ADMIN (last logon: 6 months ago)                    │    │
│  │ ...                                                          │    │
│  │                                                              │    │
│  │ [Review Users]  [Generate Cleanup Script]  [Dismiss]        │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Proactive Analysis Types

| Analysis | Description |
|----------|-------------|
| Toxic Combinations | Findings that are dangerous together |
| Stale Accounts | Privileged accounts with old activity |
| Attack Path Chains | Multi-step attack scenarios |
| Configuration Drift | Changes from security baseline |
| Industry Comparisons | How you compare to similar orgs |

### User Benefit

Proactive security insights that go beyond reactive reporting. Surfaces risks that manual analysis might miss.

---

## Priority Matrix

| Phase | Feature | Effort | Impact | Wow Factor |
|-------|---------|--------|--------|------------|
| **10** | Natural Language Queries | Medium | High | ⭐⭐⭐ |
| **11** | Additional Findings Export | Medium | Medium | ⭐⭐ |
| **12** | Interactive Graph | High | High | ⭐⭐⭐⭐ |
| **13** | Remediation Tracker | Medium | High | ⭐⭐⭐ |
| **14** | Scan Comparison | Medium | High | ⭐⭐⭐⭐ |
| **15** | Attack Simulation | High | Medium | ⭐⭐⭐⭐⭐ |
| **16** | Learning Mode | Low | Medium | ⭐⭐ |
| **17** | Compliance Mapping | Medium | High | ⭐⭐⭐ |
| **18** | Ticketing Integration | Medium | Medium | ⭐⭐ |
| **19** | Risk Dashboard | Medium | High | ⭐⭐⭐ |
| **20** | AI Security Advisor | High | High | ⭐⭐⭐⭐⭐ |

---

## Implementation Recommendations

### Immediate Priority (Post-Capstone)

| Rank | Phase | Reason |
|------|-------|--------|
| 🥇 | **Phase 10** | Natural language makes AEGIS accessible to all skill levels |
| 🥈 | **Phase 11** | Enables users to capture discoveries |
| 🥉 | **Phase 12** | Interactive graphs are intuitive and impressive |

### Short-Term (1-3 months)

| Phase | Reason |
|-------|--------|
| **Phase 14** | Scan comparison proves ongoing value |
| **Phase 13** | Remediation tracking essential for enterprise |
| **Phase 19** | Risk dashboard appeals to executives |

### Long-Term (3-6 months)

| Phase | Reason |
|-------|--------|
| **Phase 15** | Attack simulation is unique differentiator |
| **Phase 17** | Compliance mapping for enterprise sales |
| **Phase 20** | AI advisor positions AEGIS as premium tool |

### Nice-to-Have (When Resources Allow)

| Phase | Reason |
|-------|--------|
| **Phase 16** | Learning mode aids adoption |
| **Phase 18** | Ticketing integration for workflow |

---

## Dependencies Between Phases

```
Phase 8 (Local Neo4j) ─────────────────────────────────────────────────┐
         │                                                              │
         ▼                                                              │
Phase 10 (NL Queries) ──► Phase 11 (Add to Report)                     │
         │                        │                                     │
         │                        ▼                                     │
         │               Phase 13 (Remediation Tracker)                │
         │                        │                                     │
         ▼                        ▼                                     │
Phase 12 (Interactive Graph) ◄── Phase 14 (Scan Comparison)           │
         │                                                              │
         ▼                                                              │
Phase 15 (Attack Simulation)                                           │
         │                                                              │
         ▼                                                              │
Phase 20 (AI Advisor) ◄────────────────────────────────────────────────┘
```

---

## Conclusion

These phases transform AEGIS from a security assessment tool into a comprehensive Active Directory security platform. The roadmap balances user experience improvements (Phases 10-12), operational features (Phases 13-14), educational capabilities (Phases 15-16), enterprise requirements (Phases 17-19), and cutting-edge AI features (Phase 20).

Each phase builds on previous work, creating a cohesive product that serves security analysts at all skill levels while providing executive-level visibility and compliance support.

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Author: AEGIS Development Team*