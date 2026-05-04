# AEGIS — Active Directory Security Analysis Platform

AEGIS is an offensive-security tool that analyses BloodHound Community Edition data to produce structured penetration-testing reports. It identifies attack paths, generates exploitation commands with OPSEC classifications, and recommends remediations — augmenting the work a human pentester would otherwise do by hand.

## What It Does

- **Attack path detection** — runs a curated library of Cypher queries against a Neo4j BloodHound CE database to surface privilege-escalation, lateral-movement, and domain-compromise paths.
- **LLM-synthesised attack chains** — for each finding, an LLM produces a multi-step exploitation chain with rationale, grounded in the underlying graph evidence (RAG over BloodHound docs and AD-attack literature).
- **Concrete commands with OPSEC tagging** — every step is rendered as a runnable command (`impacket-secretsdump`, `nxc`, `certipy`, `bloodyAD`, etc.) classified as `safe` or `risky`.
- **Remediation guidance** — per-finding mitigation steps tailored to the abused edge type.
- **Graph visualisation** — interactive React-Flow graph per finding, with node/edge colouring by attack category.
- **Local chat over the AD graph** — natural-language queries get translated to Cypher, executed locally, and explained.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Electron + React (aegis-electron/)                             │
│  ─ Local UI, Cypher execution against user's Neo4j              │
└──────────────┬──────────────────────────────────────────────────┘
               │ HTTPS
┌──────────────▼──────────────────────────────────────────────────┐
│  FastAPI backend (backend/)                                     │
│  ─ Query classification, Cypher generation                      │
│  ─ RAG: BM25 + vector retrieval over ChromaDB                   │
│  ─ LLM orchestration (DeepSeek-Chat / DeepSeek-R1)              │
└──────────────┬──────────────────────────────────────────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
┌────────────┐    ┌────────────┐
│ ChromaDB   │    │ User's     │
│ (RAG       │    │ Neo4j +    │
│ vectors)   │    │ BloodHound │
└────────────┘    └────────────┘
```

| Layer    | Tech                                                       |
|----------|------------------------------------------------------------|
| Frontend | Electron, React, Vite, TypeScript, React Flow, better-sqlite3 |
| Backend  | FastAPI, LangChain, LangChain-Chroma, OpenAI / DeepSeek SDK |
| Storage  | Neo4j 5.x (BloodHound CE), ChromaDB (RAG), local SQLite (project state) |

**Local-first.** Raw AD data — SIDs, session info, ACLs — never leaves the user's machine. Cypher executes locally via the Electron Neo4j driver. Only pre-processed finding context (entity names, edge types, counts) is sent to the LLM during report generation.

## Prerequisites

| Tool             | Version                  | Purpose                              |
|------------------|--------------------------|--------------------------------------|
| Node.js          | 20.x or later            | Electron + Vite                      |
| Python           | 3.11 or later            | FastAPI backend                      |
| Neo4j            | 5.x                      | BloodHound CE graph database         |
| BloodHound CE    | Latest                   | AD data collection / ingestion       |
| DeepSeek API key | —                        | LLM for chain generation (primary)   |
| OpenAI API key   | —                        | Embeddings for ChromaDB vector store |

A working BloodHound CE instance with AD data already ingested is required before generating reports. See the [BloodHound CE docs](https://bloodhound.specterops.io/) for collection and ingestion.

## Installation

### 1. Clone

```bash
git clone https://github.com/Dyonis-afk/capstone_project.git
cd capstone_project
```

### 2. Backend

```bash
python3 -m venv venv
source venv/bin/activate              # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create `backend/.env`:

```
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
CHROMA_PERSIST_DIRECTORY=./aegis_vector_db
AEGIS_LOG_MODE=normal
```

### 3. RAG vector store

The submission **does not include** the prebuilt ChromaDB or the training corpus — both are too large to bundle. To reproduce the vector store locally:

1. Clone each training source listed under [Resources](#resources) into `backend/training_data/raw/<source-name>/`.
2. Run the rebuild script:

```bash
python retrain_rag.py
```

The script chunks the corpus, generates OpenAI embeddings, and writes the ChromaDB to `aegis_vector_db/` (configurable via `CHROMA_PERSIST_DIRECTORY`). Expect this to take ~10–30 min depending on connection speed and corpus size.

### 4. Frontend

```bash
cd aegis-electron
npm install
```

## Running

Start in three terminals (in order).

**Terminal 1 — Neo4j / BloodHound CE.** Start your BloodHound CE stack however you normally do (docker compose, native install). AEGIS connects to whatever Neo4j endpoint you configure in **Settings** inside the Electron app.

**Terminal 2 — Backend.**

```bash
source venv/bin/activate
uvicorn backend.app:app --reload --port 8000
```

**Terminal 3 — Electron app.**

```bash
cd aegis-electron
npm run electron:dev
```

The app opens on `http://localhost:5173` and the Electron shell. On first launch, open **Settings** and configure your BloodHound CE Neo4j connection (URL, username, password). After that, click **Generate Report** to run the full attack-path scan against the loaded domain.

### Debug mode

By default the backend runs with clean, production-style logs. To enable verbose tracing and write logs to disk, start the backend with `AEGIS_LOG_MODE=debug`:

```bash
# verbose + file logging at backend/logs/aegis.log
AEGIS_LOG_MODE=debug python -m uvicorn backend.app:app --reload --port 8000
```

Tail the log file in another terminal:

```bash
tail -f backend/logs/aegis.log
```

Health check:

```bash
curl http://localhost:8000/health
```

### Building distributables

```bash
cd aegis-electron
npm run electron:dist:mac       # or :win / :linux / :all
```

## Project Structure

```
capstone_project/
├── backend/                          FastAPI server
│   ├── app.py                          ─ application entry
│   ├── routers/
│   │   ├── attack_paths/                  Per-finding RAG generation
│   │   │   ├── constants/                 Static Cypher queries, prompt templates
│   │   │   └── services/                  Report assembler, chain auditor, validators
│   │   └── chat.py                        Natural-language → Cypher endpoint
│   └── services/                        Shared services (RAG, graph extractor, etc.)
│
├── aegis-electron/                   Electron + React client
│   ├── electron/                        Main-process services (Neo4j driver, BHCE API)
│   └── src/
│       ├── components/                    UI components (graph, attack cards, chat)
│       ├── screens/                       App screens (Home, Report, Chat, Settings)
│       └── services/                      Frontend services (chat, signing)
│
├── requirements.txt                  Backend Python dependencies
├── retrain_rag.py                    Rebuild the RAG vector store
└── data_loader.py                    Helper for loading documents into the corpus
```

> The `aegis_vector_db/` (ChromaDB) and `backend/training_data/` directories are produced by `retrain_rag.py` and are **not included** in the submission. See [Resources](#resources).

## Limitations

AEGIS analyses what BloodHound CE collects. It cannot detect:

| Data type                  | Status        | Workaround                          |
|----------------------------|---------------|-------------------------------------|
| ADCS template misconfigs   | Partial (BHCE 5+ ESC1–ESC4) | Run Certipy for full coverage |
| MSSQL configurations       | Not collected | Detected by edge / naming heuristic only |
| GPO contents (GPP creds)   | Partial       | Manual review of SYSVOL              |
| LAPS passwords             | Not collected | Manual via DSInternals / BloodyAD    |
| Service-binary configs     | Not collected | Manual on compromised host           |

## Resources

AEGIS's RAG store is built from public, open-source AD-attack documentation. None of the source corpora are redistributed in the submission — clone each repository directly from the URL below into `backend/training_data/raw/` before running `retrain_rag.py`.

### RAG training corpora

| # | Source | Repository |
|---|--------|------------|
| 1 | Sigma detection rules | https://github.com/SigmaHQ/sigma |
| 2 | Splunk Security Content | https://github.com/splunk/security_content |
| 3 | Mimikatz Wiki | https://github.com/gentilkiwi/mimikatz/wiki |
| 4 | Rubeus | https://github.com/GhostPack/Rubeus |
| 5 | Certify Wiki | https://github.com/GhostPack/Certify/wiki |
| 6 | NetExec Wiki | https://github.com/Pennyw0rth/NetExec-Wiki |
| 7 | PsMapExec Wiki | https://github.com/The-Viper-One/PsMapExec/wiki |
| 8 | InternalAllTheThings | https://github.com/swisskyrepo/InternalAllTheThings |
| 9 | adPEAS | https://github.com/61106960/adPEAS |
| 10 | CRTP Cheatsheet | https://github.com/0xJs/CRTP-cheatsheet |
| 11 | AD Cheatsheet (S1ckB0y1337) | https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet |
| 12 | AD Cheatsheet (Integration-IT) | https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet |
| 13 | Pentest-Everything | https://github.com/The-Viper-One/Pentest-Everything |
| 14 | Exploit Notes | https://github.com/hdks-bug/exploit-notes |
| 15 | Win-Linux-AD-Pentesting | https://github.com/iptracej-education/Win-Linux-AD-pentesting |
| 16 | RedTeaming Cheatsheet | https://github.com/0xJs/RedTeaming_CheatSheet |
| 17 | CRTE Cheatsheet | https://github.com/0xJs/CRTE-Cheatsheet |
| 18 | Red-Teaming Notes | https://github.com/0xn1k5/Red-Teaming |

A complete extraction guide (which directories to keep, which to skip) lives in `RAG_TRAINING_DATA_SOURCES.md`.

### Authoritative references for BloodHound edges

Edge-specific guidance (descriptions, attack semantics, remediation) is grounded in:

- BloodHound CE official docs — https://bloodhound.readthedocs.io/
- BloodHound source — https://github.com/SpecterOps/BloodHound (Apache 2.0)
- MITRE ATT&CK Enterprise — https://attack.mitre.org/
- Microsoft Active Directory security docs — https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/

Per-edge citations are listed in `references_justification.md`.

## Evaluation

AEGIS was evaluated against three Hack The Box machines representing different AD attack profiles. Sample reports and the underlying BloodHound exports are in the capstone submission bundle's `data/` directory — see `data/readme.txt` there for an inventory.

### Sauna *(demo box — see `demo/` folder)*

- **Difficulty:** Easy
- **Domain:** EGOTISTICAL-BANK.LOCAL
- **Intended path:** AS-REP Roasting (`FSMITH`) → kerberoast hash → WinRM → `HSMITH` → DCSync via Exchange Windows Permissions
- **Notable detections:** AS-REP roastable users, DCSync-capable principals, WriteDacl on domain
- **Demo video** (`demo/demo_video.mp4`) walks through full Sauna exploitation using the report's commands.

### Support

- **Difficulty:** Easy
- **Domain:** SUPPORT.HTB
- **Intended path:** SMB enumeration → service account info-disclosure → LDAP creds (`LDAP`) → Resource-Based Constrained Delegation on the DC → Administrator
- **Notable detections:** RBCD-writable computer accounts, GenericAll edges to DC

### Administrator

- **Difficulty:** Medium
- **Domain:** administrator.htb
- **Intended path:** Foothold as `OLIVIA` → BloodHound enumeration reveals `EMILY` has **GenericWrite** over `ETHAN` → coerce password change on Ethan → Ethan has **GetChanges / GetChangesAll** (DCSync capability) → dump domain hashes
- **Notable detections:** GenericWrite ACL chain across users, DCSync-capable principal reachable via two-hop ACL abuse

## Capstone Submission

This codebase was developed as a capstone project. The submission bundle contains the report PDF, presentation, demo video, and this codebase (`backend/` + `aegis-electron/` only).
