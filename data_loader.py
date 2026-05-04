"""

This script loads all data sources needed for the AEGIS RAG system:

1. MITRE ATT&CK techniques (from JSON file): 
stored in 'data/mitre_attack_techniques.json, consisting of technique IDs, names, descriptions, and tactics commonly used in cyber attacks.'

2. BloodHound edge documentation (from JSON file): 
The primary active directory enumeration being used for this project is bloodhound, in order for the model to understand the various edges and relationships within BloodHound, 
we load the edge documentation from 'data/structured/bloodhound_edges.json, a lot of research was done to be able to map all the known edges to an mitre attacks and provide 
their corresponding event ids and their possible remediations, view the references_justification.md to see how it was made'.  

3. BloodHound queries (from YAML files in queries folder):
Bloodhound has a cypher language to run queries against the graph database, we load all the queries from the 'data/queries/' folder, each query has a name, description, and the cypher query itself.
All the queries are stored in individual YAML files for easy management, Here is the link to the repo where the queries were sourced from: https://github.com/SpecterOps/BloodHoundQueryLibrary/tree/main

4. PDF security documents:
Contains books and documents about well know active directory exploits, remediation steps and defensive strategies. The PDFs are stored in the 'data/pdfs/' folder.

All data is converted to LangChain Document format for RAG ingestion.

WHY WE NEED THIS DATA LOADER:

BloodHound scan results contain edge types (like "AdminTo", "WriteDacl", "DCSync") 
that are just names in the JSON output. The RAG system needs to understand what 
these edges mean, how they can be exploited, and how to fix them.

PDFs alone cannot provide this structured knowledge because:
- They don't explain every specific edge type in detail
- They don't map findings to MITRE ATT&CK techniques
- They don't provide exact PowerShell remediation commands
- They can't answer "What does AdminTo mean?" with edge-specific context

This loader combines 4 data sources so the RAG can:
1. Understand BloodHound terminology (edges, queries)
2. Map attacks to MITRE ATT&CK framework
3. Provide specific detection methods and remediation steps
4. Give detailed explanations from PDF security guides

Without this loader, the RAG would only search PDFs and give generic advice.
With it, the RAG can interpret actual BloodHound findings and provide 
actionable, edge-specific guidance.

"""


import json
import yaml
import os
from pathlib import Path
from typing import List
from langchain_core.documents import Document
from langchain_community.document_loaders import PyPDFLoader


class DataLoader:
    """

    Loads and combines all data sources for AEGIS RAG system.
    Handles MITRE ATT&CK, BloodHound edges, queries, PDFs, and GitHub training data.

    """

    def __init__(self, data_folder: str = 'data', training_data_folder: str = 'backend/training_data/processed') -> None:

        """
        This is the function for Initializing the DataLoader class.

        data_folder: Root folder containing all the data sources needed.
        training_data_folder: Folder containing extracted GitHub training data.

        """
        self.data_folder = Path(data_folder)
        self.training_data_folder = Path(training_data_folder)

        # Paths to all the various data sources
        self.structured_folder = self.data_folder / "structured"
        self.queries_folder = self.structured_folder / "queries"
        self.pdfs_folder = self.data_folder / "pdfs"

    # loading MITRE ATT&CK techniques
    def load_mitre_attack(self) -> List[Document]:
        
        """
        
        This function will be used to load MITRE ATT&CK techniques from a JSON file.
        it is a very big file with about 876448 lines, in this function we will only extract the attack techniques which are relvenat to active directory attacks.
        This reduces the training time of the model and improves the relevance of the retrieved information.
        
        it will return a List of Documents containing the MITRE ATT&CK techniques.
        
        """
        
        mitre_file = self.structured_folder / "mitre_attack_enterprise.json"
        
        # check if the file exists
        if not mitre_file.exists():
            print(f"MITRE ATT&CK file not found at {mitre_file}")
            return []

        print("Loading MITRE ATT&CK techniques...")
        
        # reading the JSON file
        with open(mitre_file, 'r', encoding='utf-8') as f:
            mitre_data = json.load(f)
        
        documents = []
        
        # this section loops through all the objects and attack techniques in the MITRE ATT&CK data
        for obj in mitre_data.get('objects', []):
            # we are only interested in attack techniques
            if obj.get('type') != 'attack-pattern':
                continue
            
            technique_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
            name = obj.get('name', 'N/A')
            description = obj.get('description', 'N/A')
            tactics = [tactic.get('phase_name', 'N/A') for tactic in obj.get('kill_chain_phases', []) if tactic.get('phase_name')]
            platforms = obj.get('x_mitre_platforms', [])
            detection = obj.get('x_mitre_detection', 'N/A')
            
            # we will only keep techniques relevant to windows/AD platforms
            if 'Windows' not in platforms and 'Active Directory' not in platforms:
                continue
            
            # creating the document content with all the relevant information
            content = f"Technique ID: {technique_id}\nMITRE ATT&CK Technique: {name}\nDescription: {description}\nTactics: {', '.join(tactics)}\nPlatforms: {', '.join(platforms)}\nDetection: {detection}".strip()
            metadata = {"source": "MITRE ATT&CK", "technique_id": technique_id, "name": name}

            documents.append(Document(page_content=content, metadata=metadata))

        return documents
            
    def load_bloodhound_edges(self) -> List[Document]:
        
        """
        
        This function will be used to load BloodHound edge documentation from a JSON file.
        it will return a List of Documents containing the BloodHound edge documentation.
        
        """
        
        # Path to the BloodHound edges JSON file
        edges_file = self.structured_folder / "bloodhound_edges.json"
        
        # check if the file exists
        if not edges_file.exists():
            print(f"BloodHound edges file not found at {edges_file}")
            return []
        
        print("Loading BloodHound edge documentation...")
        
        # Read the JSON file
        with open(edges_file, 'r', encoding='utf-8') as f:
            edges_data = json.load(f)
        
        documents = []
        
        # Loop through each edge and create a Document
        for edge_name, edge_info in edges_data.items():
            description = edge_info.get('description', 'No description')
            abuse = edge_info.get('abuse', 'No abuse info')
            opsec = edge_info.get('opsec', 'No OPSEC info')
            detection = edge_info.get('detection', 'No detection info')
            remediation = edge_info.get('remediation', 'No remediation info')
            powershell_fix = edge_info.get('powershell_remediation', 'No PowerShell commands')
            mitre_techniques = edge_info.get('mitre_mapping', [])
            
            # create the document content with all the edge information
            content = f"Edge Name: {edge_name}\nDescription: {description}\nHow to Abuse: {abuse}\nOPSEC Considerations: {opsec}\nDetection Methods: {detection}\nRemediation: {remediation}\nPowerShell Remediation: {powershell_fix}\nMITRE ATT&CK: {', '.join(mitre_techniques)}".strip()
            metadata = {"source": "BloodHound Edge Documentation", "edge_name": edge_name, 'category': 'Attack Path'}
            
            documents.append(Document(page_content=content, metadata=metadata))
        
        return documents
        
    def load_bloodhound_queries(self) -> List[Document]:
        
        """
        
        This function loads the Bloodhound queries from YAML files in the queries folder.
        It returns a List of Documents containing the BloodHound queries.
        
        """
        
        # check to see if the queries folder exists
        if not self.queries_folder.exists():
            print(f"BloodHound queries folder not found at {self.queries_folder}")
            return []
        
        print("Loading BloodHound queries...")
        documents = []
        
        # Get all the YML files in the queries folder
        yaml_files = list(self.queries_folder.glob("*.yml")) + list(self.queries_folder.glob("*.yaml"))
        
        if not yaml_files:
            print(f"No YAML files found in {self.queries_folder}")
            return []

        # Loop through each YAML file and create a Document

        for yaml_file in yaml_files:
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    query_data = yaml.safe_load(f)

                if not query_data:
                    print(f"Skipping empty YAML file: {yaml_file.name}")
                    continue

                name = query_data.get('name', 'Unnamed Query')
                category = query_data.get('category', 'General')
                description = query_data.get('description', 'No description')
                cypher_query = query_data.get('query', 'No query provided')
                platforms = query_data.get('platforms', [])
                if not isinstance(platforms, list):
                    platforms = []
                resources = query_data.get('resources', '')
                contributors = query_data.get('acknowledgements', '')

                content = f"Query Name: {name}\nCategory: {category}\nDescription: {description}\nPlatforms: {', '.join(platforms)}\nResources: {resources}\nContributors: {contributors}\nCypher Query:\n{cypher_query}".strip()
                metadata = {"source": "BloodHound Query", "query_name": name, "category": category}

                documents.append(Document(page_content=content, metadata=metadata))
            except yaml.YAMLError as e:
                print(f"Error parsing YAML file {yaml_file.name}: {e}")
                continue
            except Exception as e:
                print(f"Error loading YAML file {yaml_file.name}: {e}")
                continue

        return documents
    
    def load_pdfs(self) -> List[Document]:
        """
        
        This function loads PDF security documents from the specified folder.
        It returns a List of Documents containing the PDF contents.
        
        """
        
        # check if the PDFs folder exists
        if not self.pdfs_folder.exists():
            print(f"PDFs folder not found at {self.pdfs_folder}")
            return []
        
        print("Loading PDF security documents...")
        
        documents = []
        
        # Get all PDF files in the PDFs folder
        pdf_files = list(self.pdfs_folder.glob("**/*.pdf"))
        
        if not pdf_files:
            print(f"No PDF files found in {self.pdfs_folder}")
            return []

        # Loop through each PDF file and create Documents
        for pdf_file in pdf_files:
            try:
                # Check if file is empty
                if pdf_file.stat().st_size == 0:
                    print(f"Skipping empty PDF file: {pdf_file.name}")
                    continue

                loader = PyPDFLoader(str(pdf_file))
                pdf_docs = loader.load()

                # Add metadata to each document
                for doc in pdf_docs:
                    doc.metadata.update({"source": f"PDF Document: {pdf_file.name}"})

                documents.extend(pdf_docs)
            except Exception as e:
                print(f"Error loading PDF file {pdf_file.name}: {e}")
                continue

        return documents
    
    def load_github_training_data(self) -> List[Document]:
        """

        This function loads the extracted GitHub training data (markdown and yaml files).
        Sources include: Sigma rules, Splunk detections, tool wikis, cheatsheets, etc.
        It returns a List of Documents containing the training content.

        """

        if not self.training_data_folder.exists():
            print(f"Training data folder not found at {self.training_data_folder}")
            return []

        print("Loading GitHub training data...")
        documents = []

        # Get all markdown and yaml files
        md_files = list(self.training_data_folder.rglob("*.md"))
        yaml_files = list(self.training_data_folder.rglob("*.yaml")) + list(self.training_data_folder.rglob("*.yml"))

        print(f"  Found {len(md_files)} markdown files and {len(yaml_files)} yaml files")

        # Process markdown files
        for md_file in md_files:
            try:
                content = md_file.read_text(encoding='utf-8', errors='ignore')
                if not content.strip():
                    continue

                # Determine source category from path
                rel_path = md_file.relative_to(self.training_data_folder)
                source_folder = rel_path.parts[0] if rel_path.parts else "unknown"

                # Map folder names to readable sources
                source_map = {
                    "sigma-rules": "Sigma Detection Rules",
                    "splunk": "Splunk Security Content",
                    "mimikatz-wiki": "Mimikatz Wiki",
                    "rubeus": "Rubeus Documentation",
                    "certify-wiki": "Certify Wiki (ADCS)",
                    "netexec-wiki": "NetExec Wiki",
                    "psmapexec-wiki": "PsMapExec Wiki",
                    "internal-all-the-things": "InternalAllTheThings",
                    "adpeas": "adPEAS",
                    "crtp-cheatsheet": "CRTP Cheatsheet",
                    "crte-cheatsheet": "CRTE Cheatsheet",
                    "ad-cheatsheet-s1ck": "AD Exploitation Cheatsheet",
                    "ad-cheatsheet-integration": "AD Exploitation Cheatsheet",
                    "pentest-everything": "Pentest-Everything",
                    "exploit-notes-windows": "Exploit Notes (Windows)",
                    "win-linux-ad-pentesting": "Win-Linux-AD-Pentesting",
                    "redteaming-cheatsheet": "RedTeaming Cheatsheet",
                    "red-teaming-notes": "Red Team Certification Notes",
                }
                source_name = source_map.get(source_folder, source_folder)

                metadata = {
                    "source": f"GitHub: {source_name}",
                    "file": str(rel_path),
                    "category": "Training Data"
                }

                documents.append(Document(page_content=content, metadata=metadata))

            except Exception as e:
                print(f"  Error loading {md_file.name}: {e}")
                continue

        # Process YAML files (Sigma rules, Splunk detections)
        for yaml_file in yaml_files:
            try:
                content = yaml_file.read_text(encoding='utf-8', errors='ignore')
                if not content.strip():
                    continue

                # Parse YAML to extract structured info
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        # Format detection rules nicely
                        formatted_parts = []

                        # Common fields in detection rules
                        if 'title' in yaml_data:
                            formatted_parts.append(f"Title: {yaml_data['title']}")
                        if 'name' in yaml_data:
                            formatted_parts.append(f"Name: {yaml_data['name']}")
                        if 'description' in yaml_data:
                            formatted_parts.append(f"Description: {yaml_data['description']}")
                        if 'status' in yaml_data:
                            formatted_parts.append(f"Status: {yaml_data['status']}")
                        if 'logsource' in yaml_data:
                            formatted_parts.append(f"Log Source: {yaml_data['logsource']}")
                        if 'detection' in yaml_data:
                            formatted_parts.append(f"Detection Logic: {yaml_data['detection']}")
                        if 'tags' in yaml_data:
                            tags = yaml_data['tags']
                            if isinstance(tags, list):
                                formatted_parts.append(f"Tags: {', '.join(str(t) for t in tags)}")
                        if 'references' in yaml_data:
                            refs = yaml_data['references']
                            if isinstance(refs, list):
                                formatted_parts.append(f"References: {', '.join(str(r) for r in refs[:3])}")

                        if formatted_parts:
                            content = "\n".join(formatted_parts)

                except yaml.YAMLError:
                    pass  # Keep raw content if parsing fails

                rel_path = yaml_file.relative_to(self.training_data_folder)
                source_folder = rel_path.parts[0] if rel_path.parts else "unknown"

                # Determine source
                if "sigma" in source_folder.lower():
                    source_name = "Sigma Detection Rules"
                elif "splunk" in source_folder.lower():
                    source_name = "Splunk Security Content"
                else:
                    source_name = source_folder

                metadata = {
                    "source": f"GitHub: {source_name}",
                    "file": str(rel_path),
                    "category": "Detection Rules"
                }

                documents.append(Document(page_content=content, metadata=metadata))

            except Exception as e:
                print(f"  Error loading {yaml_file.name}: {e}")
                continue

        print(f"  Loaded {len(documents)} documents from GitHub training data")
        return documents

    def load_all_data(self) -> List[Document]:
        """

        This function loads all data sources and combines them into a single list of Documents.
        It returns a List of Documents containing all the data.

        """

        all_documents = []

        # Load each data source
        all_documents.extend(self.load_mitre_attack())
        all_documents.extend(self.load_bloodhound_edges())
        all_documents.extend(self.load_bloodhound_queries())
        all_documents.extend(self.load_pdfs())
        all_documents.extend(self.load_github_training_data())

        print(f"Total documents loaded: {len(all_documents)}")

        return all_documents

    def load_all_data_split(self) -> tuple:
        """
        Load all data sources separated into two groups for source-aware chunking:

        1. structured_docs — BloodHound edges, MITRE techniques, BloodHound queries.
           These should NOT be chunked further — each document is a self-contained
           unit (one edge, one technique, one query) that loses meaning if split.

        2. unstructured_docs — PDFs and GitHub training data (markdown, YAML).
           These should be chunked with RecursiveCharacterTextSplitter because
           they contain long-form content that needs splitting.

        Returns:
            (structured_docs, unstructured_docs)
        """
        structured_docs = []
        unstructured_docs = []

        # Structured: keep whole (each doc is a self-contained unit)
        structured_docs.extend(self.load_mitre_attack())
        structured_docs.extend(self.load_bloodhound_edges())
        structured_docs.extend(self.load_bloodhound_queries())

        # Unstructured: needs chunking
        unstructured_docs.extend(self.load_pdfs())
        unstructured_docs.extend(self.load_github_training_data())

        print(f"Structured documents (keep whole): {len(structured_docs)}")
        print(f"Unstructured documents (will be chunked): {len(unstructured_docs)}")

        return structured_docs, unstructured_docs
                
               
if __name__ == "__main__":
    data_loader = DataLoader()
    all_data = data_loader.load_all_data()
    print(f"Loaded {len(all_data)} documents for RAG ingestion.")