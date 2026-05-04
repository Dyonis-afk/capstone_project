"""Loads the persisted ChromaDB vector store and exposes RAG query helpers."""

import os
import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from re import search
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_chroma import Chroma
from langchain_core.prompts import PromptTemplate, ChatPromptTemplate, SystemMessagePromptTemplate, HumanMessagePromptTemplate
from langchain_core.runnables import RunnablePassthrough
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv

# Load .env from project root
env_path = Path(__file__).parent.parent.parent / ".env"
load_dotenv(env_path)

# Set up logger for this module
logger = logging.getLogger(__name__)

class RAGService:

    def __init__(self) -> None:
        # Use environment variable or default to local path
        env_db_path = os.getenv("CHROMA_PERSIST_DIRECTORY")
        if env_db_path:
            self.vector_db_path = Path(env_db_path)
        else:
            self.vector_db_path = Path(__file__).parent.parent.parent / "aegis_vector_db"

        self.collection_name = "aegis_docs"

        # Create directory if it doesn't exist (for production)
        if not os.path.exists(self.vector_db_path):
            logger.warning(f"Vector database not found at {self.vector_db_path}, creating empty database...")
            os.makedirs(self.vector_db_path, exist_ok=True)
        
        logger.info("Loading vector database...")
        
        try:
            # Initialize embeddings and vector store
            self.embeddings = OpenAIEmbeddings(
                model="text-embedding-3-small",
                openai_api_key=os.getenv("OPENAI_API_KEY")
            )
            
            # load the vector database
            self.vectordb = Chroma(
                collection_name=self.collection_name,
                embedding_function=self.embeddings,
                persist_directory=str(self.vector_db_path)
            )
            
            logger.info("Vector database loaded successfully.")
        except Exception as e:
            error_msg = f"Error initializing RAGService: {str(e)}"
            logger.error(error_msg, exc_info=True)
            # Re-raise to let the caller know initialization failed
            raise RuntimeError(error_msg) from e
        
        # Import static rules that are universal across all findings.
        # These go in the system message where DeepSeek caches them.
        from routers.attack_paths.constants.dynamic_prompts import STATIC_SYSTEM_RULES

        # Create chat prompt template with separate system/user messages.
        # DeepSeek automatically caches the system message prefix across requests,
        # so identical system content is processed once and reused.
        # The system message contains:
        #   - Persona (~700 tokens)
        #   - Output format rules (~900 tokens)
        #   - OPSEC classification rules (~800 tokens)
        #   - Exclusion rules (~1,800 tokens)
        #   Total: ~4,200 tokens (above DeepSeek's 1,024 caching threshold)
        self.prompt = ChatPromptTemplate.from_messages([
            SystemMessagePromptTemplate.from_template(
                """You are AEGIS, an elite offensive security expert, senior penetration tester, and Active Directory red team specialist with deep expertise in BloodHound analysis, adversary tradecraft, and enterprise security assessment.

Your knowledge includes:
- Advanced Active Directory attack techniques and privilege escalation paths
- BloodHound/SharpHound data analysis and attack path identification
- Kerberos attacks (Kerberoasting, AS-REP Roasting, delegation abuse, Golden/Silver tickets)
- ACL abuse vectors (GenericAll, WriteDacl, WriteOwner, GenericWrite, ForceChangePassword)
- ADCS (Active Directory Certificate Services) exploitation (ESC1-ESC13)
- Lateral movement techniques and credential theft
- Defense evasion and persistence mechanisms
- MITRE ATT&CK framework mapping for Active Directory attacks
- You are an expert in PowerShell and Windows security.

CRITICAL FORMATTING RULES - YOU MUST USE MARKDOWN:
1. Use markdown syntax for all formatting
2. **DO NOT** use ## headers - the frontend will add section headers automatically
3. Use ### for subsections only when absolutely necessary for organization
4. Use numbered lists (1. 2. 3.) for ordered steps
5. Use - or * for bullet points
6. Wrap ONLY PowerShell commands and actual code in triple backticks (```)
7. Use **bold** for emphasis on important terms like domain names, usernames, group names, and relationship types
8. **DO NOT** use `backticks` for domain names, usernames, relationship types, or entity names
9. **Format entities properly:**
   - Domain names: **<DOMAIN.TLD>** (bold, not code)
   - User names: **<USERNAME>@<DOMAIN.TLD>** (bold, not code)
   - Group names: **DOMAIN ADMINS** (bold, not code)
   - Relationship types: **GenericAll**, **WriteDacl**, **MemberOf** (bold, not code)
   - Commands only: ```powershell ... ``` (code blocks)

IMPORTANT: Always use the ACTUAL domain name and entity names from the provided context/data.

""" + STATIC_SYSTEM_RULES
            ),
            HumanMessagePromptTemplate.from_template(
                """Context:
{context}

Question: {question}

Answer:"""
            ),
        ])

        # Initialize DeepSeek R1 (reasoner) for detailed analysis and report generation
        # R1 excels at complex attack chain analysis and contextual understanding
        self.llm = ChatOpenAI(
            model="deepseek-reasoner",
            temperature=0.0,  # Deterministic: same environment = same queries every time
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
            max_tokens=65536,  # DeepSeek R1 max — reasoning tokens are separate, this is output only
            timeout=300.0,  # 5 minutes - R1 thinks longer
            max_retries=2
        )

        # Initialize DeepSeek-Chat for faster responses (chat format, suggestions)
        # Chat model is optimized for quick conversational responses
        self.llm_fast = ChatOpenAI(
            model="deepseek-chat",
            temperature=0.0,  # Deterministic for consistent query generation and suggestions
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com",
            max_tokens=4096,  # Shorter responses for speed
            timeout=60.0,  # 1 minute timeout
            max_retries=2
        )
        
        # Create hybrid retriever (vector similarity + BM25 keyword matching)
        # Vector search: good for semantic queries ("how to compromise a DC")
        # BM25 search: good for keyword queries ("GenericAll", "GetChanges")
        self._vector_retriever = self.vectordb.as_retriever(
            search_type="similarity",
            search_kwargs={"k": 10}
        )
        self._bm25_retriever = None

        try:
            from langchain_community.retrievers import BM25Retriever

            logger.info("Building BM25 keyword index for hybrid search...")
            collection = self.vectordb._collection
            all_data = collection.get(include=["documents", "metadatas"])

            if all_data and all_data.get("documents"):
                from langchain_core.documents import Document as LCDocument
                bm25_docs = [
                    LCDocument(
                        page_content=all_data["documents"][i],
                        metadata=all_data["metadatas"][i] if all_data.get("metadatas") else {}
                    )
                    for i in range(len(all_data["documents"]))
                ]
                self._bm25_retriever = BM25Retriever.from_documents(bm25_docs, k=10)
                logger.info(f"Hybrid retriever ready: {len(bm25_docs)} docs in BM25 index")
            else:
                logger.warning("No documents in vector DB for BM25 — vector-only mode")
        except ImportError:
            logger.warning("rank_bm25 not installed — using vector-only retriever (pip install rank_bm25)")
        except Exception as e:
            logger.warning(f"BM25 initialization failed: {e} — using vector-only retriever")

        # Build a custom hybrid retriever that merges vector + BM25 results
        self.retriever = self._build_hybrid_retriever()
        
        # Create the RAG chain using LCEL (LangChain Expression Language)
        def format_docs(docs):
            return "\n\n".join(doc.page_content for doc in docs)

        self._format_docs = format_docs  # Store for reuse

        # Full RAG chain with R1 (for reports and detailed analysis)
        self.rag_chain = (
            {
                "context": self.retriever | format_docs,
                "question": RunnablePassthrough()
            }
            | self.prompt
            | self.llm
            | StrOutputParser()
        )

        # Fast RAG chain with DeepSeek-Chat (for chat responses and suggestions)
        self.rag_chain_fast = (
            {
                "context": self.retriever | format_docs,
                "question": RunnablePassthrough()
            }
            | self.prompt
            | self.llm_fast
            | StrOutputParser()
        )

        # Thread pool executor for running synchronous operations
        self.executor = ThreadPoolExecutor(max_workers=4)

    def _build_hybrid_retriever(self):
        """
        Build a hybrid retriever that combines vector similarity + BM25 keyword search.
        Returns a callable that conforms to LangChain's retriever interface.
        """
        from langchain_core.retrievers import BaseRetriever
        from langchain_core.documents import Document as LCDocument
        from langchain_core.callbacks import CallbackManagerForRetrieverRun
        from typing import List as TList

        vector_retriever = self._vector_retriever
        bm25_retriever = self._bm25_retriever

        if not bm25_retriever:
            # No BM25 — just use vector with k=7
            return self.vectordb.as_retriever(search_type="similarity", search_kwargs={"k": 7})

        class HybridRetriever(BaseRetriever):
            """Merges vector similarity + BM25 keyword results, deduplicates, returns top 7."""

            def _get_relevant_documents(
                self, query: str, *, run_manager: CallbackManagerForRetrieverRun
            ) -> TList[LCDocument]:
                # Get results from both retrievers
                vector_docs = vector_retriever.invoke(query)
                bm25_docs = bm25_retriever.invoke(query)

                # Merge and deduplicate by content
                seen_content = set()
                merged = []

                # Interleave: take from vector first (higher weight), then BM25
                # This gives vector 60% priority, BM25 40%
                vi, bi = 0, 0
                while len(merged) < 14 and (vi < len(vector_docs) or bi < len(bm25_docs)):
                    # Take 3 from vector, then 2 from BM25 (60/40 ratio)
                    for _ in range(3):
                        if vi < len(vector_docs):
                            content = vector_docs[vi].page_content[:200]
                            if content not in seen_content:
                                seen_content.add(content)
                                merged.append(vector_docs[vi])
                            vi += 1
                    for _ in range(2):
                        if bi < len(bm25_docs):
                            content = bm25_docs[bi].page_content[:200]
                            if content not in seen_content:
                                seen_content.add(content)
                                merged.append(bm25_docs[bi])
                            bi += 1

                return merged[:7]

        return HybridRetriever()

    def query(self, question: str) -> dict:
        """
        Synchronous query method. For async operations, use query_async.
        """
        try:
            logger.info(f"Processing RAG query: {question[:100]}...")

            # Get source documents - use truncated query for embedding (2048 token limit)
            # Extract first ~6000 chars (~1500 tokens) for retrieval to stay under limit
            retrieval_query = question[:6000] if len(question) > 6000 else question
            logger.info("Retrieving relevant documents from vector database...")
            source_docs = self.retriever.invoke(retrieval_query)
            logger.info(f"Retrieved {len(source_docs)} relevant documents")

            # Get answer with timeout protection
            logger.info("Generating AI response with DeepSeek...")
            # For long questions, bypass rag_chain (which has its own retriever that would fail)
            # Instead, manually format context and use prompt + llm directly
            context = self._format_docs(source_docs)
            direct_chain = self.prompt | self.llm | StrOutputParser()
            answer = direct_chain.invoke({"context": context, "question": question})
            logger.info(f"AI response generated ({len(answer)} characters)")
            
            # Format response to match old API structure
            return {
                "query": question,
                "result": answer,
                "source_documents": source_docs
            }
        except Exception as e:
            error_msg = f"Error in RAG query: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg) from e
    
    async def query_async(self, question: str) -> dict:
        """
        Async query method that runs the synchronous query in a thread pool.
        This prevents blocking the event loop.
        Uses DeepSeek R1 (slower, more thorough - for reports).
        """
        loop = asyncio.get_event_loop()
        try:
            # Run the synchronous query in a thread pool
            result = await asyncio.wait_for(
                loop.run_in_executor(self.executor, self.query, question),
                timeout=180.0  # 3 minutes total timeout
            )
            return result
        except asyncio.TimeoutError:
            error_msg = "RAG query timed out after 3 minutes"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"Error in async RAG query: {str(e)}"
            logger.error(error_msg, exc_info=True)
            # Preserve the original exception type if it's already a RuntimeError
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(error_msg) from e

    def query_fast(self, question: str) -> dict:
        """
        Fast synchronous query using DeepSeek-Chat.
        For chat format responses and suggestions.
        """
        try:
            logger.info(f"Processing fast RAG query: {question[:100]}...")

            # Get source documents - use truncated query for embedding (2048 token limit)
            retrieval_query = question[:6000] if len(question) > 6000 else question
            source_docs = self.retriever.invoke(retrieval_query)
            logger.info(f"Retrieved {len(source_docs)} relevant documents")

            # Get answer using fast model
            # For long questions, bypass rag_chain_fast (which has its own retriever)
            logger.info("Generating AI response with DeepSeek-Chat (fast)...")
            context = self._format_docs(source_docs)
            direct_chain = self.prompt | self.llm_fast | StrOutputParser()
            answer = direct_chain.invoke({"context": context, "question": question})
            logger.info(f"Fast AI response generated ({len(answer)} characters)")

            return {
                "query": question,
                "result": answer,
                "source_documents": source_docs
            }
        except Exception as e:
            error_msg = f"Error in fast RAG query: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise RuntimeError(error_msg) from e

    async def query_fast_async(self, question: str) -> dict:
        """
        Async fast query method using DeepSeek-Chat.
        For chat format responses and AI suggestions.
        Much faster than query_async (uses R1).
        """
        loop = asyncio.get_event_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(self.executor, self.query_fast, question),
                timeout=60.0  # 1 minute timeout for fast queries
            )
            return result
        except asyncio.TimeoutError:
            error_msg = "Fast RAG query timed out after 1 minute"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except Exception as e:
            error_msg = f"Error in async fast RAG query: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if isinstance(e, RuntimeError):
                raise
            raise RuntimeError(error_msg) from e

