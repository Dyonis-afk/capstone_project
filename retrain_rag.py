#!/usr/bin/env python3
"""
AEGIS RAG Retraining Script

Rebuilds the ChromaDB vector database with all training data:
- MITRE ATT&CK techniques
- BloodHound edges and queries
- PDF security documents
- GitHub training data (Sigma, Splunk, cheatsheets, wikis)

Usage: python retrain_rag.py
"""

import os
import sys
import shutil
import time
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Check for API key early
if not os.environ.get('OPENAI_API_KEY'):
    print("❌ Error: OPENAI_API_KEY not found in environment")
    print("   Set it in your .env file or export it")
    sys.exit(1)

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_chroma import Chroma
from data_loader import DataLoader

# Configuration
CHROMA_PATH = './aegis_vector_db'
COLLECTION_NAME = 'aegis_docs'
EMBEDDING_MODEL = 'text-embedding-3-small'
CHUNK_SIZE = 1500       # Up from 800 — keeps full attack procedures in one chunk
CHUNK_OVERLAP = 200     # Up from 150 — better continuity between chunks
BATCH_SIZE = 5000


def progress_bar(current, total, prefix='', suffix='', length=40):
    """Display a progress bar."""
    percent = current / total if total > 0 else 0
    filled = int(length * percent)
    bar = '█' * filled + '░' * (length - filled)
    print(f'\r{prefix} |{bar}| {percent*100:.1f}% {suffix}', end='', flush=True)
    if current >= total:
        print()


def main():
    start_time = time.time()

    print("\n" + "="*60)
    print("       AEGIS RAG RETRAINING SCRIPT")
    print("="*60 + "\n")

    # Step 1: Check if database exists
    if Path(CHROMA_PATH).exists():
        print(f"⚠️  Existing database found at {CHROMA_PATH}")
        response = input("   Delete and rebuild? (y/n): ").strip().lower()
        if response != 'y':
            print("   Aborted.")
            return
        print("   Deleting existing database...")
        shutil.rmtree(CHROMA_PATH)
        print("   ✅ Deleted\n")

    # Step 2: Load all data with source-aware split
    print("📚 STEP 1: Loading Training Data")
    print("-" * 40)

    loader = DataLoader()
    structured_docs, unstructured_docs = loader.load_all_data_split()

    print(f"\n📊 Structured docs (keep whole): {len(structured_docs)}")
    print(f"📊 Unstructured docs (will chunk): {len(unstructured_docs)}")

    # Step 3: Chunk ONLY unstructured documents
    # Structured docs (BloodHound edges, MITRE, queries) stay whole —
    # each is a self-contained unit that loses meaning if split
    print(f"\n✂️  STEP 2: Chunking Unstructured Documents (chunk_size={CHUNK_SIZE})")
    print("-" * 40)

    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        separators=["\n\n", "\n", ". ", " ", ""]
    )

    unstructured_chunks = []
    total_docs = len(unstructured_docs)

    for i, doc in enumerate(unstructured_docs):
        if i % 100 == 0 or i == total_docs - 1:
            progress_bar(i + 1, total_docs, prefix="Chunking", suffix=f"({len(unstructured_chunks)} chunks)", length=30)
        doc_chunks = text_splitter.split_documents([doc])
        unstructured_chunks.extend(doc_chunks)

    # Combine: structured (whole) + unstructured (chunked)
    chunks = structured_docs + unstructured_chunks

    print(f"\n📊 Structured (kept whole):  {len(structured_docs)}")
    print(f"📊 Unstructured (chunked):   {len(unstructured_chunks)}")
    print(f"📊 Total chunks for embedding: {len(chunks)}")

    # Step 4: Create embeddings and store in ChromaDB
    print("\n🧠 STEP 3: Creating Embeddings & Storing in ChromaDB")
    print("-" * 40)
    print(f"   Model: {EMBEDDING_MODEL}")
    print(f"   Batch size: {BATCH_SIZE}")

    embeddings = OpenAIEmbeddings(
        model=EMBEDDING_MODEL,
        openai_api_key=os.environ['OPENAI_API_KEY']
    )

    total_batches = (len(chunks) + BATCH_SIZE - 1) // BATCH_SIZE
    vectordb = None

    for batch_num in range(total_batches):
        start_idx = batch_num * BATCH_SIZE
        end_idx = min(start_idx + BATCH_SIZE, len(chunks))
        batch = chunks[start_idx:end_idx]

        progress_bar(
            batch_num + 1,
            total_batches,
            prefix=f"Batch {batch_num + 1}/{total_batches}",
            suffix=f"({len(batch)} chunks)",
            length=30
        )

        try:
            if batch_num == 0:
                vectordb = Chroma.from_documents(
                    documents=batch,
                    embedding=embeddings,
                    persist_directory=CHROMA_PATH,
                    collection_name=COLLECTION_NAME
                )
            else:
                vectordb.add_documents(batch)
        except Exception as e:
            print(f"\n❌ Error in batch {batch_num + 1}: {e}")
            print("   Retrying in 30 seconds...")
            time.sleep(30)
            vectordb.add_documents(batch)

    # Step 5: Verify
    print("\n✅ STEP 4: Verification")
    print("-" * 40)

    final_count = vectordb._collection.count()
    elapsed = time.time() - start_time

    print(f"   Vectors in database: {final_count}")
    print(f"   Time elapsed: {elapsed/60:.1f} minutes")

    # Summary
    print("\n" + "="*60)
    print("       RETRAINING COMPLETE!")
    print("="*60)
    print(f"""
📊 Summary:
   - Structured docs (whole): {len(structured_docs)}
   - Unstructured docs (chunked): {len(unstructured_docs)} → {len(unstructured_chunks)} chunks
   - Total vectors: {len(chunks)}
   - Vectors stored: {final_count}
   - Database path: {CHROMA_PATH}
   - Time: {elapsed/60:.1f} minutes

🎯 Next Steps:
   - Run quality evaluation: python backend/scripts/test_attack_chain_quality.py
   - Test the RAG: python -c "from backend.services.rag_service import RAGService; ..."
""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
