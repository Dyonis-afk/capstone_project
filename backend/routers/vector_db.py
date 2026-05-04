"""
Vector Database Management Router
Protected endpoint for uploading/updating ChromaDB files.

Usage:
1. Set VECTOR_DB_SECRET environment variable on Render
2. Upload files with: POST /api/vector-db/upload
   Header: X-Vector-DB-Secret: your-secret-key
"""

import os
import shutil
import zipfile
import logging
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Header, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/vector-db", tags=["vector-db"])

# Get paths from environment
VECTOR_DB_PATH = os.getenv("CHROMA_PERSIST_DIRECTORY", "./aegis_vector_db")
VECTOR_DB_SECRET = os.getenv("VECTOR_DB_SECRET")


def verify_secret(secret: str = Header(None, alias="X-Vector-DB-Secret")):
    """Verify the secret key for protected endpoints."""
    if not VECTOR_DB_SECRET:
        raise HTTPException(
            status_code=503,
            detail="VECTOR_DB_SECRET not configured on server"
        )
    if secret != VECTOR_DB_SECRET:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing X-Vector-DB-Secret header"
        )
    return True


@router.get("/status")
async def get_status():
    """Check vector DB status (public endpoint)."""
    db_path = Path(VECTOR_DB_PATH)
    exists = db_path.exists()

    file_count = 0
    total_size = 0

    if exists:
        for f in db_path.rglob("*"):
            if f.is_file():
                file_count += 1
                total_size += f.stat().st_size

    return {
        "path": str(db_path),
        "exists": exists,
        "file_count": file_count,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "secret_configured": VECTOR_DB_SECRET is not None
    }


@router.post("/upload")
async def upload_vector_db(
    file: UploadFile = File(...),
    secret: str = Header(None, alias="X-Vector-DB-Secret")
):
    """
    Upload vector database as a ZIP file.

    The ZIP should contain the ChromaDB files (chroma.sqlite3, etc.)
    at the root level or in a single folder.

    Requires X-Vector-DB-Secret header.
    """
    verify_secret(secret)

    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="File must be a .zip archive")

    db_path = Path(VECTOR_DB_PATH)
    temp_zip = Path("/tmp/vector_db_upload.zip")
    temp_extract = Path("/tmp/vector_db_extract")

    try:
        logger.info(f"Receiving vector DB upload: {file.filename}")

        # Save uploaded file
        with open(temp_zip, "wb") as f:
            content = await file.read()
            f.write(content)

        logger.info(f"Saved ZIP file: {temp_zip.stat().st_size / (1024*1024):.2f} MB")

        # Clear temp extract directory
        if temp_extract.exists():
            shutil.rmtree(temp_extract)
        temp_extract.mkdir(parents=True)

        # Extract ZIP
        with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
            zip_ref.extractall(temp_extract)

        logger.info(f"Extracted to {temp_extract}")

        # Find the actual DB files (might be in a subfolder)
        extracted_items = list(temp_extract.iterdir())
        source_path = temp_extract

        # If there's a single folder, use that as source
        if len(extracted_items) == 1 and extracted_items[0].is_dir():
            source_path = extracted_items[0]
            logger.info(f"Using subfolder as source: {source_path}")

        # Backup existing DB if it exists
        if db_path.exists():
            backup_path = Path(str(db_path) + "_backup")
            if backup_path.exists():
                shutil.rmtree(backup_path)
            shutil.move(str(db_path), str(backup_path))
            logger.info(f"Backed up existing DB to {backup_path}")

        # Move new DB to target path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_path, db_path)

        # Count files
        file_count = sum(1 for _ in db_path.rglob("*") if _.is_file())
        total_size = sum(f.stat().st_size for f in db_path.rglob("*") if f.is_file())

        logger.info(f"Vector DB uploaded successfully: {file_count} files, {total_size/(1024*1024):.2f} MB")

        # Cleanup
        temp_zip.unlink()
        shutil.rmtree(temp_extract)

        return JSONResponse({
            "success": True,
            "message": "Vector database uploaded successfully",
            "path": str(db_path),
            "file_count": file_count,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        })

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")
    except Exception as e:
        logger.error(f"Upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.delete("/clear")
async def clear_vector_db(
    secret: str = Header(None, alias="X-Vector-DB-Secret")
):
    """Clear the vector database. Requires X-Vector-DB-Secret header."""
    verify_secret(secret)

    db_path = Path(VECTOR_DB_PATH)

    if db_path.exists():
        shutil.rmtree(db_path)
        db_path.mkdir(parents=True)
        logger.info(f"Cleared vector DB at {db_path}")
        return {"success": True, "message": "Vector database cleared"}

    return {"success": True, "message": "Vector database was already empty"}
