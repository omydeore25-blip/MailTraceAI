import sys
import os
from pathlib import Path
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

# Ensure backend directory is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.main import app as fastapi_app
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine, AsyncSessionLocal
import app.models  # Register all models

SAMPLES_DIR = backend_dir / "app" / "data" / "samples"


@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    """Ensure database schema is created before running test suite."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield


@pytest_asyncio.fixture
async def async_client():
    """Async HTTP client for testing FastAPI API routes."""
    transport = ASGITransport(app=fastapi_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client



@pytest.fixture
def sample_emails():
    """Dictionary containing paths and text contents of sample emails."""
    samples = {}
    for filename in ["clean_newsletter.eml", "credential_phishing.eml", "bec_wire_fraud.eml", "dkim_spf_spoofed.eml"]:
        filepath = SAMPLES_DIR / filename
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                samples[filename] = {
                    "path": str(filepath),
                    "content": f.read()
                }
    return samples
