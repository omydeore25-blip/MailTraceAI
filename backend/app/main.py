from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.core.exceptions import MailTraceException
from app.core.security import get_password_hash
from app.db.base import Base
from app.db.session import engine, AsyncSessionLocal
from app.db.neo4j_session import get_neo4j_driver, close_neo4j_driver
from app.models.user import User
from app.api.v1.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} in {settings.APP_ENV} mode...")
    
    # Initialize SQL database tables automatically (for SQLite or fresh PostgreSQL setup)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database schemas verified.")
    
    # Initialize default admin/analyst user if empty
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == "analyst"))
        if not result.scalar_one_or_none():
            demo_user = User(
                username="analyst",
                email="analyst@mailtrace.ai",
                full_name="Forensic Analyst",
                role="analyst",
                hashed_password=get_password_hash("analyst123!"),
                is_active=True
            )
            session.add(demo_user)
            await session.commit()
            logger.info("Default forensic analyst user created (username: analyst, password: analyst123!).")
    
    # Check Neo4j connection
    if settings.NEO4J_ENABLED:
        await get_neo4j_driver()
        
    yield
    
    # Shutdown
    logger.info("Shutting down MailTrace AI...")
    await close_neo4j_driver()


app = FastAPI(
    title=settings.APP_NAME,
    description="Enterprise-grade AI Email Threat Detection, Forensics, Threat Intelligence and Infrastructure Attribution Platform (SIH 2026).",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers
@app.exception_handler(MailTraceException)
async def mailtrace_exception_handler(request: Request, exc: MailTraceException):
    return JSONResponse(
        status_code=400,
        content={"error": exc.message, "details": exc.details}
    )

# Include API Router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Root-level health check matching documentation
from app.api.v1.health import health_check
app.add_api_route("/health", health_check, methods=["GET"], tags=["Health"])


@app.get("/")
async def root():
    return {
        "app": settings.APP_NAME,
        "version": "1.0.0",
        "docs": "/docs",
        "api": settings.API_V1_STR,
        "health": "/health",
        "status": "online"
    }
