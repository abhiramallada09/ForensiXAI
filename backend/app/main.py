from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.api.v1.router import api_router


# Ensure storage directories and database tables exist
settings.resolved_upload_dir()
settings.resolved_working_dir()
settings.resolved_report_dir()
init_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup tasks
    init_db()
    yield
    # Shutdown tasks (if any)


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        f"{settings.APP_DESCRIPTION}\n\n"
        f"**Official Academic Title:** {settings.ACADEMIC_TITLE}"
    ),
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API v1 router
app.include_router(api_router, prefix="/api/v1")


@app.get("/", tags=["Root"])
def root():
    return {
        "product": settings.APP_NAME,
        "academic_title": settings.ACADEMIC_TITLE,
        "status": "Online",
        "documentation": "/docs",
        "api_v1": "/api/v1"
    }
