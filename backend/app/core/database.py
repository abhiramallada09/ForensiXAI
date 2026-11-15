from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings

# Handle SQLite vs PostgreSQL connection configurations
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and safely closes it upon exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initialize database tables and seed baseline admin/investigator accounts."""
    # Ensure tables are registered
    import backend.app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)

    from backend.app.models.user import User
    from backend.app.core.security import hash_password

    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            default_users = [
                User(
                    email="investigator@forensix.ai",
                    username="abhiram",
                    hashed_password=hash_password("Password123!"),
                    full_name="A. Abhiram",
                    role="Lead Forensic Examiner",
                    is_active=True,
                ),
                User(
                    email="analyst@forensix.ai",
                    username="analyst",
                    hashed_password=hash_password("Password123!"),
                    full_name="DFIR Analyst",
                    role="Cybersecurity Analyst",
                    is_active=True,
                ),
            ]
            db.add_all(default_users)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

