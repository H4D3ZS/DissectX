"""SQLAlchemy declarative base and database configuration"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Create declarative base
Base = declarative_base()

# Database URL will be configured from settings
DATABASE_URL = "sqlite:///./vulnchain.db"  # Default for development

# Create engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    echo=False,  # Set to True for SQL query logging
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """
    Dependency to get database session.
    
    Yields:
        Database session
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initialize database by creating all tables.
    
    This should be called on application startup.
    """
    # Import all models to ensure they are registered with Base
    from src.vulnchain.db.models import (
        user,
        workspace,
        finding,
        session,
        target,
        log,
        evidence,
    )
    
    Base.metadata.create_all(bind=engine)
