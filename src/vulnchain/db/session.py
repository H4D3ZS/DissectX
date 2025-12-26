"""Database session management"""

from typing import Generator
from sqlalchemy.orm import Session

from src.vulnchain.db.base import SessionLocal, engine, Base


def get_db() -> Generator[Session, None, None]:
    """
    Dependency function to get database session.
    
    Yields:
        Database session
        
    Example:
        @app.get("/items/")
        def read_items(db: Session = Depends(get_db)):
            return db.query(Item).all()
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Initialize database by creating all tables.
    
    This should be called on application startup.
    """
    # Import all models to ensure they are registered with Base
    from src.vulnchain.db.models import (
        user,
        workspace,
        finding,
        evidence,
        session,
        target,
        log,
    )
    
    # Create all tables
    Base.metadata.create_all(bind=engine)


def drop_db() -> None:
    """
    Drop all database tables.
    
    WARNING: This will delete all data!
    Only use in development/testing.
    """
    Base.metadata.drop_all(bind=engine)


def reset_db() -> None:
    """
    Reset database by dropping and recreating all tables.
    
    WARNING: This will delete all data!
    Only use in development/testing.
    """
    drop_db()
    init_db()
