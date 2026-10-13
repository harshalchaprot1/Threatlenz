"""FastAPI Dependency Injection Providers.

Provides database session generators and reusable context dependencies.
"""

from typing import Generator
from sqlalchemy.orm import Session

from src.database import get_db_session


def get_db() -> Generator[Session, None, None]:
    """Dependency provider yielding a scoped database session.

    Ensures that sessions are cleanly committed/closed upon completion
    of the HTTP request lifecycle.
    """
    session = get_db_session()
    try:
        yield session
    finally:
        session.close()
