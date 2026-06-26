from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from intellipatch.config import settings
from intellipatch.storage.orm import Base


def make_engine(database_url: str | None = None):
    return create_engine(database_url or settings.database_url, pool_pre_ping=True)


engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db(bind_engine=None) -> None:
    Base.metadata.create_all(bind=bind_engine or engine)


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
