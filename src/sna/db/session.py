"""Async SQLAlchemy engine and session factory.

Provides:
    create_async_engine_from_url: Creates a configured async engine
    create_session_factory: Creates an async session maker
    get_db_session: FastAPI dependency that yields a transactional session
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_async_engine_from_url(
    database_url: str,
    *,
    pool_timeout: int = 5,
    connect_timeout: int = 5,
    echo: bool = False,
) -> AsyncEngine:
    """Create an async SQLAlchemy engine with configured timeouts.

    Args:
        database_url: The database connection URL.
        pool_timeout: Seconds to wait for a connection from the pool.
        connect_timeout: Seconds to wait for the initial connection.
        echo: Whether to log SQL statements.

    Returns:
        A configured AsyncEngine instance.
    """
    kwargs: dict[str, object] = {"echo": echo}

    # Dialect-based pool configuration (not string matching)
    from sqlalchemy import make_url

    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        kwargs["connect_args"] = {"timeout": connect_timeout}
    else:
        kwargs["pool_timeout"] = pool_timeout
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20

    return create_async_engine(database_url, **kwargs)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory bound to the given engine.

    Args:
        engine: The async engine to bind sessions to.

    Returns:
        An async_sessionmaker configured with expire_on_commit=False.
    """
    return async_sessionmaker(engine, expire_on_commit=False)


async def get_db_session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession, None]:
    """Yield a transactional database session.

    Commits on success, rolls back on exception. Intended for use
    as a FastAPI dependency.

    Args:
        session_factory: The async session maker to create sessions from.

    Yields:
        An AsyncSession within a transaction.
    """
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
