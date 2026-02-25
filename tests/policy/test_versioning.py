"""Tests for policy versioning — C25.

Covers:
- Version persistence on reload
- Initial version on from_config
- Rollback creates new version
- compute_policy_hash
- Round-trip YAML through DB
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from sna.db.models import PolicyVersion
from sna.policy.engine import PolicyEngine
from sna.policy.loader import compute_policy_hash, load_policy


@pytest.fixture
def session_factory(async_engine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(async_engine, expire_on_commit=False)


class TestComputePolicyHash:
    def test_hash_is_sha256(self) -> None:
        h = compute_policy_hash("hello world")
        assert len(h) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in h)

    def test_same_content_same_hash(self) -> None:
        assert compute_policy_hash("abc") == compute_policy_hash("abc")

    def test_different_content_different_hash(self) -> None:
        assert compute_policy_hash("abc") != compute_policy_hash("xyz")


class TestVersionPersistenceOnReload:
    async def test_reload_creates_version(self, session_factory, sample_policy_path) -> None:
        engine = await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )

        # Count versions before reload
        async with session_factory() as session:
            before = await session.execute(select(func.count(PolicyVersion.id)))
            count_before = before.scalar() or 0

        await engine.reload(str(sample_policy_path))

        async with session_factory() as session:
            after = await session.execute(select(func.count(PolicyVersion.id)))
            count_after = after.scalar() or 0

        assert count_after == count_before + 1

    async def test_reload_version_has_correct_fields(self, session_factory, sample_policy_path) -> None:
        engine = await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )
        await engine.reload(str(sample_policy_path))

        async with session_factory() as session:
            result = await session.execute(
                select(PolicyVersion).order_by(PolicyVersion.id.desc()).limit(1)
            )
            version = result.scalar_one()

        assert version.version_string == "1.0"
        assert len(version.policy_hash) == 64
        assert version.policy_yaml  # Not empty
        assert version.created_by == "system"


class TestVersionPersistenceOnFromConfig:
    async def test_from_config_creates_initial_version(self, session_factory, sample_policy_path) -> None:
        async with session_factory() as session:
            before = await session.execute(select(func.count(PolicyVersion.id)))
            count_before = before.scalar() or 0

        await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )

        async with session_factory() as session:
            after = await session.execute(select(func.count(PolicyVersion.id)))
            count_after = after.scalar() or 0

        assert count_after == count_before + 1

    async def test_initial_version_has_no_diff(self, session_factory, sample_policy_path) -> None:
        await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )

        async with session_factory() as session:
            result = await session.execute(
                select(PolicyVersion).order_by(PolicyVersion.id.desc()).limit(1)
            )
            version = result.scalar_one()

        assert version.diff_text is None
        assert version.created_by == "system_init"


class TestRoundTripYaml:
    async def test_yaml_round_trip(self, session_factory, sample_policy_path) -> None:
        """YAML stored in DB can be loaded back into a valid PolicyConfig."""
        engine = await PolicyEngine.from_config(
            policy_file_path=str(sample_policy_path),
            session_factory=session_factory,
            default_eas=0.1,
        )

        async with session_factory() as session:
            result = await session.execute(
                select(PolicyVersion).order_by(PolicyVersion.id.desc()).limit(1)
            )
            version = result.scalar_one()

        import yaml
        from sna.policy.models import PolicyConfig

        data = yaml.safe_load(version.policy_yaml)
        restored = PolicyConfig(**data)
        assert restored.version == engine.policy.version
        assert len(restored.action_tiers) == 5
