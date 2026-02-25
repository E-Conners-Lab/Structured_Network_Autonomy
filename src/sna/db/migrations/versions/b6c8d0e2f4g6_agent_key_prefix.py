"""phase6_agent_key_prefix

Adds api_key_prefix column and index to agent table for O(1) auth lookup.

Revision ID: b6c8d0e2f4g6
Revises: a5b7c9d1e3f5
Create Date: 2026-02-25 14:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b6c8d0e2f4g6'
down_revision: Union[str, None] = 'a5b7c9d1e3f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add api_key_prefix column (nullable initially for existing agents)
    op.add_column(
        'agent',
        sa.Column('api_key_prefix', sa.String(length=8), nullable=True, server_default='')
    )

    # Backfill existing rows with empty prefix
    op.execute("UPDATE agent SET api_key_prefix = '' WHERE api_key_prefix IS NULL")

    # Make non-nullable now that all rows have a value
    with op.batch_alter_table('agent') as batch_op:
        batch_op.alter_column('api_key_prefix', nullable=False)

    # Add index for fast prefix lookup
    op.create_index('ix_agent_api_key_prefix', 'agent', ['api_key_prefix'])


def downgrade() -> None:
    op.drop_index('ix_agent_api_key_prefix', table_name='agent')
    op.drop_column('agent', 'api_key_prefix')
