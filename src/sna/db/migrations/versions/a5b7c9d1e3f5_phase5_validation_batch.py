"""phase5_validation_batch

Adds validation_log table and batch_id column to execution_log.

Revision ID: a5b7c9d1e3f5
Revises: 133a0e6fbe2c
Create Date: 2026-02-25 12:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a5b7c9d1e3f5'
down_revision: Union[str, None] = '133a0e6fbe2c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create validation_log table
    op.create_table(
        'validation_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('external_id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('execution_log_id', sa.Integer(), nullable=True),
        sa.Column('tool_name', sa.String(length=255), nullable=False),
        sa.Column('device_target', sa.String(length=255), nullable=False),
        sa.Column('testcase_name', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=True),
        sa.Column('duration_seconds', sa.Float(), nullable=False),
        sa.Column('triggered_rollback', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['execution_log_id'], ['execution_log.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('external_id'),
    )
    op.create_index('ix_validation_log_timestamp', 'validation_log', ['timestamp'])
    op.create_index('ix_validation_log_execution_log_id', 'validation_log', ['execution_log_id'])
    op.create_index('ix_validation_log_status', 'validation_log', ['status'])

    # Add batch_id column to execution_log
    op.add_column('execution_log', sa.Column('batch_id', sa.String(length=36), nullable=True))
    op.create_index('ix_execution_log_batch_id', 'execution_log', ['batch_id'])


def downgrade() -> None:
    op.drop_index('ix_execution_log_batch_id', table_name='execution_log')
    op.drop_column('execution_log', 'batch_id')
    op.drop_index('ix_validation_log_status', table_name='validation_log')
    op.drop_index('ix_validation_log_execution_log_id', table_name='validation_log')
    op.drop_index('ix_validation_log_timestamp', table_name='validation_log')
    op.drop_table('validation_log')
