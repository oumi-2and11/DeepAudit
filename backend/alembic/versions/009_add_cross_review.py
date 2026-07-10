"""Add verdict and cross_review columns to agent_findings (§7 交叉复核)

Revision ID: 009_add_cross_review
Revises: 008_add_files_with_findings
Create Date: 2026-07-09

"""
from alembic import op
import sqlalchemy as sa


revision = '009_add_cross_review'
down_revision = '008_add_files_with_findings'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 幂等添加 §7 交叉复核字段
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('agent_findings')]

    if 'verdict' not in columns:
        op.add_column(
            'agent_findings',
            sa.Column('verdict', sa.String(length=40), nullable=True)
        )
        op.create_index(
            'ix_agent_findings_verdict',
            'agent_findings',
            ['verdict'],
        )

    if 'cross_review' not in columns:
        op.add_column(
            'agent_findings',
            sa.Column('cross_review', sa.JSON(), nullable=True)
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('agent_findings')]

    if 'cross_review' in columns:
        op.drop_column('agent_findings', 'cross_review')
    if 'verdict' in columns:
        # index 会随 drop_column 一起清（PG/SQLite 都支持），不放心就手动 drop
        try:
            op.drop_index('ix_agent_findings_verdict', table_name='agent_findings')
        except Exception:
            pass
        op.drop_column('agent_findings', 'verdict')
