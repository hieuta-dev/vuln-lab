"""add scan tables (scan_targets, scan_sessions, scan_results)

Revision ID: 002_add_scan_tables
Revises: 001_create_base_tables
Create Date: 2024-06-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision      = '002_add_scan_tables'
down_revision = '001_create_base_tables'
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── scan_targets ──────────────────────────────────────────────────────────
    op.create_table(
        'scan_targets',
        sa.Column('id',           sa.Integer(),     nullable=False),
        sa.Column('user_id',      sa.Integer(),     nullable=False),
        sa.Column('target_url',   sa.String(512),   nullable=False),
        sa.Column('target_name',  sa.String(255),   nullable=False),
        sa.Column('description',  sa.String(1000),  nullable=True),
        sa.Column('auth_info',    postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('headers',      postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at',   sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_targets_id'), 'scan_targets', ['id'], unique=False)

    # ── scan_sessions ─────────────────────────────────────────────────────────
    op.create_table(
        'scan_sessions',
        sa.Column('id',           sa.Integer(),  nullable=False),
        sa.Column('user_id',      sa.Integer(),  nullable=False),
        sa.Column('target_id',    sa.Integer(),  nullable=False),
        sa.Column('status',       sa.String(20), server_default='pending', nullable=True),
        sa.Column('started_at',   sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'],   ['users.id']),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_sessions_id'), 'scan_sessions', ['id'], unique=False)

    # ── scan_results ──────────────────────────────────────────────────────────
    op.create_table(
        'scan_results',
        sa.Column('id',               sa.Integer(),  nullable=False),
        sa.Column('session_id',       sa.Integer(),  nullable=False),
        sa.Column('scenario_id',      sa.Integer(),  nullable=True),
        sa.Column('vuln_type',        sa.String(60), nullable=False),
        sa.Column('status',           sa.String(20), server_default='scanning', nullable=True),
        sa.Column('missing_info',     sa.Text(),     nullable=True),
        sa.Column('findings',         postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('severity',         sa.String(20), nullable=True),
        sa.Column('reproduce_steps',  postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('scanned_at',       sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['session_id'],  ['scan_sessions.id']),
        sa.ForeignKeyConstraint(['scenario_id'], ['scenarios.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scan_results_id'), 'scan_results', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_scan_results_id'),  table_name='scan_results')
    op.drop_table('scan_results')
    op.drop_index(op.f('ix_scan_sessions_id'), table_name='scan_sessions')
    op.drop_table('scan_sessions')
    op.drop_index(op.f('ix_scan_targets_id'),  table_name='scan_targets')
    op.drop_table('scan_targets')
