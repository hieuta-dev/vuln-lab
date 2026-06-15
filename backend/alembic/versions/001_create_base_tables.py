"""create base tables (users, comments, uploads, scenarios, attack_logs)

Revision ID: 001_create_base_tables
Revises: None
Create Date: 2024-06-14
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision     = '001_create_base_tables'
down_revision = None
branch_labels = None
depends_on    = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        'users',
        sa.Column('id',             sa.Integer(),    nullable=False),
        sa.Column('username',       sa.String(50),   nullable=False),
        sa.Column('password_plain', sa.String(255),  nullable=True),
        sa.Column('password_hash',  sa.String(255),  nullable=True),
        sa.Column('role',           sa.String(20),   server_default='user', nullable=True),
        sa.Column('created_at',     sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
    )
    op.create_index(op.f('ix_users_id'),       'users', ['id'],       unique=False)
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)

    # ── comments ──────────────────────────────────────────────────────────────
    op.create_table(
        'comments',
        sa.Column('id',         sa.Integer(),  nullable=False),
        sa.Column('user_id',    sa.Integer(),  nullable=True),
        sa.Column('content',    sa.Text(),     nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_comments_id'), 'comments', ['id'], unique=False)

    # ── uploads ───────────────────────────────────────────────────────────────
    op.create_table(
        'uploads',
        sa.Column('id',          sa.Integer(),    nullable=False),
        sa.Column('user_id',     sa.Integer(),    nullable=True),
        sa.Column('file_name',   sa.String(255),  nullable=False),
        sa.Column('file_path',   sa.String(255),  nullable=False),
        sa.Column('file_size',   sa.Integer(),    nullable=True),
        sa.Column('mime_type',   sa.String(100),  nullable=True),
        sa.Column('uploaded_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_uploads_id'), 'uploads', ['id'], unique=False)

    # ── scenarios ─────────────────────────────────────────────────────────────
    op.create_table(
        'scenarios',
        sa.Column('id',           sa.Integer(),    nullable=False),
        sa.Column('vuln_type',    sa.String(60),   nullable=False),
        sa.Column('title',        sa.String(255),  nullable=True),
        sa.Column('steps',        postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('payloads',     postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('cvss_score',   sa.Float(),      nullable=True),
        sa.Column('generated_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_scenarios_id'),        'scenarios', ['id'],        unique=False)
    op.create_index(op.f('ix_scenarios_vuln_type'), 'scenarios', ['vuln_type'], unique=False)

    # ── attack_logs ───────────────────────────────────────────────────────────
    op.create_table(
        'attack_logs',
        sa.Column('id',            sa.Integer(),   nullable=False),
        sa.Column('endpoint',      sa.String(255), nullable=True),
        sa.Column('payload',       sa.Text(),      nullable=True),
        sa.Column('security_mode', sa.String(20),  nullable=True),
        sa.Column('result',        sa.String(50),  nullable=True),
        sa.Column('timestamp',     sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_attack_logs_id'), 'attack_logs', ['id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_attack_logs_id'), table_name='attack_logs')
    op.drop_table('attack_logs')
    op.drop_index(op.f('ix_scenarios_vuln_type'), table_name='scenarios')
    op.drop_index(op.f('ix_scenarios_id'),        table_name='scenarios')
    op.drop_table('scenarios')
    op.drop_index(op.f('ix_uploads_id'),   table_name='uploads')
    op.drop_table('uploads')
    op.drop_index(op.f('ix_comments_id'),  table_name='comments')
    op.drop_table('comments')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_id'),       table_name='users')
    op.drop_table('users')
