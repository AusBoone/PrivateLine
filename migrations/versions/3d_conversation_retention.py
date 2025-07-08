"""Add group retention and conversation-specific TTL"""

from alembic import op
import sqlalchemy as sa

revision = '3d'
down_revision = '2c'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('group', sa.Column('retention_days', sa.Integer(), nullable=True))
    op.create_table(
        'conversation_retention',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('peer_id', sa.Integer(), nullable=False),
        sa.Column('retention_days', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['user.id']),
        sa.ForeignKeyConstraint(['peer_id'], ['user.id']),
        sa.UniqueConstraint('owner_id', 'peer_id', name='uix_conv_retention'),
    )


def downgrade():
    op.drop_table('conversation_retention')
    op.drop_column('group', 'retention_days')
