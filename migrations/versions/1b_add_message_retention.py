"""Add message_retention_days to user"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1b'
down_revision = '8e2fe4b661c1'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user', sa.Column('message_retention_days', sa.Integer(), nullable=False, server_default='30'))


def downgrade():
    op.drop_column('user', 'message_retention_days')
