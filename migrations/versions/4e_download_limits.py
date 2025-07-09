"""Add download count tracking to File"""

from alembic import op
import sqlalchemy as sa

revision = '4e'
down_revision = '3d'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('file', sa.Column('max_downloads', sa.Integer(), nullable=False, server_default='1'))
    op.add_column('file', sa.Column('download_count', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    op.drop_column('file', 'download_count')
    op.drop_column('file', 'max_downloads')

