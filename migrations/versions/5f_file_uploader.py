"""Add ``uploader_id`` column to the ``file`` table.

This migration introduces a foreign key linking each file to the user who
uploaded it. Existing rows are assumed empty so the column is added nullable and
then made mandatory once the constraint is in place.
"""

from alembic import op
import sqlalchemy as sa

revision = '5f'
down_revision = '4e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('file', sa.Column('uploader_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        None, 'file', 'user', ['uploader_id'], ['id']
    )
    op.alter_column('file', 'uploader_id', nullable=False)


def downgrade():
    op.drop_constraint(None, 'file', type_='foreignkey')
    op.drop_column('file', 'uploader_id')
