"""Add recipient_id column

Revision ID: 0001
Revises: 
Create Date: 2024-05-02 00:00:00
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('message', sa.Column('recipient_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'message', 'user', ['recipient_id'], ['id'])
    op.alter_column('message', 'recipient_id', nullable=False)

def downgrade():
    op.drop_constraint(None, 'message', type_='foreignkey')
    op.drop_column('message', 'recipient_id')
