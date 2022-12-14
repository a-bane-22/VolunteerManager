"""Add Volunteer table

Revision ID: aa55c913abc3
Revises: b1e1da9148fd
Create Date: 2022-07-30 17:39:43.361526

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aa55c913abc3'
down_revision = 'b1e1da9148fd'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('volunteer',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('first_name', sa.String(length=32), nullable=True),
    sa.Column('last_name', sa.String(length=32), nullable=True),
    sa.Column('dob', sa.Date(), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('phone', sa.String(length=10), nullable=True),
    sa.Column('address', sa.String(length=120), nullable=True),
    sa.Column('city', sa.String(length=32), nullable=True),
    sa.Column('state', sa.String(length=24), nullable=True),
    sa.Column('zip', sa.String(length=10), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_volunteer_dob'), 'volunteer', ['dob'], unique=False)
    op.create_index(op.f('ix_volunteer_email'), 'volunteer', ['email'], unique=True)
    op.create_index(op.f('ix_volunteer_first_name'), 'volunteer', ['first_name'], unique=False)
    op.create_index(op.f('ix_volunteer_last_name'), 'volunteer', ['last_name'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_volunteer_last_name'), table_name='volunteer')
    op.drop_index(op.f('ix_volunteer_first_name'), table_name='volunteer')
    op.drop_index(op.f('ix_volunteer_email'), table_name='volunteer')
    op.drop_index(op.f('ix_volunteer_dob'), table_name='volunteer')
    op.drop_table('volunteer')
    # ### end Alembic commands ###
