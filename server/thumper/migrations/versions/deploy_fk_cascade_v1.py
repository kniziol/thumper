"""Add ON DELETE CASCADE to deployment foreign keys.

Defense-in-depth: store.delete_tripwire / endpoint removal already delete the
deployments first, but a DB-level cascade guarantees no orphan deployments even
if a row is deleted out of band.

Revision ID: deploy_fk_cascade_v1
Revises: baseline_tables_v1
Create Date: 2026-06-13
"""
from typing import Sequence, Union

from alembic import op

revision: str = "deploy_fk_cascade_v1"
down_revision: Union[str, None] = "baseline_tables_v1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The baseline created these FKs unnamed; a naming convention lets batch mode
# (SQLite has no ALTER for FKs - it rebuilds the table) address them by name.
_NAMING = {"fk": "fk_%(table_name)s_%(column_0_name)s"}


def upgrade() -> None:
    with op.batch_alter_table("deployments", naming_convention=_NAMING) as b:
        b.drop_constraint("fk_deployments_tripwire_id", type_="foreignkey")
        b.drop_constraint("fk_deployments_endpoint_id", type_="foreignkey")
        b.create_foreign_key("fk_deployments_tripwire_id", "tripwires",
                             ["tripwire_id"], ["id"], ondelete="CASCADE")
        b.create_foreign_key("fk_deployments_endpoint_id", "endpoints",
                             ["endpoint_id"], ["id"], ondelete="CASCADE")


def downgrade() -> None:
    with op.batch_alter_table("deployments", naming_convention=_NAMING) as b:
        b.drop_constraint("fk_deployments_tripwire_id", type_="foreignkey")
        b.drop_constraint("fk_deployments_endpoint_id", type_="foreignkey")
        b.create_foreign_key("fk_deployments_tripwire_id", "tripwires",
                             ["tripwire_id"], ["id"])
        b.create_foreign_key("fk_deployments_endpoint_id", "endpoints",
                             ["endpoint_id"], ["id"])
