"""M4: investigations, investigation evidence and approval binding

Revision ID: a4c1e2f0b7d3
Revises: 5894789b61cf
Create Date: 2026-11-17 21:30:00
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a4c1e2f0b7d3"
down_revision: Union[str, None] = "5894789b61cf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("target_type", sa.String(), nullable=False),
        sa.Column("target_ref", sa.String(), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=True),
        sa.Column("objective", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("stage", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("report", sa.JSON(), nullable=True),
    )
    op.create_table(
        "investigation_evidence",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("investigation_id", sa.String(), nullable=False),
        sa.Column("source_tool", sa.String(), nullable=False),
        sa.Column("source_ref", sa.String(), nullable=False),
        sa.Column("trust", sa.String(), nullable=False),
        sa.Column("summary", sa.String(), nullable=False),
        sa.Column("content", sa.JSON(), nullable=False),
        sa.Column("limitations", sa.String(), nullable=False),
        sa.Column("retrieved_at", sa.String(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
    )
    op.create_index("ix_investigation_evidence_investigation_id",
                    "investigation_evidence", ["investigation_id"])

    with op.batch_alter_table("proposed_actions") as b:
        b.alter_column("incident_id", existing_type=sa.String(), nullable=True)
        b.add_column(sa.Column("investigation_id", sa.String(), nullable=True))
        b.add_column(sa.Column("args", sa.JSON(), nullable=True))
        b.add_column(sa.Column("payload_hash", sa.String(), nullable=True))
        b.add_column(sa.Column("proposed_by", sa.String(), nullable=True))
        b.add_column(sa.Column("status", sa.String(), nullable=False,
                               server_default="proposed"))
        b.add_column(sa.Column("version", sa.Integer(), nullable=False, server_default="1"))
        b.add_column(sa.Column("supersedes", sa.String(), nullable=True))
        b.add_column(sa.Column("reason", sa.String(), nullable=True))
        b.add_column(sa.Column("evidence_ids", sa.JSON(), nullable=True))
        b.add_column(sa.Column("limitations", sa.String(), nullable=True))
        b.add_column(sa.Column("created_at", sa.String(), nullable=True))
        b.add_column(sa.Column("executed_at", sa.String(), nullable=True))
        b.add_column(sa.Column("result", sa.JSON(), nullable=True))
        b.create_index("ix_proposed_actions_investigation_id", ["investigation_id"])

    with op.batch_alter_table("approvals") as b:
        b.alter_column("incident_id", existing_type=sa.String(), nullable=True)
        b.add_column(sa.Column("investigation_id", sa.String(), nullable=True))
        b.add_column(sa.Column("payload_hash", sa.String(), nullable=True))
        b.add_column(sa.Column("approver_role", sa.String(), nullable=True))
        b.add_column(sa.Column("consumed_at", sa.String(), nullable=True))
        b.create_index("ix_approvals_investigation_id", ["investigation_id"])


def downgrade() -> None:
    with op.batch_alter_table("approvals") as b:
        b.drop_index("ix_approvals_investigation_id")
        for col in ("consumed_at", "approver_role", "payload_hash", "investigation_id"):
            b.drop_column(col)
        b.alter_column("incident_id", existing_type=sa.String(), nullable=False)
    with op.batch_alter_table("proposed_actions") as b:
        b.drop_index("ix_proposed_actions_investigation_id")
        for col in ("result", "executed_at", "created_at", "limitations", "evidence_ids",
                    "reason", "supersedes", "version", "status", "proposed_by",
                    "payload_hash", "args", "investigation_id"):
            b.drop_column(col)
        b.alter_column("incident_id", existing_type=sa.String(), nullable=False)
    op.drop_index("ix_investigation_evidence_investigation_id", "investigation_evidence")
    op.drop_table("investigation_evidence")
    op.drop_table("investigations")
