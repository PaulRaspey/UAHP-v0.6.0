"""Add post-quantum cryptography columns to agents table — UAHP v0.6.0

Revision ID: 20260402_pqc_upgrade
Revises: add_uahp_registry_agents_table
Create Date: 2026-04-02

This migration responds to Google's March 31, 2026 whitepaper showing
ECDLP-256 can be broken with ~1,200 logical qubits / 500,000 physical qubits.

Ed25519 and X25519 are elliptic curve primitives. They are on the threat list.
UAHP v0.6.0 adds hybrid PQC columns while keeping the classical columns
for backward compatibility during the 2026-2035 transition window.
"""

from alembic import op
import sqlalchemy as sa

revision = '20260402_pqc_upgrade'
down_revision = 'add_uahp_registry_agents_table'
branch_labels = None
depends_on = None


def upgrade():
    # New PQC key material columns
    op.add_column('agents', sa.Column(
        'kem_algorithm',
        sa.String(50),
        nullable=True,
        comment='Key encapsulation algorithm: X25519, ML-KEM-768, hybrid-x25519-ml-kem'
    ))
    op.add_column('agents', sa.Column(
        'key_algorithm',
        sa.String(50),
        nullable=True,
        comment='Signature algorithm: Ed25519, ML-DSA-65, ML-DSA-87, hybrid-ed25519-ml-dsa'
    ))
    op.add_column('agents', sa.Column(
        'pqc_public_key',
        sa.Text(),
        nullable=True,
        comment='Base64 ML-DSA public key for signature verification'
    ))
    op.add_column('agents', sa.Column(
        'pqc_kem_public_key',
        sa.Text(),
        nullable=True,
        comment='Base64 ML-KEM public key for key encapsulation'
    ))

    # Quantum compliance tracking
    op.add_column('agents', sa.Column(
        'quantum_compliant',
        sa.Boolean(),
        nullable=False,
        server_default='0',
        comment='True if agent uses hybrid or pure PQC mode'
    ))
    op.add_column('agents', sa.Column(
        'quantum_readiness_tier',
        sa.String(20),
        nullable=True,
        server_default='vulnerable',
        comment='vulnerable | transitioning | quantum_safe'
    ))
    op.add_column('agents', sa.Column(
        'crypto_suite',
        sa.String(20),
        nullable=True,
        server_default='legacy',
        comment='legacy | hybrid | pure_pqc'
    ))
    op.add_column('agents', sa.Column(
        'protocol_version',
        sa.String(10),
        nullable=True,
        server_default='0.5.4',
        comment='UAHP protocol version this agent registered with'
    ))
    op.add_column('agents', sa.Column(
        'pqc_upgraded_at',
        sa.DateTime(timezone=True),
        nullable=True,
        comment='When this agent upgraded to PQC support'
    ))

    # Backfill existing agents as legacy/vulnerable
    op.execute("""
        UPDATE agents
        SET
            kem_algorithm = 'X25519',
            key_algorithm = 'Ed25519',
            quantum_compliant = 0,
            quantum_readiness_tier = 'vulnerable',
            crypto_suite = 'legacy',
            protocol_version = '0.5.4'
        WHERE kem_algorithm IS NULL
    """)

    # Index for fast quantum-ready agent discovery
    # Allows SMART-UAHP to route sensitive tasks to quantum-safe agents first
    op.create_index('ix_agents_quantum_compliant', 'agents', ['quantum_compliant'])
    op.create_index('ix_agents_quantum_readiness_tier', 'agents', ['quantum_readiness_tier'])
    op.create_index('ix_agents_crypto_suite', 'agents', ['crypto_suite'])


def downgrade():
    op.drop_index('ix_agents_crypto_suite', table_name='agents')
    op.drop_index('ix_agents_quantum_readiness_tier', table_name='agents')
    op.drop_index('ix_agents_quantum_compliant', table_name='agents')

    op.drop_column('agents', 'pqc_upgraded_at')
    op.drop_column('agents', 'protocol_version')
    op.drop_column('agents', 'crypto_suite')
    op.drop_column('agents', 'quantum_readiness_tier')
    op.drop_column('agents', 'quantum_compliant')
    op.drop_column('agents', 'pqc_kem_public_key')
    op.drop_column('agents', 'pqc_public_key')
    op.drop_column('agents', 'key_algorithm')
    op.drop_column('agents', 'kem_algorithm')
