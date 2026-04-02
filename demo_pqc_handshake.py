"""
UAHP v0.6.0 Demo: Quantum-Resistant Handshake
Shows the full hybrid handshake between two agents.
Runs with or without oqs-python (falls back to classical if not installed).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from uahp.session_v6 import SecureSessionV6
from uahp.schemas_v6 import KeyAlgorithm, KEMAlgorithm
from uahp.verification_v6 import quantum_readiness_summary
from polis.quantum import QuantumReadinessScore, inject_quantum_into_standing
from beacon.beacon_v6 import get_beacon_dict


def run_demo():
    print("=" * 65)
    print("UAHP v0.6.0 — Quantum-Resistant Handshake Demo")
    print("=" * 65)
    print()

    # Show quantum readiness of this system
    summary = quantum_readiness_summary()
    print("SYSTEM QUANTUM READINESS:")
    print(f"  oqs-python available: {summary['oqs_available']}")
    print(f"  Supported KEMs: {', '.join(summary['supported_kems'])}")
    print(f"  Supported signatures: {', '.join(summary['supported_signatures'][:3])}...")
    print(f"  Threat: {summary['quantum_threat']}")
    print(f"  Status: {summary['recommended_action']}")
    print()

    # Create two agents
    print("CREATING AGENTS...")
    alice = SecureSessionV6(
        agent_id="alice-quantum",
        public_key="alice_ed25519_pub_base64",
        private_key=b"alice_private_key_32bytes_padding",
        key_algorithm=KeyAlgorithm.HYBRID_ED25519_ML_DSA,
        kem_algorithm=KEMAlgorithm.HYBRID_X25519_ML_KEM,
    )

    bob = SecureSessionV6(
        agent_id="bob-quantum",
        public_key="bob_ed25519_pub_base64",
        private_key=b"bob_private_key_32bytes_paddingg",
        key_algorithm=KeyAlgorithm.HYBRID_ED25519_ML_DSA,
        kem_algorithm=KEMAlgorithm.HYBRID_X25519_ML_KEM,
    )

    print(f"  Alice crypto suite: {alice.crypto_suite}")
    print(f"  Alice quantum compliant: {alice.quantum_compliant}")
    print(f"  Bob crypto suite: {bob.crypto_suite}")
    print(f"  Bob quantum compliant: {bob.quantum_compliant}")
    print()

    # Exchange handshake packets
    print("HANDSHAKE EXCHANGE...")
    alice_packet = alice.get_handshake_packet()
    bob_packet = bob.get_handshake_packet()

    print(f"  Alice packet fields: {list(alice_packet.keys())}")
    print(f"  Has PQC key: {'pqc_public_key' in alice_packet}")
    print(f"  Protocol version: {alice_packet['protocol_version']}")
    print()

    # Derive shared secrets
    print("DERIVING SHARED SECRETS...")
    alice_success, alice_secret = alice.derive_shared_secret(bob_packet)
    bob_success, bob_secret = bob.derive_shared_secret(alice_packet)

    print(f"  Alice success: {alice_success}")
    print(f"  Bob success: {bob_success}")

    if alice_secret and bob_secret:
        secrets_match = alice_secret == bob_secret
        print(f"  Secrets match: {secrets_match}")
        print(f"  Secret (hex): {alice_secret.hex()[:32]}...")
        print(f"  HKDF info: UAHP_SESSION_v0.6_HYBRID")
    print()

    # POLIS quantum standing
    print("POLIS QUANTUM STANDING...")
    agent_identity = {
        "crypto_suite": alice.crypto_suite,
        "key_algorithm": alice.key_algorithm.value,
        "kem_algorithm": alice.kem_algorithm.value,
        "quantum_compliant": alice.quantum_compliant,
    }

    q_score = QuantumReadinessScore.score(**{
        k: agent_identity.get(k)
        for k in ["crypto_suite", "key_algorithm", "kem_algorithm", "quantum_compliant"]
    })
    print(f"  Quantum readiness score: {q_score} / 100")
    print(f"  Label: {QuantumReadinessScore.standing_label(q_score)}")
    print(f"  Advisory: {QuantumReadinessScore.threat_advisory(alice.crypto_suite)[:80]}...")
    print()

    # Beacon
    print("BEACON PAYLOAD (embedded in every handshake)...")
    beacon = get_beacon_dict(agent_id="alice-quantum", crypto_suite=alice.crypto_suite)
    print(f"  Beacon version: {beacon['beacon_version']}")
    print(f"  Quantum KEM: {beacon['quantum']['recommended_kem']}")
    print(f"  Quantum Signature: {beacon['quantum']['recommended_signature']}")
    print(f"  Google timeline: {beacon['quantum']['google_timeline']}")
    print()

    print("=" * 65)
    print("UAHP v0.6.0 SUMMARY")
    print("=" * 65)
    print()
    print(f"  Handshake: {'Hybrid (Classical + PQC)' if alice.quantum_compliant else 'Classical only (install oqs-python for PQC)'}")
    print(f"  KEM: {'X25519 + ML-KEM-768' if alice.quantum_compliant else 'X25519 only'}")
    print(f"  Signatures: {'Ed25519 + ML-DSA-65' if alice.quantum_compliant else 'Ed25519 only'}")
    print(f"  HKDF: {'UAHP_SESSION_v0.6_HYBRID' if alice.quantum_compliant else 'UAHP_SESSION_v0.5'}")
    print(f"  Quantum threat: ECDLP-256 breakable with ~1,200 logical qubits")
    print(f"  Google migration deadline: 2029")
    print(f"  NIST standards: FIPS 203 (ML-KEM) + FIPS 204 (ML-DSA)")
    print()
    if not alice.quantum_compliant:
        print("  To enable full quantum resistance:")
        print("  pip install oqs-python")
        print("  (requires liboqs system library)")
        print("  https://github.com/open-quantum-safe/liboqs-python")


if __name__ == "__main__":
    run_demo()
