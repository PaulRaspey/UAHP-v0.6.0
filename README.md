# UAHP v0.6.0 — Quantum-Resistant Edition

**Responding to Google's March 31, 2026 whitepaper.**

Google Quantum AI confirmed that ECDLP-256 — the mathematical foundation
of Ed25519 signatures and X25519 key exchange — can be broken with fewer
than 1,200 logical qubits and 500,000 physical qubits. That is a 20-fold
reduction from previous estimates. Google's migration deadline is 2029.

UAHP v0.5.4 uses Ed25519 and X25519. Both are on the threat list.

UAHP v0.6.0 adds hybrid post-quantum cryptography following NIST FIPS 203
and FIPS 204 while preserving full backward compatibility with v0.5.4 agents.

---

## The Hybrid Approach (2026–2035 Transition Window)

The hybrid model is the NIST, IETF, and Google recommended transition strategy:

- Keep Ed25519 + X25519 for backward compatibility
- Add ML-DSA-65 (NIST FIPS 204) for quantum-resistant signatures
- Add ML-KEM-768 (NIST FIPS 203) for quantum-resistant key exchange
- Combine both shared secrets via HKDF: `UAHP_SESSION_v0.6_HYBRID`
- Security guarantee: attacker must break BOTH classical AND PQC simultaneously

```
Combined Secret = HKDF(
    input   = X25519_shared_secret + ML-KEM-768_shared_secret,
    info    = b"UAHP_SESSION_v0.6_HYBRID",
    length  = 32
)
```

---

## New Files in This Release

| File | Purpose |
|------|---------|
| `uahp/schemas_v6.py` | PQC enums: KeyAlgorithm, KEMAlgorithm, QuantumReadinessTier |
| `uahp/session_v6.py` | SecureSession with hybrid handshake + graceful fallback |
| `uahp/verification_v6.py` | ML-DSA signature verification + keypair generation |
| `polis/quantum.py` | Quantum readiness component of POLIS Standing Score |
| `beacon/beacon_v6.py` | Beacon v1.1.0 with quantum readiness announcement |
| `migrations/20260402_pqc_upgrade.py` | Alembic migration for PQC columns |
| `demo_pqc_handshake.py` | Full demo: hybrid handshake + POLIS + beacon |

---

## Installation

```bash
# Core stack (classical only — v0.5.4 compatible)
pip install uahp

# Enable quantum resistance
pip install oqs-python

# Note: oqs-python requires liboqs system library
# macOS: brew install liboqs
# Ubuntu: apt install liboqs-dev
# Full docs: https://github.com/open-quantum-safe/liboqs-python
```

---

## Quick Start

```python
from uahp.session_v6 import SecureSessionV6
from uahp.schemas_v6 import KeyAlgorithm, KEMAlgorithm

alice = SecureSessionV6(
    agent_id="alice",
    public_key="alice_pub_base64",
    private_key=b"alice_private_key",
    key_algorithm=KeyAlgorithm.HYBRID_ED25519_ML_DSA,
    kem_algorithm=KEMAlgorithm.HYBRID_X25519_ML_KEM,
)

bob = SecureSessionV6(
    agent_id="bob",
    public_key="bob_pub_base64",
    private_key=b"bob_private_key",
)

alice_packet = alice.get_handshake_packet()
bob_packet = bob.get_handshake_packet()

success, secret = alice.derive_shared_secret(bob_packet)
# secret is 32 bytes derived from X25519 + ML-KEM-768 via HKDF
```

---

## Migration Timeline

| Phase | Version | Default Mode | When |
|-------|---------|-------------|------|
| Hybrid optional | v0.6.0 | Legacy (backward compat) | Now |
| Hybrid default | v0.7.0 | Hybrid | Q3 2026 |
| Hard requirement for regulated ops | v0.8.0 | Hybrid | 2029 |
| Pure PQC | v1.0.0 | ML-DSA + ML-KEM only | Post-2035 |

---

## POLIS Standing Score Impact

Quantum readiness is now a component of civil standing:

- **Vulnerable** (Ed25519/X25519 only): 10/100 quantum score
- **Transitioning** (hybrid mode): 75/100 quantum score
- **Quantum Safe** (pure PQC): 100/100 quantum score

Current weight: 5% of total Standing Score.
Will increase to 20% by 2029 (Google's migration deadline).

---

## NIST Standards

- **FIPS 203** — ML-KEM (Module Lattice Key Encapsulation Mechanism)
  Formerly Kyber. Replaces X25519 for key exchange.

- **FIPS 204** — ML-DSA (Module Lattice Digital Signature Algorithm)
  Formerly Dilithium. Replaces Ed25519 for signatures.

- **FIPS 205** — SLH-DSA (Stateless Hash-Based Digital Signature)
  Formerly SPHINCS+. Backup option, different mathematical foundation.

---

## The Threat

> "We have compiled two quantum circuits that implement Shor's algorithm
> for ECDLP-256: one that uses less than 1,200 logical qubits and 90
> million Toffoli gates... We estimate these circuits can be executed
> on a superconducting qubit CRQC with fewer than 500,000 physical
> qubits in a few minutes."
>
> — Google Quantum AI, March 31, 2026

UAHP was built to be the trust layer for the agentic economy.
Trust that cannot survive quantum computers is not trust.
We migrate now, while there is time.

---

## License

MIT. Part of the continuation of the universal project of knowing itself.

## Author

Paul Raspey — Greenville, Texas
github.com/PaulRaspey
