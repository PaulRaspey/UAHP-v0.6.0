Consolidated into github.com/PaulRaspey/uahp. Archived for history; tags remain browsable.

# UAHP v0.6.0 — Hybrid PQC-Ready Edition

**Responding to Google's March 31, 2026 whitepaper.**

Google Quantum AI confirmed that ECDLP-256 — the mathematical foundation
of Ed25519 signatures and X25519 key exchange — can be broken with fewer
than 1,200 logical qubits and 500,000 physical qubits. That is a 20-fold
reduction from previous estimates. Google's migration deadline is 2029.

UAHP v0.5.4 uses Ed25519 and X25519. Both are on the threat list.

UAHP v0.6.0 adds hybrid post-quantum cryptography following NIST FIPS 203
and FIPS 204, behind a tested feature flag.

---

## Honest Security Status

Read this before anything else. We say exactly what runs and what doesn't.

| Component | Status |
|-----------|--------|
| Ed25519 packet signatures | **Real, always on.** Verified with the signer's public key. |
| X25519 + HKDF key exchange | **Real, always on.** Both sides derive the same 32-byte secret. |
| ML-KEM-768 key exchange | **Runs only when `oqs-python` + liboqs are installed.** Proper encapsulate/decapsulate roles; secret equality is asserted in `test_kem_flow.py`. |
| ML-DSA-65 signatures | **Runs only when `oqs-python` + liboqs are installed.** |
| Silent fallback | **Removed.** Requesting a hybrid/PQC suite without oqs raises `PQCUnavailableError` with install instructions. Every packet carries an explicit `crypto_mode` field; suite mismatches are hard errors. |

Accurate one-line claim: *hybrid PQC-ready design; Ed25519/X25519 today,
ML-KEM-768/ML-DSA-65 behind a tested feature flag.*

This code has **not** been externally audited. Do not use it to protect
high-value secrets yet.

---

## The Hybrid Approach (2026–2035 Transition Window)

The hybrid model is the NIST, IETF, and Google recommended transition strategy:

- Keep Ed25519 + X25519 (real, tested, classical)
- Add ML-DSA-65 (NIST FIPS 204) signatures when oqs is installed
- Add ML-KEM-768 (NIST FIPS 203) key encapsulation when oqs is installed
- Combine both shared secrets via HKDF: `UAHP_SESSION_v0.6_HYBRID`
- Security property: attacker must break BOTH classical AND PQC simultaneously

```
Combined Secret = HKDF(
    input   = X25519_shared_secret + ML-KEM-768_shared_secret,
    info    = b"UAHP_SESSION_v0.6_HYBRID",
    length  = 32
)
```

### KEM roles (fixed in this release)

Key encapsulation is asymmetric — the two sides do different things:

1. The **initiator** encapsulates to the responder's ML-KEM-768 public
   key, producing a ciphertext and a shared secret.
2. The ciphertext is **transmitted** to the responder.
3. The **responder** decapsulates with its ML-KEM-768 private key and
   recovers the same shared secret.

Earlier v0.6.0 builds had both sides encapsulating, which derives two
different secrets; the bug was masked by a silent classical fallback.
Both the bug and the fallback are gone. `test_kem_flow.py` asserts
secret equality on every run.

---

## Files

| File | Purpose |
|------|---------|
| `schemas_v6.py` | PQC enums: KeyAlgorithm, KEMAlgorithm, QuantumReadinessTier |
| `session_v6.py` | SecureSession: Ed25519 + X25519 always; hybrid ML-KEM/ML-DSA behind feature flag |
| `verification_v6.py` | Signature verification + PQC keypair generation |
| `quantum.py` | Quantum readiness component of POLIS Standing Score |
| `beacon_v6.py` | Beacon v1.1.0 with crypto-suite announcement |
| `test_kem_flow.py` | Proves secret equality, tamper rejection, no-silent-fallback |
| `demo_pqc_handshake.py` | Full demo: handshake + POLIS + beacon |

---

## Installation

```bash
# Classical suite (Ed25519 + X25519) — works everywhere
pip install cryptography

# Optional PQC feature flag (ML-KEM-768 + ML-DSA-65)
# macOS:  brew install liboqs && pip install liboqs-python
# Ubuntu: apt install liboqs-dev && pip install liboqs-python
# Docs:   https://github.com/open-quantum-safe/liboqs-python
```

---

## Quick Start

```python
from session_v6 import SecureSessionV6
from schemas_v6 import KeyAlgorithm, KEMAlgorithm

# Keys are generated internally (real Ed25519). With oqs installed,
# the default suite is hybrid; without oqs, requesting hybrid RAISES.
alice = SecureSessionV6(agent_id="alice")   # initiator
bob = SecureSessionV6(agent_id="bob")       # responder

alice_packet = alice.get_handshake_packet()
bob_packet = bob.get_handshake_packet()

# Distinct roles: initiator encapsulates, responder decapsulates.
ok_a, secret_a, kem_ciphertext = alice.initiate_key_exchange(bob_packet)
ok_b, secret_b = bob.complete_key_exchange(alice_packet, kem_ciphertext)

assert secret_a == secret_b  # asserted in test_kem_flow.py on every run
```

Explicit classical-only mode (no quantum-resistance claim):

```python
alice = SecureSessionV6(
    agent_id="alice",
    key_algorithm=KeyAlgorithm.ED25519,
    kem_algorithm=KEMAlgorithm.X25519,
)
```

---

## Migration Timeline

| Phase | Version | Default Mode | When |
|-------|---------|-------------|------|
| Hybrid behind feature flag | v0.6.x | Classical (explicit) | Now |
| Hybrid default where oqs present | v0.7.0 | Hybrid | Q3 2026 |
| Hard requirement for regulated ops | v0.8.0 | Hybrid | 2029 |
| Pure PQC | v1.0.0 | ML-DSA + ML-KEM only | Post-2035 |

---

## POLIS Standing Score Impact

Crypto posture is a component of civil standing:

- **Vulnerable** (Ed25519/X25519 only): 10/100 quantum score
- **Transitioning** (hybrid mode actually running): 75/100 quantum score
- **Quantum Safe** (pure PQC): 100/100 quantum score

The score reflects `crypto_mode` — what actually runs, not what is aspired to.

---

## NIST Standards

- **FIPS 203** — ML-KEM (Module Lattice Key Encapsulation Mechanism).
  Formerly Kyber.
- **FIPS 204** — ML-DSA (Module Lattice Digital Signature Algorithm).
  Formerly Dilithium.
- **FIPS 205** — SLH-DSA (Stateless Hash-Based Digital Signature).
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
We migrate now, while there is time — and we do not claim resistance
we have not shipped.

---

## License

MIT. Part of the continuation of the universal project of knowing itself.

## Author

Paul Raspey — Greenville, Texas
github.com/PaulRaspey
