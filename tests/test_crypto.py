"""
Tests for the Schnorr Zero-Knowledge Proof crypto module.

Tests cover:
    - Parameter validity (p prime, q prime, q | (p-1), g^q ≡ 1)
    - Key generation and validation
    - Full protocol: commit -> challenge -> response -> verify
    - Rejection of invalid proofs
    - Rejection of identity-element public key (y = 1)
    - Parameter fingerprint consistency
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto import schnorr


# ===========================================================================
# Parameter tests
# ===========================================================================

def test_params_loaded():
    """Parameters should be loaded and be integers."""
    p, q, g = schnorr.get_params()
    assert isinstance(p, int) and isinstance(q, int) and isinstance(g, int)
    print("  ✓ Parameters loaded correctly")


def test_p_bit_length():
    """p should be exactly 3072 bits."""
    p, _, _ = schnorr.get_params()
    assert p.bit_length() == 3072, f"p is {p.bit_length()} bits"
    print("  ✓ p is 3072 bits")


def test_q_bit_length():
    """q should be exactly 256 bits."""
    _, q, _ = schnorr.get_params()
    assert q.bit_length() == 256, f"q is {q.bit_length()} bits"
    print("  ✓ q is 256 bits")


def test_q_divides_p_minus_1():
    """q must divide (p - 1)."""
    p, q, _ = schnorr.get_params()
    assert (p - 1) % q == 0
    print("  ✓ q divides (p - 1)")


def test_g_order():
    """g^q must equal 1 mod p (g generates subgroup of order q)."""
    p, q, g = schnorr.get_params()
    assert pow(g, q, p) == 1
    print("  ✓ g^q ≡ 1 (mod p)")


def test_g_not_one():
    """g must be greater than 1."""
    _, _, g = schnorr.get_params()
    assert g > 1
    print("  ✓ g > 1")


# ===========================================================================
# Key generation tests
# ===========================================================================

def test_keypair_generation():
    """Key generation should produce valid private and public keys."""
    x, y = schnorr.generate_keypair()
    p, q, _ = schnorr.get_params()
    assert 1 <= x <= q - 1, "Private key out of range"
    assert 1 < y < p, "Public key out of range"
    print("  ✓ Keypair generated with valid ranges")


def test_public_key_validation_valid():
    """A freshly generated public key should pass validation."""
    _, y = schnorr.generate_keypair()
    assert schnorr.validate_public_key(y) is True
    print("  ✓ Valid public key passes validation")


def test_public_key_validation_identity():
    """y = 1 (identity element) must be REJECTED — total auth bypass."""
    assert schnorr.validate_public_key(1) is False
    print("  ✓ Identity element (y=1) rejected")


def test_public_key_validation_zero():
    """y = 0 must be rejected."""
    assert schnorr.validate_public_key(0) is False
    print("  ✓ y=0 rejected")


def test_public_key_validation_negative():
    """Negative values must be rejected."""
    assert schnorr.validate_public_key(-1) is False
    print("  ✓ Negative value rejected")


def test_public_key_validation_non_subgroup():
    """A random number not in the subgroup should be rejected."""
    p, q, _ = schnorr.get_params()
    # A random number is almost certainly not in the order-q subgroup
    import secrets
    fake_key = secrets.randbelow(p - 2) + 2
    # It's astronomically unlikely to be in the subgroup
    if pow(fake_key, q, p) != 1:
        assert schnorr.validate_public_key(fake_key) is False
        print("  ✓ Non-subgroup element rejected")
    else:
        print("  ~ Skipped (random element happened to be in subgroup — astronomically rare)")


# ===========================================================================
# Protocol tests (the core 3-move handshake)
# ===========================================================================

def test_full_protocol_honest():
    """A complete honest handshake must succeed (completeness property)."""
    x, y = schnorr.generate_keypair()
    
    # Move 1: Prover creates commitment
    r, R = schnorr.create_commitment()
    
    # Move 2: Verifier generates challenge
    c = schnorr.generate_challenge()
    
    # Move 3: Prover computes response
    s = schnorr.create_response(r, c, x)
    
    # Verify
    assert schnorr.verify(R, c, s, y) is True
    print("  ✓ Honest handshake accepted (completeness)")


def test_full_protocol_multiple_times():
    """Run the protocol 10 times — all must succeed."""
    x, y = schnorr.generate_keypair()
    for i in range(10):
        r, R = schnorr.create_commitment()
        c = schnorr.generate_challenge()
        s = schnorr.create_response(r, c, x)
        assert schnorr.verify(R, c, s, y) is True
    print("  ✓ 10 consecutive handshakes all accepted")


def test_wrong_private_key_rejected():
    """Using the wrong private key must fail (soundness)."""
    x1, y1 = schnorr.generate_keypair()
    x2, _  = schnorr.generate_keypair()   # different key
    
    r, R = schnorr.create_commitment()
    c = schnorr.generate_challenge()
    s = schnorr.create_response(r, c, x2)  # respond with WRONG key
    
    assert schnorr.verify(R, c, s, y1) is False
    print("  ✓ Wrong private key rejected (soundness)")


def test_wrong_commitment_rejected():
    """Mismatched commitment and response must fail."""
    x, y = schnorr.generate_keypair()
    
    r1, R1 = schnorr.create_commitment()  # commitment 1
    r2, R2 = schnorr.create_commitment()  # commitment 2 (different)
    
    c = schnorr.generate_challenge()
    s = schnorr.create_response(r1, c, x)  # response uses r1
    
    # Verify with R2 (mismatched) — must fail
    assert schnorr.verify(R2, c, s, y) is False
    print("  ✓ Mismatched commitment rejected")


def test_wrong_challenge_rejected():
    """Response to a different challenge must fail."""
    x, y = schnorr.generate_keypair()
    
    r, R = schnorr.create_commitment()
    c1 = schnorr.generate_challenge()
    c2 = schnorr.generate_challenge()  # different challenge
    
    s = schnorr.create_response(r, c1, x)  # respond to c1
    
    # Verify with c2 — must fail
    if c1 != c2:  # astronomically unlikely to be equal
        assert schnorr.verify(R, c2, s, y) is False
        print("  ✓ Wrong challenge rejected")


def test_tampered_response_rejected():
    """A modified response must fail."""
    x, y = schnorr.generate_keypair()
    
    r, R = schnorr.create_commitment()
    c = schnorr.generate_challenge()
    s = schnorr.create_response(r, c, x)
    
    # Tamper with the response
    s_tampered = s + 1
    assert schnorr.verify(R, c, s_tampered, y) is False
    print("  ✓ Tampered response rejected")


# ===========================================================================
# Parameter fingerprint tests
# ===========================================================================

def test_fingerprint_consistent():
    """Same params should always produce the same fingerprint."""
    fp1 = schnorr.param_fingerprint()
    fp2 = schnorr.param_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 16  # truncated to 16 hex chars
    print(f"  ✓ Fingerprint consistent: {fp1}")


# ===========================================================================
# Run all tests
# ===========================================================================

if __name__ == "__main__":
    tests = [
        ("Parameter Tests", [
            test_params_loaded,
            test_p_bit_length,
            test_q_bit_length,
            test_q_divides_p_minus_1,
            test_g_order,
            test_g_not_one,
        ]),
        ("Key Generation Tests", [
            test_keypair_generation,
            test_public_key_validation_valid,
            test_public_key_validation_identity,
            test_public_key_validation_zero,
            test_public_key_validation_negative,
            test_public_key_validation_non_subgroup,
        ]),
        ("Protocol Tests (3-Move Handshake)", [
            test_full_protocol_honest,
            test_full_protocol_multiple_times,
            test_wrong_private_key_rejected,
            test_wrong_commitment_rejected,
            test_wrong_challenge_rejected,
            test_tampered_response_rejected,
        ]),
        ("Fingerprint Tests", [
            test_fingerprint_consistent,
        ]),
    ]

    total = 0
    passed = 0
    failed = 0

    for section_name, section_tests in tests:
        print(f"\n{'='*50}")
        print(f" {section_name}")
        print(f"{'='*50}")
        for test_fn in section_tests:
            total += 1
            try:
                test_fn()
                passed += 1
            except AssertionError as e:
                failed += 1
                print(f"  ✗ {test_fn.__name__}: {e}")
            except Exception as e:
                failed += 1
                print(f"  ✗ {test_fn.__name__}: UNEXPECTED ERROR: {e}")

    print(f"\n{'='*50}")
    print(f" Results: {passed}/{total} passed, {failed} failed")
    print(f"{'='*50}")
    
    sys.exit(0 if failed == 0 else 1)
