"""
schnorr.py — Shared Schnorr Zero-Knowledge Identification Protocol Module

Implements the three-move sigma protocol (commit -> challenge -> response)
over a discrete logarithm group with NIST-recommended parameters (L=3072, N=256).

This module is shared between prover (client) and verifier (server)
to prevent implementation drift, as recommended by the MobileBank-ZKP paper.

Protocol summary (Table 1 from the paper):
    Move 1 (Prover):   r <- [1, q-1],  R = g^r mod p        -> send R
    Move 2 (Verifier):                                       <- send c (256-bit random)
    Move 3 (Prover):   s = (r + c*x) mod q                  -> send s
    Verify:            accept iff g^s ≡ R * y^c (mod p)

Reference: Schnorr, C.P., "Efficient identification and signatures for smart cards", 1989
"""

import secrets
import hashlib
from crypto.params import P, Q, G


# ---------------------------------------------------------------------------
# Parameter access
# ---------------------------------------------------------------------------

def get_params():
    """Return the group parameters (p, q, g)."""
    return P, Q, G


def param_fingerprint():
    """
    Compute a truncated SHA-256 fingerprint of the group parameters.
    
    Used to detect parameter changes — if a client's stored fingerprint
    doesn't match the server's, the client must re-enroll instead of
    experiencing silent, inexplicable authentication failures.
    """
    data = f"{P}:{Q}:{G}".encode()
    return hashlib.sha256(data).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair():
    """
    Generate a Schnorr keypair.
    
    Private key:  x  chosen uniformly from [1, q-1]
    Public key:   y = g^x mod p
    
    The private key NEVER leaves the device.
    The public key is the ONLY thing sent to the server.
    
    Returns:
        (x, y) — (private_key, public_key)
    """
    x = secrets.randbelow(Q - 1) + 1       # x ∈ [1, q-1]
    y = pow(G, x, P)                        # y = g^x mod p
    return x, y


# ---------------------------------------------------------------------------
# Public key validation (CRITICAL — server must do this at registration)
# ---------------------------------------------------------------------------

def validate_public_key(y):
    """
    Validate a public key before accepting registration.
    
    Checks (Equation 5 from the paper):
        1. 1 < y < p-1       (reject identity element and trivial values)
        2. y^q ≡ 1 (mod p)   (confirm subgroup membership)
    
    WHY THIS MATTERS:
        If y = 1 (identity element), the verification equation becomes:
            g^s ≡ R * 1^c = R  (mod p)
        which is satisfied by s = r — the value the prover already has
        WITHOUT knowing any secret. This is a TOTAL authentication bypass.
    
    Args:
        y: the public key to validate
        
    Returns:
        True if the key is valid and safe to store
    """
    if not isinstance(y, int) or y <= 1 or y >= P - 1:
        return False
    
    # Subgroup membership: y must be in the order-q subgroup
    if pow(y, Q, P) != 1:
        return False
    
    return True


# ---------------------------------------------------------------------------
# Prover functions (run on the client/device)
# ---------------------------------------------------------------------------

def create_commitment():
    """
    Prover — Move 1: Create a commitment.
    
    Choose a random nonce r ∈ [1, q-1]  (this is SECRET — never sent!)
    Compute R = g^r mod p               (this IS sent to the verifier)
    
    Returns:
        (r, R) — r must be kept secret until response computation,
                  R is sent to the server
    """
    r = secrets.randbelow(Q - 1) + 1       # random nonce
    R = pow(G, r, P)                        # commitment
    return r, R


def create_response(r, c, x):
    """
    Prover — Move 3: Compute the response to the verifier's challenge.
    
    s = (r + c * x) mod q
    
    This is a single modular multiply + add — effectively free (~0.001 ms).
    
    Args:
        r: the secret nonce from create_commitment()
        c: the challenge received from the verifier
        x: the prover's private key
    
    Returns:
        s — the response (sent to the server)
    """
    s = (r + c * x) % Q
    return s


# ---------------------------------------------------------------------------
# Verifier functions (run on the server)
# ---------------------------------------------------------------------------

def generate_challenge():
    """
    Verifier — Move 2: Generate a random 256-bit challenge.
    
    c is chosen uniformly from [0, q-1].
    
    A single correct guess has probability 2^(-256) ≈ 8.6 × 10^(-78),
    which is the soundness error of the protocol.
    
    Returns:
        c — the challenge (sent to the prover)
    """
    c = secrets.randbelow(Q)
    return c


def verify(R, c, s, y):
    """
    Verifier: Check whether the proof is valid.
    
    Accept iff:  g^s ≡ R * y^c  (mod p)
    
    Completeness proof (why this works for an honest prover):
        g^s = g^(r + cx)           [substituting s = r + cx]
            = g^r * (g^x)^c       [exponent rules]
            = R * y^c   (mod p)   [since R = g^r and y = g^x]
    
    Soundness: if an adversary can answer two distinct challenges c1 ≠ c2
    for the same commitment R, then:
        x = (s1 - s2) * (c1 - c2)^(-1)  mod q
    i.e., they can extract the discrete logarithm — assumed intractable.
    
    Args:
        R: commitment from the prover
        c: challenge from the verifier
        s: response from the prover
        y: the prover's registered public key
    
    Returns:
        True if the proof is valid (the prover knows the private key)
    """
    # Left side: g^s mod p
    lhs = pow(G, s, P)
    
    # Right side: R * y^c mod p
    rhs = (R * pow(y, c, P)) % P
    
    return lhs == rhs
