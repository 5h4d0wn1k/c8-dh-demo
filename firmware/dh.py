#!/usr/bin/env python3
"""C8 - Diffie-Hellman Demo

DH key exchange implementation, MITM demo, parameter analysis.
Uses hashlib, secrets, pow only.
"""

import hashlib
import secrets
import sys

# RFC 3526 Group 14 (2048-bit MODP) prime
P2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
G2048 = 2


def modexp(base, exp, mod):
    return pow(base, exp, mod)


def gen_private_key(bits=256):
    return secrets.randbits(bits)


def gen_public_key(private, g=G2048, p=P2048):
    return modexp(g, private, p)


def derive_shared(their_public, my_private, p=P2048):
    return modexp(their_public, my_private, p)


def kdf(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).hexdigest()


def keystring(shared):
    return hashlib.sha256(shared.to_bytes((shared.bit_length() + 7) // 8 or 1, "big")).hexdigest()


def dh_exchange(p=P2048, g=G2048, label=""):
    a_priv = gen_private_key()
    b_priv = gen_private_key()
    A = gen_public_key(a_priv, g, p)
    B = gen_public_key(b_priv, g, p)

    s_a = derive_shared(B, a_priv, p)
    s_b = derive_shared(A, b_priv, p)

    match = s_a == s_b
    k_a = keystring(s_a)
    k_b = keystring(s_b)

    lines = []
    lines.append("=== Diffie-Hellman Key Exchange%s ===" % (" [%s]" % label if label else ""))
    lines.append("p (prime, %d bits): ...%s" % (p.bit_length(), hex(p)[-12:]))
    lines.append("g (generator): %d" % g)
    lines.append("")
    lines.append("Private keys (secret):")
    lines.append("  a (Alice): %d bits" % a_priv.bit_length())
    lines.append("  b (Bob):   %d bits" % b_priv.bit_length())
    lines.append("")
    lines.append("Public keys (sent over channel):")
    lines.append("  A (Alice): ...%s" % hex(A)[-12:])
    lines.append("  B (Bob):   ...%s" % hex(B)[-12:])
    lines.append("")
    lines.append("Shared secrets:")
    lines.append("  s_a == s_b? %s" % match)
    lines.append("  Session key (SHA256): %s" % k_a)
    return lines, s_a, (A, B), (a_priv, b_priv)


def mitm_demo(p=P2048, g=G2048):
    """Demonstrate a man-in-the-middle attack where Mallory establishes
    independent keys with Alice and Bob."""
    lines = []
    lines.append("=== Man-in-the-Middle Demonstration ===")
    lines.append("Mallory intercepts and relays, creating two keys.")

    a_priv = gen_private_key()
    b_priv = gen_private_key()
    m_priv = gen_private_key()

    A = gen_public_key(a_priv, g, p)   # Alice's public
    B = gen_public_key(b_priv, g, p)   # Bob's public
    M = gen_public_key(m_priv, g, p)   # Mallory's forged public

    # Alice thinks she's talking to Bob, but receives Mallory's key
    s_alice = derive_shared(M, a_priv, p)  # Alice-Mallory key
    s_bob = derive_shared(M, b_priv, p)    # Bob-Mallory key
    s_m_a = derive_shared(A, m_priv, p)
    s_m_b = derive_shared(B, m_priv, p)

    lines.append("Alice's computed key:  %s" % keystring(s_alice))
    lines.append("Bob's computed key:    %s" % keystring(s_bob))
    lines.append("Mallory's key w/Alice: %s" % keystring(s_m_a))
    lines.append("Mallory's key w/Bob:   %s" % keystring(s_m_b))

    alice_convinced = s_alice == s_m_a
    bob_convinced = s_bob == s_m_b
    both_same = s_alice == s_bob

    lines.append("")
    lines.append("Alice & Mallory agree: %s" % alice_convinced)
    lines.append("Bob & Mallory agree:   %s" % bob_convinced)
    lines.append("Alice & Bob share SAME key: %s" % both_same)
    lines.append("")
    lines.append("=> Alice and Bob each have a key with Mallory, but")
    lines.append("   NOT with each other. Mallory can decrypt/forward.")
    return lines


def analyze_parameters(p=P2048, g=G2048):
    lines = []
    lines.append("=== Parameter Analysis ===")
    lines.append("Prime p bit-length: %d" % p.bit_length())
    lines.append("Generator g: %d" % g)
    lines.append("g < p: %s" % (g < p))
    n = p - 1
    lines.append("p is odd: %s" % (p % 2 == 1))
    lines.append("p not even: %s" % (p % 2 == 1))
    # small prime factor check of p-1 / 2
    q = n // 2
    lines.append("q = (p-1)/2 bit-length: %d" % q.bit_length())
    lines.append("(p-1)/2 even (safe prime check): %s" % (q % 2 == 0))
    return lines


def main():
    print("Running Diffie-Hellman with RFC 3526 Group 14 (2048-bit).\n")
    lines, shared, pubs, privs = dh_exchange()
    print("\n".join(lines))

    print("\n" + "-" * 60)
    print("\n".join(mitm_demo()))

    print("\n" + "-" * 60)
    print("\n".join(analyze_parameters()))

    # small-prime demo for clarity/education
    print("\n" + "-" * 60)
    print("\n=== Small-Prime Example (education) ===")
    p_small = 23
    g_small = 5
    a = 6
    b = 15
    A = modexp(g_small, a, p_small)
    B = modexp(g_small, b, p_small)
    print("p=23, g=5, Alice priv=6, Bob priv=15")
    print("Alice pub  = 5^6 mod 23 = %d" % A)
    print("Bob pub    = 5^15 mod 23 = %d" % B)
    print("Alice key  = B^6 mod 23 = %d" % modexp(B, a, p_small))
    print("Bob key    = A^15 mod 23 = %d" % modexp(A, b, p_small))
    return 0


if __name__ == "__main__":
    sys.exit(main())
