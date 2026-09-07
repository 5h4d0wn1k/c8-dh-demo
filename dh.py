#!/usr/bin/env python3
"""C8 - Diffie-Hellman Demo

DH key exchange (RFC 3526 Group 14), man-in-the-middle demonstration,
and parameter analysis. Stdlib only: hashlib, secrets, argparse.

For education and authorized lab testing only - see README.
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple

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
    """Modular exponentiation: base**exp mod mod."""
    return pow(base, exp, mod)


def gen_private_key(bits=256):
    """Cryptographically random private exponent using secrets."""
    return secrets.randbits(bits)


def gen_public_key(private, g=G2048, p=P2048):
    """Public key A = g**a (mod p)."""
    return modexp(g, private, p)


def derive_shared(their_public, my_private, p=P2048):
    """Shared secret s = their_public**my_private (mod p)."""
    return modexp(their_public, my_private, p)


def kdf(shared_secret):
    """Derive a session key from a shared secret: SHA-256 of big-endian bytes."""
    raw = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8 or 1, "big")
    return hashlib.sha256(raw).hexdigest()


def is_probable_prime(n, rounds=32):
    """Miller-Rabin probable-prime test with random bases (secrets)."""
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_safe_prime(p):
    """True if both p and (p-1)/2 are prime (Sophie Germain structure)."""
    return is_probable_prime(p) and is_probable_prime((p - 1) // 2)


def generator_ok(g, p):
    """Sanity-check g for use as a DH generator.

    For safe prime p = 2q + 1 (q prime) the group order is 2q, so the
    possible element orders are 1, 2, q and 2q. Both a generator of the
    prime-order subgroup (order q, e.g. quadratic residues) and a
    primitive root (order 2q) are acceptable for DH; g = p-1 (order 2)
    is only acceptable for teaching with tiny primes.
    """
    if g < 2 or g >= p:
        return {'ok': False, 'reason': 'g must satisfy 2 <= g < p'}
    if p < 5 or p % 2 == 0:
        return {'ok': False, 'reason': 'p must be an odd prime >= 5'}
    q = (p - 1) // 2
    if not is_probable_prime(p):
        return {'ok': False, 'reason': 'p is not prime'}
    if not is_probable_prime(q):
        return {'ok': True, 'reason': 'p prime; g in [2,p); (p-1)/2 not prime so order check skipped'}
    if g % p == p - 1:
        return {'ok': True, 'reason': 'g = p-1 has order 2 (use only for small worked examples)'}
    if g != 1 and pow(g, q, p) == 1:
        return {'ok': True,
                'reason': f'g generates the prime-order subgroup (order q, {q.bit_length()} bits)'}
    if pow(g, 2, p) != 1 and pow(g, q, p) != 1 and pow(g, p - 1, p) == 1:
        return {'ok': True, 'reason': 'g is a primitive root (order p-1)'}
    if pow(g, 2, p) == 1:
        return {'ok': False, 'reason': 'g has order 2 (bad, group of size 2)'}
    return {'ok': False, 'reason': 'g has reduced order; not suitable'}


def dh_exchange(p=P2048, g=G2048):
    """Full key exchange. Returns a report dict (values, no secrets leaked)."""
    a_priv = gen_private_key()
    b_priv = gen_private_key()
    A = gen_public_key(a_priv, g, p)
    B = gen_public_key(b_priv, g, p)
    s_a = derive_shared(B, a_priv, p)
    s_b = derive_shared(A, b_priv, p)
    return {
        'p_bits': p.bit_length(),
        'g': g,
        'a_bits': a_priv.bit_length(),
        'b_bits': b_priv.bit_length(),
        'public_a_tail': hex(A)[-12:],
        'public_b_tail': hex(B)[-12:],
        'shared_equal': s_a == s_b,
        'session_key': kdf(s_a),
    }


def mitm_demo(p=P2048, g=G2048):
    """MITM: Mallory negotiates independent keys with Alice and Bob."""
    a_priv = gen_private_key()
    b_priv = gen_private_key()
    m_priv = gen_private_key()
    A = gen_public_key(a_priv, g, p)
    B = gen_public_key(b_priv, g, p)
    M = gen_public_key(m_priv, g, p)

    s_alice = derive_shared(M, a_priv, p)
    s_bob = derive_shared(M, b_priv, p)
    s_m_a = derive_shared(A, m_priv, p)
    s_m_b = derive_shared(B, m_priv, p)
    return {
        'alice_mallory_equal': s_alice == s_m_a,
        'bob_mallory_equal': s_bob == s_m_b,
        'alice_bob_same_key': s_alice == s_bob,
        'key_alice': kdf(s_alice)[:12],
        'key_bob': kdf(s_bob)[:12],
        'key_mallory_alice': kdf(s_m_a)[:12],
        'key_mallory_bob': kdf(s_m_b)[:12],
    }


def analyze_parameters(p=P2048, g=G2048):
    """Check DH parameter properties. Returns dict of booleans + reasons."""
    report = {
        'p_bits': p.bit_length(),
        'g': g,
        'p_large_enough': p.bit_length() >= 1024,
        'p_odd': p % 2 == 1,
        'probable_prime': is_probable_prime(p),
        'safe_prime': is_safe_prime(p),
    }
    gen = generator_ok(g, p)
    report['generator'] = gen
    return report


def small_prime_example():
    """Worked p=23 example, fully deterministic."""
    p, g, a, b = 23, 5, 6, 15
    A = modexp(g, a, p)
    B = modexp(g, b, p)
    s_a = modexp(B, a, p)
    s_b = modexp(A, b, p)
    return {
        'p': p, 'g': g, 'a': a, 'b': b,
        'A': A, 'B': B, 's_a': s_a, 's_b': s_b,
        'shared_equal': s_a == s_b,
    }


def run_demo():
    """Deterministic full offline demo; returns report dict."""
    report = {
        'exchange': dh_exchange(),
        'mitm': mitm_demo(),
        'analysis': analyze_parameters(),
        'small_prime': small_prime_example(),
    }
    return report


def _render_demo(report: Dict) -> str:
    lines = []
    ex = report['exchange']
    lines.append('=== Diffie-Hellman Demo ===')
    lines.append('RFC 3526 Group 14 (2048-bit) key exchange:')
    lines.append(f"  p bits: {ex['p_bits']}, g: {ex['g']}")
    lines.append(f"  Alice pub: ...{ex['public_a_tail']}")
    lines.append(f"  Bob pub:   ...{ex['public_b_tail']}")
    lines.append(f"  shared secrets equal: {ex['shared_equal']}")
    lines.append(f"  session key (SHA-256): {ex['session_key']}")

    mm = report['mitm']
    lines.append('')
    lines.append('=== Man-in-the-Middle ===')
    lines.append(f"  Alice & Mallory agree: {mm['alice_mallory_equal']}")
    lines.append(f"  Bob & Mallory agree:   {mm['bob_mallory_equal']}")
    lines.append(f"  Alice & Bob SAME key:  {mm['alice_bob_same_key']}")

    an = report['analysis']
    lines.append('')
    lines.append('=== Parameter Analysis ===')
    lines.append(f"  p bits: {an['p_bits']}, probable prime: {an['probable_prime']}, "
                 f"safe prime: {an['safe_prime']}")
    lines.append(f"  generator g={an['g']}: {an['generator']['ok']} "
                 f"({an['generator']['reason']})")
    lines.append(f"  smallest usable? p>=1024 bits: {an['p_large_enough']}")

    sm = report['small_prime']
    lines.append('')
    lines.append('=== Small-Prime Example (education) ===')
    lines.append(f"  p={sm['p']}, g={sm['g']}, a={sm['a']}, b={sm['b']}")
    lines.append(f"  A={sm['A']}, B={sm['B']}, s_a={sm['s_a']}, s_b={sm['s_b']}")
    return '\n'.join(lines)


_RENDERERS = {
    'demo': _render_demo,
    'default': lambda report: json.dumps(report, indent=2, default=str),
}


def _common_args(parser):
    parser.add_argument('--json', action='store_true',
                        help='emit JSON (default render)')
    parser.add_argument('--output', metavar='PATH',
                        help='write report to PATH')
    parser.add_argument('--p', type=int, default=None,
                        help='override prime (default RFC 3526 Group 14)')
    parser.add_argument('--g', type=int, default=None,
                        help='override generator (default 2)')


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog='dh',
        description='Diffie-Hellman key exchange, MITM demo, parameter analysis.',
    )
    _common_args(parser)
    parser.add_argument('--run', action='store_true',
                        help='run the classic text-mode exchange')
    args = parser.parse_args(argv)

    p = args.p or P2048
    g = args.g or G2048
    report = run_demo() if p == P2048 and g == G2048 else {
        'exchange': dh_exchange(p, g),
        'mitm': mitm_demo(p, g),
        'analysis': analyze_parameters(p, g),
        'small_prime': small_prime_example(),
    }

    if args.run:
        lines, _shared, _pubs, _privs = _classic_text(p, g)
        print('\n'.join(lines))
        return 0

    renderer = _RENDERERS['default' if args.json else 'demo']
    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"wrote {args.output}")
    else:
        print(renderer(report))
    return 0


def _classic_text(p=P2048, g=G2048):
    """Legacy text-mode demo, for --run."""
    lines = []
    lines.append("Running Diffie-Hellman with RFC 3526 Group 14 (2048-bit).\n"
                 if p == P2048 else f"Running Diffie-Hellman p={p} g={g}\n")
    ex = dh_exchange(p, g)
    lines.append(f"p (prime, {ex['p_bits']} bits)")
    lines.append(f"g (generator): {ex['g']}")
    lines.append("")
    lines.append(f"  a (Alice): {ex['a_bits']} bits")
    lines.append(f"  b (Bob):   {ex['b_bits']} bits")
    lines.append("")
    lines.append(f"Shared secrets equal: {ex['shared_equal']}")
    lines.append(f"Session key (SHA256): {ex['session_key']}")
    return lines, ex, (), ()


if __name__ == "__main__":
    sys.exit(main())