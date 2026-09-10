import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dh import (
    G2048,
    P2048,
    analyze_parameters,
    derive_shared,
    dh_exchange,
    gen_private_key,
    gen_public_key,
    generator_ok,
    is_probable_prime,
    is_safe_prime,
    kdf,
    mitm_demo,
    modexp,
    run_demo,
    small_prime_example,
)


class ModeExpTests(unittest.TestCase):
    def test_modexp_matches_pow(self):
        for base in range(2, 20):
            for exp in range(0, 12):
                for mod in range(7, 40):
                    self.assertEqual(modexp(base, exp, mod),
                                     pow(base, exp, mod))

    def test_small_prime_worked_example(self):
        result = small_prime_example()
        self.assertEqual(result['A'], 8)
        self.assertEqual(result['B'], 19)
        self.assertEqual(result['s_a'], 2)
        self.assertEqual(result['s_b'], 2)
        self.assertTrue(result['shared_equal'])


class ExchangeTests(unittest.TestCase):
    def test_shared_secrets_equal(self):
        a = gen_private_key()
        b = gen_private_key()
        A = gen_public_key(a)
        B = gen_public_key(b)
        self.assertEqual(derive_shared(B, a), derive_shared(A, b))

    def test_exchange_report(self):
        report = dh_exchange()
        self.assertEqual(report['p_bits'], 2048)
        self.assertTrue(report['shared_equal'])
        self.assertEqual(len(report['session_key']), 64)

    def test_custom_small_prime_exchange(self):
        p, g, a, b = 23, 5, 6, 15
        self.assertEqual(derive_shared(modexp(g, a, p), b, p),
                         derive_shared(modexp(g, b, p), a, p))

    def test_kdf_stable_and_wide(self):
        k1 = kdf(123456789)
        k2 = kdf(123456789)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 64)
        self.assertNotEqual(kdf(1), kdf(2))


class PrimeTests(unittest.TestCase):
    def test_small_primes(self):
        for composite in (1, 4, 6, 9, 15, 21, 25, 100, 561):
            self.assertFalse(is_probable_prime(composite), composite)
        for prime in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 97, 151):
            self.assertTrue(is_probable_prime(prime), prime)

    def test_group14_prime_properties(self):
        self.assertEqual(P2048.bit_length(), 2048)
        self.assertTrue(is_safe_prime(P2048))

    def test_generator_group14(self):
        check = generator_ok(G2048, P2048)
        self.assertTrue(check['ok'], check)
        self.assertIn('prime-order subgroup', check['reason'])

    def test_generator_small_prime_primitive_root(self):
        check = generator_ok(5, 23)
        self.assertTrue(check['ok'], check)
        self.assertIn('primitive root', check['reason'])

    def test_generator_rejects_bad(self):
        self.assertTrue(generator_ok(1, 23)['ok'] is False)
        self.assertTrue(generator_ok(2, 4)['ok'] is False)
        check = generator_ok(22, 23)   # p-1, order 2 -> order-2 branch
        self.assertTrue(check['ok'], check)


class AnalysisTests(unittest.TestCase):
    def test_group14_analysis(self):
        report = analyze_parameters()
        self.assertTrue(report['probable_prime'])
        self.assertTrue(report['safe_prime'])
        self.assertTrue(report['p_large_enough'])
        self.assertTrue(report['generator']['ok'])

    def test_small_prime_flagged(self):
        report = analyze_parameters(23, 5)
        self.assertFalse(report['p_large_enough'])


class MITMTests(unittest.TestCase):
    def test_mitm_breaks_pairwise_agreement(self):
        report = mitm_demo()
        self.assertTrue(report['alice_mallory_equal'])
        self.assertTrue(report['bob_mallory_equal'])
        self.assertFalse(report['alice_bob_same_key'])


class DemoAndCLITests(unittest.TestCase):
    def test_demo_report_shape(self):
        report = run_demo()
        self.assertIn('exchange', report)
        self.assertIn('mitm', report)
        self.assertIn('analysis', report)
        self.assertIn('small_prime', report)

    def test_cli_demo_subprocess(self):
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        result = subprocess.run(
            [sys.executable, os.path.join(root, 'dh.py')],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('shared secrets equal: True', result.stdout)

    def test_cli_json_roundtrip(self):
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, 'report.json')
            result = subprocess.run(
                [sys.executable, os.path.join(root, 'dh.py'),
                 '--json', '--output', report_path],
                capture_output=True, text=True, timeout=300,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(report_path) as f:
                report = json.load(f)
            self.assertIn('exchange', report)
            self.assertIn('small_prime', report)

    def test_cli_run_text_mode(self):
        here = os.path.dirname(os.path.abspath(__file__))
        root = os.path.dirname(here)
        result = subprocess.run(
            [sys.executable, os.path.join(root, 'dh.py'), '--run'],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Session key (SHA256)', result.stdout)


if __name__ == '__main__':
    unittest.main()