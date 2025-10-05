#!/usr/bin/env python3
"""
Random RSA-256 Franklin-Reiter Attack
Generates random vulnerable RSA-256 keys and attacks them using Franklin-Reiter attack
"""

import random
from franklin_reiter_attack import franklin_reiter_attack


def is_prime(n, k=10):
    """
    Miller-Rabin primality test

    Args:
        n: number to test
        k: number of rounds (higher = more accurate)

    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    """
    Generate a random prime number with specified bit length

    Args:
        bits: desired bit length of the prime

    Returns:
        A prime number with the specified bit length
    """
    while True:
        # Generate random odd number with correct bit length
        n = random.getrandbits(bits)
        # Set MSB and LSB to ensure correct bit length and odd number
        n |= (1 << (bits - 1)) | 1

        if is_prime(n):
            return n


def generate_rsa_256_parameters():
    """
    Generate random RSA-256 parameters

    Returns:
        Tuple of (p, q, n, e) where:
        - p, q: 128-bit prime factors
        - n: 256-bit modulus
        - e: public exponent (3 for Franklin-Reiter attack)
    """
    print("Generating random 128-bit primes for RSA-256...")
    print()

    # Generate two random 128-bit primes
    p = generate_prime(128)
    q = generate_prime(128)

    # Ensure p != q
    while p == q:
        q = generate_prime(128)

    n = p * q
    e = 3  # Small exponent required for Franklin-Reiter attack

    print(f"Generated RSA-256 parameters:")
    print(f"  p = {p}")
    print(f"  p bit length = {p.bit_length()} bits")
    print(f"  q = {q}")
    print(f"  q bit length = {q.bit_length()} bits")
    print(f"  n = p × q = {n}")
    print(f"  n bit length = {n.bit_length()} bits")
    print(f"  e = {e}")
    print()

    return p, q, n, e


def generate_related_messages(n):
    """
    Generate two related messages with random linear relation

    Args:
        n: RSA modulus

    Returns:
        Tuple of (m1, m2, a, b) where M2 = a*M1 + b (mod n)
    """
    print("Generating random related messages...")
    print()

    # Generate random message M1 (must be smaller than n)
    # Use smaller message for practical purposes (e.g., 100 bits)
    m1_bits = 100
    m1 = random.getrandbits(m1_bits)

    # Generate random relation parameters a and b
    # a should be small and non-zero
    a = random.randint(2, 100)

    # b should be small
    b = random.randint(1, 1000000)

    # Compute M2 = a*M1 + b (mod n)
    m2 = (a * m1 + b) % n

    print(f"Generated related messages:")
    print(f"  M1 = {m1}")
    print(f"  a = {a}")
    print(f"  b = {b}")
    print(f"  M2 = {a}*M1 + {b} = {m2}")
    print(f"  Relation: M2 = {a}*M1 + {b} (mod n)")
    print()

    return m1, m2, a, b


def main():
    """Generate random RSA-256 parameters and perform Franklin-Reiter attack"""

    print("=" * 70)
    print("Random RSA-256 Franklin-Reiter Attack")
    print("=" * 70)
    print()

    # Generate random RSA-256 parameters
    p, q, n, e = generate_rsa_256_parameters()

    # Generate random related messages
    m1, m2, a, b = generate_related_messages(n)

    # Encrypt both messages
    print("Encrypting messages...")
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    print(f"  C1 = M1^{e} mod n = {c1}")
    print(f"  C2 = M2^{e} mod n = {c2}")
    print()

    print("=" * 70)
    print("Launching Franklin-Reiter Attack on RSA-256...")
    print("=" * 70)
    print()
    print("Note: Polynomial GCD with 256-bit modulus is computationally intensive.")
    print("      This may take several minutes. Please wait...")
    print()

    # Perform the attack
    recovered_m1 = franklin_reiter_attack(c1, c2, n, e, a, b)

    print()
    print("=" * 70)
    print("VERIFICATION")
    print("=" * 70)

    if recovered_m1 is not None:
        print(f"Original M1:  {m1}")
        print(f"Recovered M1: {recovered_m1}")
        print()

        if recovered_m1 == m1:
            print("✅ SUCCESS! The attack recovered the correct message!")
            print()
            print(f"Verification:")
            print(f"  M1 = {m1}")
            print(f"  M2 = {m2}")
            print(f"  C1 = {c1}")
            print(f"  C2 = {c2}")
            print(f"  Relation: M2 = {a}*M1 + {b}")
        else:
            print("❌ FAILED! Recovered message doesn't match.")
    else:
        print("❌ Attack returned None")
        print(f"Expected M1: {m1}")

if __name__ == "__main__":
    # Directly run RSA-256 attack without asking
    main()

    print()
    print("=" * 70)
    print("Run this script multiple times to generate different random keys!")
    print("=" * 70)
