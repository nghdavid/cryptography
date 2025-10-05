#!/usr/bin/env python3
"""
Random RSA-256 Key Generator and Wiener Attack
Generates random vulnerable RSA-256 keys and attacks them using Wiener's attack
"""

import random
from wiener_attack import attack_custom_key


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


def gcd(a, b):
    """Compute greatest common divisor"""
    while b:
        a, b = b, a % b
    return a


def generate_vulnerable_rsa_256():
    """
    Generate a random vulnerable RSA-256 key
    Vulnerable to Wiener attack due to small private exponent d

    Returns:
        Tuple of (e, n, d, p, q) where:
        - e: public exponent
        - n: 256-bit modulus
        - d: small private exponent (vulnerable)
        - p, q: prime factors
    """
    print("Generating random 128-bit primes...")

    # Generate two random 128-bit primes
    p = generate_prime(128)
    q = generate_prime(128)

    # Ensure p != q
    while p == q:
        q = generate_prime(128)

    n = p * q
    phi = (p - 1) * (q - 1)

    print(f"Generated primes:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {n}")
    print(f"  n bit length = {n.bit_length()} bits")
    print()

    # Generate small d (vulnerable to Wiener attack)
    # For 256-bit N, N^0.25 ≈ 2^64
    # We choose d to be much smaller, around 40-50 bits
    print("Generating small private exponent d (vulnerable to Wiener)...")

    max_attempts = 1000
    for attempt in range(max_attempts):
        # Random d between 2^35 and 2^50 (35-50 bits)
        d_bits = random.randint(35, 50)
        d = random.getrandbits(d_bits)
        d |= 1  # Make it odd

        # Check if d is coprime to phi
        if gcd(d, phi) == 1:
            # Calculate e
            e = pow(d, -1, phi)

            print(f"Found valid d after {attempt + 1} attempt(s)")
            print(f"  d = {d}")
            print(f"  d bit length = {d.bit_length()} bits")
            print(f"  Wiener bound: d < N^0.25 = {int(n**0.25)}")
            print(f"  e = {e}")
            print()

            return e, n, d, p, q

    raise ValueError("Failed to generate valid d after maximum attempts")


def main():
    """Generate random RSA-256 keys and attack them"""

    print("=" * 70)
    print("Random RSA-256 Key Generation and Wiener Attack")
    print("=" * 70)
    print()

    # Generate random vulnerable RSA key
    e, n, actual_d, p, q = generate_vulnerable_rsa_256()

    print("=" * 70)
    print("Attacking with Wiener Attack...")
    print("=" * 70)
    print()

    # Attack the key
    attack_custom_key(e, n)

    print()
    print("=" * 70)
    print("Verification")
    print("=" * 70)
    print(f"Actual private exponent d = {actual_d}")
    print(f"Actual primes: p = {p}, q = {q}")
    print()

    # Test encryption/decryption
    print("Testing encryption/decryption...")
    test_message = 123456789
    ciphertext = pow(test_message, e, n)
    decrypted = pow(ciphertext, actual_d, n)

    print(f"  Original message:  {test_message}")
    print(f"  Encrypted:         {ciphertext}")
    print(f"  Decrypted:         {decrypted}")

    if decrypted == test_message:
        print("  ✓ Encryption/Decryption successful!")
    else:
        print("  ✗ Decryption failed!")


if __name__ == "__main__":
    # Set random seed for reproducibility (comment out for true randomness)
    # random.seed(42)

    main()

    print()
    print("=" * 70)
    print("Run this script multiple times to generate different random keys!")
    print("=" * 70)
