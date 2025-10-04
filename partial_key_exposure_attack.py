#!/usr/bin/env python3
"""
Partial Key Exposure Attack on RSA
This attack exploits knowledge of partial bits of the private key d.
Works when some LSBs (Least Significant Bits) or MSBs (Most Significant Bits) of d are known.

The attack uses Coppersmith's method and lattice reduction techniques.
For RSA-256 (256-bit modulus), we can recover the full key if enough bits are known.
Typically, knowing ~27-50% of the bits is sufficient, depending on which bits are known.

This implementation uses a simplified search approach that works well for small to medium
RSA keys. For larger keys or optimal bounds, more sophisticated lattice reduction
techniques (LLL algorithm) would be required.

Reference: Boneh, Durfee, and Frankel's work on partial key exposure
"""

from math import isqrt, gcd, ceil, log2
from typing import Optional, Tuple


def extended_gcd(a, b):
    """Extended Euclidean algorithm"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a, m):
    """Modular multiplicative inverse"""
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m


def is_perfect_square(n: int) -> bool:
    """Check if n is a perfect square"""
    if n < 0:
        return False
    root = isqrt(n)
    return root * root == n


def solve_quadratic(a: int, b: int, c: int):
    """
    Solve ax^2 + bx + c = 0
    Returns (p, q) if solution exists, None otherwise
    """
    discriminant = b * b - 4 * a * c

    if discriminant < 0 or not is_perfect_square(discriminant):
        return None

    sqrt_disc = isqrt(discriminant)

    if (-b + sqrt_disc) % (2 * a) != 0:
        return None

    x1 = (-b + sqrt_disc) // (2 * a)
    x2 = (-b - sqrt_disc) // (2 * a)

    return (x1, x2)


def partial_key_exposure_lsb(e: int, n: int, d_lsb: int, num_known_bits: int) -> Optional[int]:
    """
    Partial Key Exposure Attack when LSBs (Least Significant Bits) of d are known

    Given e*d = 1 + k*phi(n), we know some LSBs of d.
    We can search for the unknown MSBs.

    Args:
        e: public exponent
        n: modulus
        d_lsb: known least significant bits of d
        num_known_bits: number of known LSBs

    Returns:
        Full private exponent d if found, None otherwise
    """
    print("Partial Key Exposure Attack (LSB known)")
    print(f"Known LSBs: {num_known_bits} bits")
    print(f"d_lsb = {d_lsb}")
    print()

    # d = d_lsb + d_msb * 2^num_known_bits
    # e*d = 1 + k*phi(n)
    # e*(d_lsb + d_msb * 2^b) = 1 + k*phi(n)
    # where b = num_known_bits

    shift = 2 ** num_known_bits

    # phi(n) ≈ n - 2*sqrt(n) + 1
    sqrt_n = isqrt(n)
    phi_approx = n - 2 * sqrt_n + 1

    # e*d_lsb + e*d_msb*2^b = 1 + k*phi(n)
    # e*d_msb*2^b - k*phi(n) = 1 - e*d_lsb

    target = 1 - (e * d_lsb)

    # Estimate bounds for d_msb and k
    # d < phi(n), so d_msb < phi(n) / 2^b
    max_d_msb = (n // shift) + 1000

    # k is bounded by: k < e*d/phi ≈ e*d/n < e
    # For e=65537, k can be larger
    # Estimate: k ≈ (e*d)/phi, and d ≈ n, so k ≈ e
    max_k = min(200000, e + 10000)

    # Reduce phi search range
    phi_search_range = min(10000, sqrt_n)

    print(f"Searching for d_msb (up to {max_d_msb}) and k (up to {max_k})...")
    print(f"Phi search range: ±{phi_search_range}")
    print()

    # Search for valid k and phi that satisfy the equation
    for k in range(1, max_k):
        if k % 10000 == 0:
            print(f"  Trying k = {k}...")

        # From e*d = 1 + k*phi, we have:
        # e*(d_lsb + d_msb*shift) = 1 + k*phi
        # d_msb = (1 + k*phi - e*d_lsb) / (e*shift)

        # Try phi values around our approximation
        for phi_offset in range(-phi_search_range, phi_search_range):
            phi_candidate = phi_approx + phi_offset

            if phi_candidate <= 0:
                continue

            numerator = 1 + k * phi_candidate - e * d_lsb

            if numerator % (e * shift) != 0:
                continue

            d_msb_candidate = numerator // (e * shift)

            if d_msb_candidate < 0 or d_msb_candidate > max_d_msb:
                continue

            # Reconstruct full d
            d_candidate = d_lsb + d_msb_candidate * shift

            if d_candidate <= 0 or d_candidate >= n:
                continue

            # Verify: e*d ≡ 1 (mod phi)
            if (e * d_candidate - 1) % phi_candidate != 0:
                continue

            # Try to factor n using this phi
            sum_pq = n - phi_candidate + 1
            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    phi_actual = (p - 1) * (q - 1)

                    # Final verification
                    if (e * d_candidate) % phi_actual == 1:
                        print(f"✓ Found valid d after searching k={k}")
                        return d_candidate

    return None


def partial_key_exposure_msb(e: int, n: int, d_msb: int, num_known_bits: int) -> Optional[int]:
    """
    Partial Key Exposure Attack when MSBs (Most Significant Bits) of d are known

    Given e*d = 1 + k*phi(n), we know some MSBs of d.
    We can search for the unknown LSBs.

    Args:
        e: public exponent
        n: modulus
        d_msb: known most significant bits of d
        num_known_bits: number of known MSBs

    Returns:
        Full private exponent d if found, None otherwise
    """
    print("Partial Key Exposure Attack (MSB known)")
    print(f"Known MSBs: {num_known_bits} bits")
    print(f"d_msb = {d_msb}")
    print()

    # For MSBs, the unknown_bits parameter should represent how many LSBs are unknown
    # d_msb represents the top num_known_bits
    # The full d is: d = d_msb * 2^(d_total_bits - num_known_bits) + d_lsb
    # But we don't know d_total_bits exactly, so we try different values

    # d is typically in range [phi/e, phi] or roughly [0.5*n, n]
    # So d.bit_length() is usually n.bit_length() or n.bit_length() - 1

    # Try different possible bit lengths for d
    for d_bitlen_guess in range(max(1, n.bit_length() - 3), n.bit_length() + 1):
        unknown_bits = d_bitlen_guess - num_known_bits

        if unknown_bits <= 0:
            continue

        # Try this guess
        result = _msb_search_with_bitlen(e, n, d_msb, num_known_bits, unknown_bits)
        if result:
            return result

    return None


def _msb_search_with_bitlen(e: int, n: int, d_msb: int, num_known_bits: int, unknown_bits: int) -> Optional[int]:
    """Helper function to search with a specific bit length assumption"""

    # d = d_msb * 2^unknown_bits + d_lsb
    shift = 2 ** unknown_bits
    max_d_lsb = shift

    sqrt_n = isqrt(n)
    phi_approx = n - 2 * sqrt_n + 1
    max_k = min(200000, e + 10000)

    # Reduce phi search range
    phi_search_range = min(10000, sqrt_n)

    # Search for valid k and phi
    for k in range(1, max_k):
        # Try phi values around our approximation
        for phi_offset in range(-phi_search_range, phi_search_range):
            phi_candidate = phi_approx + phi_offset

            if phi_candidate <= 0:
                continue

            # From e*d = 1 + k*phi:
            # e*(d_msb*shift + d_lsb) = 1 + k*phi
            # d_lsb = (1 + k*phi - e*d_msb*shift) / e

            numerator = 1 + k * phi_candidate - e * d_msb * shift

            if numerator % e != 0:
                continue

            d_lsb_candidate = numerator // e

            if d_lsb_candidate < 0 or d_lsb_candidate >= max_d_lsb:
                continue

            # Reconstruct full d
            d_candidate = d_msb * shift + d_lsb_candidate

            if d_candidate <= 0 or d_candidate >= n:
                continue

            # Verify: e*d ≡ 1 (mod phi)
            if (e * d_candidate - 1) % phi_candidate != 0:
                continue

            # Try to factor n
            sum_pq = n - phi_candidate + 1
            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    phi_actual = (p - 1) * (q - 1)

                    if (e * d_candidate) % phi_actual == 1:
                        return d_candidate

    return None


def partial_key_exposure_attack(e: int, n: int, partial_d: int,
                                 num_known_bits: int, bits_type: str = 'lsb') -> Optional[int]:
    """
    Main function for Partial Key Exposure Attack

    Args:
        e: public exponent
        n: modulus
        partial_d: known bits of d (either LSBs or MSBs)
        num_known_bits: number of known bits
        bits_type: 'lsb' for least significant bits, 'msb' for most significant bits

    Returns:
        Full private exponent d if found, None otherwise
    """
    print("=" * 60)
    print("Partial Key Exposure Attack on RSA")
    print("=" * 60)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"n bit length: {n.bit_length()}")
    print(f"Known {bits_type.upper()}: {num_known_bits} bits")
    print("=" * 60)
    print()

    if bits_type.lower() == 'lsb':
        d = partial_key_exposure_lsb(e, n, partial_d, num_known_bits)
    elif bits_type.lower() == 'msb':
        d = partial_key_exposure_msb(e, n, partial_d, num_known_bits)
    else:
        print("Error: bits_type must be 'lsb' or 'msb'")
        return None

    if d:
        print()
        print("=" * 60)
        print("Attack Successful!")
        print(f"Recovered d = {d}")
        print(f"d bit length: {d.bit_length()}")
        print("=" * 60)

        # Try to factor n
        for k in range(1, 10000):
            if (e * d - 1) % k != 0:
                continue

            phi_candidate = (e * d - 1) // k
            sum_pq = n - phi_candidate + 1

            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    print()
                    print(f"Factorization:")
                    print(f"  p = {p}")
                    print(f"  q = {q}")
                    print(f"  phi = {phi_candidate}")
                    print(f"  Verification: p * q = {p * q}")
                    break
    else:
        print()
        print("=" * 60)
        print("Attack Failed")
        print("=" * 60)
        print("Possible reasons:")
        print("- Not enough bits are known (need more than ~27% for LSBs)")
        print("- Incorrect known bits provided")
        print("- Key size too large for this implementation")

    return d


def test_partial_key_exposure_lsb():
    """Test Partial Key Exposure Attack with known LSBs"""

    # Generate vulnerable RSA key with smaller e for faster attack
    p = 1009
    q = 1013
    n = p * q
    phi = (p - 1) * (q - 1)

    # Use small e that is coprime with phi
    e = 13  # Small and coprime with phi=1020096

    # Calculate d
    d = mod_inverse(e, phi)

    if not d:
        print("Failed to generate test key")
        return

    print("=" * 60)
    print("Test: Partial Key Exposure Attack (LSB known)")
    print("=" * 60)
    print(f"Generated RSA key:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {n} ({n.bit_length()} bits)")
    print(f"  e = {e}")
    print(f"  d = {d} ({d.bit_length()} bits)")
    print()

    # Simulate known LSBs (know about half the bits)
    num_known_bits = d.bit_length() // 2
    mask = (1 << num_known_bits) - 1
    d_lsb = d & mask

    print(f"Known information:")
    print(f"  LSBs of d: {num_known_bits} bits")
    print(f"  d_lsb = {d_lsb}")
    print()

    # Perform attack
    recovered_d = partial_key_exposure_attack(e, n, d_lsb, num_known_bits, bits_type='lsb')

    if recovered_d:
        print()
        if recovered_d == d:
            print("✓ SUCCESS: Recovered the correct private exponent!")
        else:
            print("✗ FAILURE: Recovered d doesn't match")
            print(f"  Expected: {d}")
            print(f"  Got:      {recovered_d}")

        # Test encryption/decryption
        test_msg = 12345
        ciphertext = pow(test_msg, e, n)
        decrypted = pow(ciphertext, recovered_d, n)

        print()
        print("Verification:")
        print(f"  Test message: {test_msg}")
        print(f"  Encrypted:    {ciphertext}")
        print(f"  Decrypted:    {decrypted}")

        if decrypted == test_msg:
            print("  ✓ Encryption/Decryption works correctly!")
        else:
            print("  ✗ Decryption failed")


def test_partial_key_exposure_msb():
    """Test Partial Key Exposure Attack with known MSBs"""

    # Generate vulnerable RSA key with smaller e for faster attack
    p = 1009
    q = 1013
    n = p * q
    phi = (p - 1) * (q - 1)

    # Use small e that is coprime with phi
    e = 13  # Small and coprime with phi=1020096

    # Calculate d
    d = mod_inverse(e, phi)

    if not d:
        print("Failed to generate test key")
        return

    print("=" * 60)
    print("Test: Partial Key Exposure Attack (MSB known)")
    print("=" * 60)
    print(f"Generated RSA key:")
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {n} ({n.bit_length()} bits)")
    print(f"  e = {e}")
    print(f"  d = {d} ({d.bit_length()} bits)")
    print()

    # Simulate known MSBs (know about half the bits)
    d_bitlen = d.bit_length()
    num_known_bits = d_bitlen // 2
    unknown_bits = d_bitlen - num_known_bits

    d_msb = d >> unknown_bits

    print(f"Known information:")
    print(f"  MSBs of d: {num_known_bits} bits")
    print(f"  d_msb = {d_msb}")
    print(f"  d bit length: {d_bitlen}")
    print()

    # Perform attack
    recovered_d = partial_key_exposure_attack(e, n, d_msb, num_known_bits, bits_type='msb')

    if recovered_d:
        print()
        if recovered_d == d:
            print("✓ SUCCESS: Recovered the correct private exponent!")
        else:
            print("✗ FAILURE: Recovered d doesn't match")
            print(f"  Expected: {d}")
            print(f"  Got:      {recovered_d}")

        # Test encryption/decryption
        test_msg = 12345
        ciphertext = pow(test_msg, e, n)
        decrypted = pow(ciphertext, recovered_d, n)

        print()
        print("Verification:")
        print(f"  Test message: {test_msg}")
        print(f"  Encrypted:    {ciphertext}")
        print(f"  Decrypted:    {decrypted}")

        if decrypted == test_msg:
            print("  ✓ Encryption/Decryption works correctly!")
        else:
            print("  ✗ Decryption failed")


if __name__ == "__main__":
    # Run both tests
    test_partial_key_exposure_lsb()
    print("\n" * 2)
    test_partial_key_exposure_msb()

    print("\n" * 2)
    print("=" * 60)
    print("Usage Examples:")
    print("=" * 60)
    print("# Attack with known LSBs:")
    print("partial_key_exposure_attack(e, n, d_lsb, num_known_bits, bits_type='lsb')")
    print()
    print("# Attack with known MSBs:")
    print("partial_key_exposure_attack(e, n, d_msb, num_known_bits, bits_type='msb')")
    print()
