#!/usr/bin/env python3
"""
Boneh-Durfee-Frankel (BDF) Attack on RSA

This attack exploits partial knowledge of the private key d.
It's a side-channel attack that works when some bits of d leak through:
- Timing attacks
- Power analysis
- Cache attacks
- Fault injection

Attack scenarios:
1. Known LSBs (Least Significant Bits) - Most common from timing leaks
2. Known MSBs (Most Significant Bits) - From partial key exposure
3. Scattered known bits - From various side channels

The attack is effective when:
- We know a fraction of the bits of d (the more bits, the easier)
- For this simplified implementation: ~1/4 to 1/2 of bits needed
- Full lattice-based version (SageMath) can work with fewer known bits

This implementation uses exhaustive search over unknown bits,
making it practical for small key sizes or many known bits.
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
    Returns (x1, x2) if solution exists, None otherwise
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


def bdf_attack_known_lsb(e: int, n: int, d_low: int, num_known_bits: int) -> Optional[int]:
    """
    Boneh-Durfee-Frankel attack when LSBs (least significant bits) of d are known

    Args:
        e: public exponent
        n: modulus
        d_low: known lower bits of d
        num_known_bits: number of known LSBs

    Returns:
        d: full private exponent if found
    """
    print(f"BDF Attack with {num_known_bits} known LSBs")
    print(f"Known LSBs: {d_low}")
    print()

    # We know d = d_high * 2^num_known_bits + d_low
    # From e*d = 1 + k*phi(n), we have:
    # e*(d_high * 2^num_known_bits + d_low) = 1 + k*phi(n)
    # e*d_high * 2^num_known_bits = 1 + k*phi(n) - e*d_low
    # e*d_high * 2^num_known_bits ≡ 1 - e*d_low (mod k)

    modulus = 2 ** num_known_bits

    # e*d ≡ 1 (mod modulus)
    # e*d_low ≡ 1 - k*phi (mod modulus)
    # We can compute: k*phi ≡ e*d_low - 1 (mod modulus)

    k_phi_low = (e * d_low - 1) % modulus

    # Now we know lower bits of k*phi(n)
    # phi(n) ≈ n, so k is small

    # Simpler approach: directly search for d candidates matching LSBs
    # e*d = 1 (mod phi), so for small k: d ≈ (1 + k*n) / e

    print(f"Searching for valid d with matching LSBs...")

    # d = d_high * modulus + d_low
    # Try different d_high values
    max_d_high = n // modulus

    for d_high in range(max_d_high + 1):
        d_candidate = d_high * modulus + d_low

        if d_candidate <= 0 or d_candidate >= n:
            continue

        # Check if this d works: find k such that e*d = 1 + k*phi
        # Try small k values
        for k in range(1, min(1000, e)):
            if (e * d_candidate - 1) % k != 0:
                continue

            phi_candidate = (e * d_candidate - 1) // k

            if phi_candidate <= 0 or phi_candidate >= n:
                continue

            # Try to factor n using phi
            sum_pq = n - phi_candidate + 1
            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    phi_actual = (p - 1) * (q - 1)
                    if (e * d_candidate) % phi_actual == 1:
                        print(f"Found d_high = {d_high}, k = {k}")
                        return d_candidate

        if d_high % 100 == 0 and d_high > 0:
            print(f"  Searched d_high up to {d_high}...")

    return None


def bdf_attack_known_msb(e: int, n: int, d_high: int, num_known_bits: int, total_d_bits: int = None) -> Optional[int]:
    """
    Boneh-Durfee-Frankel attack when MSBs (most significant bits) of d are known

    Args:
        e: public exponent
        n: modulus
        d_high: known higher bits of d (the actual high bits, not shifted)
        num_known_bits: number of known MSBs
        total_d_bits: total expected bits in d (if None, estimate from n)

    Returns:
        d: full private exponent if found
    """
    print(f"BDF Attack with {num_known_bits} known MSBs")
    print(f"Known MSBs value: {d_high}")
    print()

    # Estimate total bits in d if not provided
    if total_d_bits is None:
        # d is typically around the same size as phi(n) ≈ n
        total_d_bits = n.bit_length()

    unknown_bits = total_d_bits - num_known_bits

    if unknown_bits <= 0:
        return d_high

    # d = d_high * 2^unknown_bits + d_low
    # where d_low is the unknown lower bits

    shift = 2 ** unknown_bits
    d_base = d_high * shift

    print(f"Total d bits: {total_d_bits}")
    print(f"Unknown bits: {unknown_bits}")
    print(f"Search space: 2^{unknown_bits} = {shift}")
    print()

    # Limit search for efficiency
    max_d_low = min(shift, 100000)

    if shift > 100000:
        print(f"Warning: Search space too large, limiting to {max_d_low}")
        print()

    print(f"Searching for d = {d_high} << {unknown_bits} | d_low...")

    # Search for the unknown lower bits
    for d_low in range(max_d_low):
        d_candidate = d_base + d_low

        if d_candidate <= 0 or d_candidate >= n:
            continue

        # For each candidate d, check if e*d ≡ 1 (mod phi) for some valid phi
        # We need k such that e*d = 1 + k*phi

        # Try small k values
        for k in range(1, min(2000, e)):
            if (e * d_candidate - 1) % k != 0:
                continue

            phi_candidate = (e * d_candidate - 1) // k

            if phi_candidate <= 0 or phi_candidate >= n:
                continue

            # Try to factor n using phi
            sum_pq = n - phi_candidate + 1
            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    phi_actual = (p - 1) * (q - 1)
                    if (e * d_candidate) % phi_actual == 1:
                        print(f"Found d_low = {d_low}, k = {k}")
                        return d_candidate

        # Progress indicator
        if d_low % 5000 == 0 and d_low > 0:
            print(f"  Searched up to {d_low}/{max_d_low}...")

    return None


def bdf_attack_partial_key(e: int, n: int, known_bits: str, bit_positions: str = None) -> Optional[int]:
    """
    Generalized Boneh-Durfee-Frankel attack with partial key knowledge

    Args:
        e: public exponent
        n: modulus
        known_bits: binary string with '0', '1' for known bits, '?' for unknown
                   Example: "1101??0?11"
        bit_positions: 'lsb' or 'msb' to indicate position (optional)

    Returns:
        d: full private exponent if found
    """
    print("Boneh-Durfee-Frankel Attack with Partial Key Knowledge")
    print(f"Known bit pattern: {known_bits}")
    print()

    # Count known and unknown bits
    num_known = sum(1 for b in known_bits if b in '01')
    num_unknown = sum(1 for b in known_bits if b == '?')

    print(f"Known bits: {num_known}")
    print(f"Unknown bits: {num_unknown}")
    print()

    if num_unknown > 24:
        print(f"Warning: {num_unknown} unknown bits may take too long to search")
        print("Limiting search space...")

    # Build mask and known value
    mask = 0
    known_value = 0

    for i, bit in enumerate(reversed(known_bits)):
        if bit == '1':
            mask |= (1 << i)
            known_value |= (1 << i)
        elif bit == '0':
            mask |= (1 << i)

    # Search all possible values for unknown bits
    max_search = min(2 ** num_unknown, 1000000)

    print(f"Searching {max_search} possibilities...")
    print()

    for x in range(max_search):
        # Build d_candidate by filling in unknown bits
        d_candidate = known_value
        bit_idx = 0

        for i, bit in enumerate(reversed(known_bits)):
            if bit == '?':
                if (x >> bit_idx) & 1:
                    d_candidate |= (1 << i)
                bit_idx += 1

        # Check if this d is valid
        if d_candidate <= 0 or d_candidate >= n:
            continue

        # Try small k values
        for k in range(1, min(1000, e)):
            if (e * d_candidate - 1) % k != 0:
                continue

            phi_candidate = (e * d_candidate - 1) // k

            if phi_candidate <= 0 or phi_candidate >= n:
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

        if x % 100000 == 0 and x > 0:
            print(f"  Searched {x}/{max_search}...")

    return None


def test_bdf_attacks():
    """Test Boneh-Durfee-Frankel attacks"""

    print("=" * 60)
    print("Testing Boneh-Durfee-Frankel Attack")
    print("=" * 60)
    print()

    # Generate RSA key with more suitable parameters for the attack
    p = 1009
    q = 1013
    n = p * q
    phi = (p - 1) * (q - 1)

    # Use small d for testing
    d = 97
    e = mod_inverse(d, phi)

    print(f"RSA Parameters:")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"  d = {d} (actual private key)")
    print(f"  d in binary: {bin(d)}")
    print()

    # Test 1: Known LSBs
    print("=" * 60)
    print("Test 1: Attack with known LSBs")
    print("=" * 60)

    num_known_lsb = 8  # Know lower 8 bits (more practical)
    mask_lsb = (1 << num_known_lsb) - 1
    d_low = d & mask_lsb

    print(f"Simulating leak of lower {num_known_lsb} bits...")
    print(f"Known LSBs: {d_low} (binary: {bin(d_low)})")
    print()

    recovered_d = bdf_attack_known_lsb(e, n, d_low, num_known_lsb)

    if recovered_d == d:
        print()
        print("✓ Attack successful!")
        print(f"  Recovered d = {recovered_d}")

        # Verify
        test_msg = 12345
        c = pow(test_msg, e, n)
        m = pow(c, recovered_d, n)
        if m == test_msg:
            print("  ✓ Verification successful!")
    else:
        print()
        if recovered_d:
            print(f"✗ Attack failed. Got d = {recovered_d}, expected {d}")
        else:
            print(f"✗ Attack failed. Could not recover d")

    print()
    print("=" * 60)
    print()

    # Test 2: Known MSBs (use fewer known bits to reduce search space)
    print("Test 2: Attack with known MSBs")
    print("=" * 60)

    d_bits = d.bit_length()
    num_known_msb = 3  # Know upper 3 bits (practical for demo)
    unknown_bits_msb = d_bits - num_known_msb

    d_high = d >> unknown_bits_msb

    print(f"Actual d: {d} = {bin(d)}")
    print(f"d has {d_bits} bits")
    print(f"Simulating leak of upper {num_known_msb} bits...")
    print(f"Known MSB value: {d_high}")
    print(f"This leaves {unknown_bits_msb} unknown bits to search")
    print()

    if unknown_bits_msb > 17:
        print(f"Skipping MSB test - search space too large (2^{unknown_bits_msb})")
        print("In practice, need more known bits or lattice reduction")
    else:
        recovered_d_msb = bdf_attack_known_msb(e, n, d_high, num_known_msb, d_bits)

        if recovered_d_msb == d:
            print()
            print("✓ Attack successful!")
            print(f"  Recovered d = {recovered_d_msb}")

            # Verify
            c2 = pow(test_msg, e, n)
            m2 = pow(c2, recovered_d_msb, n)
            if m2 == test_msg:
                print("  ✓ Verification successful!")
        else:
            print()
            if recovered_d_msb:
                print(f"✗ Attack failed. Got d = {recovered_d_msb}, expected {d}")
            else:
                print(f"✗ Attack failed. Could not recover d")

    print()
    print("=" * 60)


def attack_with_known_lsb(e: int, n: int, d_low: int, num_known_bits: int):
    """
    Attack RSA with known LSBs of private key

    Args:
        e: public exponent
        n: modulus
        d_low: known lower bits of d
        num_known_bits: number of known LSBs
    """
    print("=" * 60)
    print("Boneh-Durfee-Frankel Attack (Known LSBs)")
    print("=" * 60)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"Known LSBs: {d_low} ({num_known_bits} bits)")
    print()

    d = bdf_attack_known_lsb(e, n, d_low, num_known_bits)

    if d:
        print()
        print("=" * 60)
        print(f"Success! Recovered private key d = {d}")
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
                    break
    else:
        print()
        print("Attack failed.")
        print("Try with more known bits or check parameters.")


if __name__ == "__main__":
    test_bdf_attacks()

    print()
    print("Available attack functions:")
    print("- bdf_attack_known_lsb(e, n, d_low, num_known_bits)")
    print("- bdf_attack_known_msb(e, n, d_high, num_known_bits)")
    print("- bdf_attack_partial_key(e, n, known_bits)")
