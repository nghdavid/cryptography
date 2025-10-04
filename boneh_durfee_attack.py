#!/usr/bin/env python3
"""
Boneh-Durfee Attack on RSA
This attack works when d < N^0.292 (better than Wiener's N^0.25)
Simplified implementation using only Python standard library
"""

from math import isqrt, gcd


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


def boneh_durfee_simplified(e: int, n: int, delta: float = 0.29):
    """
    Simplified Boneh-Durfee attack using brute-force search
    Works for small enough parameters where d < N^delta

    Args:
        e: public exponent
        n: modulus
        delta: parameter such that d < n^delta

    Returns:
        d: private exponent if found, None otherwise
    """

    print("Using simplified Boneh-Durfee approach...")
    print("This searches for small k where e*d - k*phi(n) = 1")
    print()

    # Bounds
    sqrt_n = isqrt(n)
    max_k = min(200000, int(n**delta) + 10000)

    # We know phi(n) = (p-1)(q-1) = n - (p+q) + 1
    # For p, q close to sqrt(n), we have p+q ≈ 2*sqrt(n)
    # So phi ≈ n - 2*sqrt(n) + 1

    phi_approx = n - 2 * sqrt_n + 1
    search_range = sqrt_n

    print(f"Searching k from 1 to {max_k}...")
    print(f"Phi approximation: {phi_approx}")
    print(f"Search range: ±{search_range}")
    print()

    for k in range(1, max_k):
        # Try phi values around our approximation
        for phi_offset in range(-search_range, search_range):
            phi_candidate = phi_approx + phi_offset

            if phi_candidate <= 0:
                continue

            # Check if (1 + k * phi_candidate) is divisible by e
            numerator = 1 + k * phi_candidate
            if numerator % e != 0:
                continue

            d_candidate = numerator // e

            if d_candidate <= 0 or d_candidate >= n:
                continue

            # Check if d_candidate satisfies the bound
            if d_candidate > int(n**delta) + 1000:
                continue

            # Try to factor n using this phi
            sum_pq = n - phi_candidate + 1
            result = solve_quadratic(1, -sum_pq, n)

            if result:
                p, q = result
                if p * q == n and p > 1 and q > 1:
                    phi_actual = (p - 1) * (q - 1)
                    # Verify e*d ≡ 1 (mod phi)
                    if (e * d_candidate) % phi_actual == 1:
                        print(f"Found after searching k={k}")
                        return d_candidate

        # Progress indicator
        if k % 20000 == 0:
            print(f"  Searched k up to {k}...")

    return None


def boneh_durfee_attack(e: int, n: int, delta: float = 0.29):
    """
    Main Boneh-Durfee attack function

    Args:
        e: public exponent
        n: modulus
        delta: parameter such that d < n^delta (typically 0.25-0.29)

    Returns:
        d: private exponent if found, None otherwise
    """
    return boneh_durfee_simplified(e, n, delta)


def test_boneh_durfee():
    """Test Boneh-Durfee attack with a vulnerable key"""

    # Generate vulnerable RSA key
    p = 12553
    q = 13007
    n = p * q
    phi = (p - 1) * (q - 1)

    # Small d (vulnerable to Boneh-Durfee)
    d = 331

    # Calculate e
    e = mod_inverse(d, phi)

    print("=" * 60)
    print("Testing Boneh-Durfee Attack")
    print("=" * 60)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"Actual d = {d}")
    print(f"N^0.25 = {int(n**0.25)} (Wiener bound)")
    print(f"N^0.292 = {int(n**0.292)} (Boneh-Durfee bound)")
    print()

    # Perform attack
    found_d = boneh_durfee_attack(e, n, delta=0.30)

    if found_d:
        print()
        print("=" * 60)
        print("Attack successful!")
        print(f"Found d = {found_d}")
        print("=" * 60)

        if found_d == d:
            print("✓ Correct private exponent recovered!")
        else:
            print("✗ Found different d")

        # Verify by encryption/decryption
        test_msg = 12345
        ciphertext = pow(test_msg, e, n)
        decrypted = pow(ciphertext, found_d, n)

        print()
        print("Verification:")
        print(f"  Test message: {test_msg}")
        print(f"  Encrypted: {ciphertext}")
        print(f"  Decrypted: {decrypted}")
        if decrypted == test_msg:
            print("  ✓ Encryption/Decryption works!")

        # Factor n
        for k in range(1, 10000):
            if (e * found_d - 1) % k != 0:
                continue
            phi_recovered = (e * found_d - 1) // k
            sum_pq = n - phi_recovered + 1
            result = solve_quadratic(1, -sum_pq, n)
            if result:
                p_found, q_found = result
                if p_found * q_found == n:
                    print()
                    print(f"Factorization:")
                    print(f"  p = {p_found}")
                    print(f"  q = {q_found}")
                    break
    else:
        print()
        print("Attack failed - key may not be vulnerable")


def attack_custom_key(e: int, n: int, delta: float = 0.29):
    """
    Attack a custom RSA key with Boneh-Durfee

    Args:
        e: public exponent
        n: modulus
        delta: expected bound (d < n^delta)
    """
    print("=" * 60)
    print("Attempting Boneh-Durfee attack")
    print("=" * 60)
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"Expected d < N^{delta} = {int(n**delta)}")
    print()

    d = boneh_durfee_attack(e, n, delta=delta)

    if d:
        print()
        print("=" * 60)
        print(f"Success! Private exponent d = {d}")
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
                    print(f"  Verification: p * q = {p * q}")
                    break
    else:
        print()
        print("Attack failed. The key may not be vulnerable.")
        print("Suggestions:")
        print("- Ensure d < N^0.292")
        print("- Try different delta values")
        print("- This simplified version works best for smaller key sizes")


if __name__ == "__main__":
    test_boneh_durfee()

    print("\n")
    print("To attack your own key, use:")
    print("attack_custom_key(e, n, delta=0.29)")
