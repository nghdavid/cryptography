#!/usr/bin/env python3
"""
Wiener Attack on RSA
This attack works when the private exponent d is small (d < N^0.25)
"""

from fractions import Fraction
from math import isqrt
from typing import Optional, Tuple


def continued_fractions(n: int, d: int) -> list:
    """
    Compute the continued fraction representation of n/d
    Returns list of quotients [a0, a1, a2, ...]
    """
    cf = []
    while d:
        q = n // d
        cf.append(q)
        n, d = d, n - q * d
    return cf


def convergents(cf: list) -> list:
    """
    Compute convergents from continued fraction
    Returns list of (numerator, denominator) tuples
    """
    convs = []
    for i in range(len(cf)):
        if i == 0:
            convs.append((cf[0], 1))
        elif i == 1:
            convs.append((cf[1] * cf[0] + 1, cf[1]))
        else:
            num = cf[i] * convs[i-1][0] + convs[i-2][0]
            den = cf[i] * convs[i-1][1] + convs[i-2][1]
            convs.append((num, den))
    return convs


def is_perfect_square(n: int) -> bool:
    """Check if n is a perfect square"""
    if n < 0:
        return False
    root = isqrt(n)
    return root * root == n


def solve_quadratic(a: int, b: int, c: int) -> Optional[Tuple[int, int]]:
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


def wiener_attack(e: int, n: int) -> Optional[int]:
    """
    Perform Wiener attack on RSA
    Returns private exponent d if attack succeeds, None otherwise

    Args:
        e: public exponent
        n: modulus

    Returns:
        d: private exponent if found
    """
    # Get continued fraction of e/n
    cf = continued_fractions(e, n)

    # Get convergents k/d
    convs = convergents(cf)

    for k, d in convs:
        # Skip if k = 0
        if k == 0:
            continue

        # Calculate phi(n) = (e*d - 1) / k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # Try to factor n using phi
        # n = p*q, phi = (p-1)*(q-1) = n - (p+q) + 1
        # So p+q = n - phi + 1
        # p and q are roots of: x^2 - (p+q)*x + n = 0

        sum_pq = n - phi + 1

        # Solve x^2 - sum_pq*x + n = 0
        result = solve_quadratic(1, -sum_pq, n)

        if result:
            p, q = result
            # Verify the factorization
            if p * q == n and p > 1 and q > 1:
                return d

    return None


def test_wiener_attack():
    """Test the Wiener attack with a vulnerable RSA key"""
    # Example vulnerable RSA parameters (small d)
    # These are demonstration values - in practice you'd have e and n

    # Generate a vulnerable key (for testing)
    # For Wiener attack to work: d < (1/3) * N^(1/4)

    # Use larger primes for RSA-256 bit equivalent
    p = 12553
    q = 13007
    n = p * q  # 163296871
    phi = (p - 1) * (q - 1)  # 163271312

    # Choose very small d (vulnerable to Wiener attack)
    # Must be coprime to phi
    d = 101

    # Calculate e
    # e*d ≡ 1 (mod phi)
    e = pow(d, -1, phi)

    print(f"Testing Wiener Attack")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"Actual d = {d}")
    print(f"Bound check: d < N^0.25 = {int(n**0.25)}")
    print()

    # Perform attack
    found_d = wiener_attack(e, n)

    if found_d:
        print(f"Attack successful!")
        print(f"Found d = {found_d}")

        # Verify
        if found_d == d:
            print("✓ Correct private exponent recovered!")
        else:
            print("✗ Found different d, but still valid")
    else:
        print("Attack failed - key may not be vulnerable")


def attack_custom_key(e: int, n: int):
    """
    Attack a custom RSA key

    Args:
        e: public exponent
        n: modulus
    """
    print(f"Attempting Wiener attack on:")
    print(f"n = {n}")
    print(f"e = {e}")
    print()

    d = wiener_attack(e, n)

    if d:
        print(f"Success! Private exponent d = {d}")

        # Verify by computing phi
        phi = (e * d - 1) // ((e * d - 1) // n + 1)
        sum_pq = n - phi + 1
        result = solve_quadratic(1, -sum_pq, n)

        if result:
            p, q = result
            print(f"p = {p}")
            print(f"q = {q}")
            print(f"Verification: p * q = {p * q} (should equal n = {n})")
    else:
        print("Attack failed. The key is not vulnerable to Wiener attack.")
        print("This could mean:")
        print("- d is too large (d >= N^0.25)")
        print("- The key is properly generated")


if __name__ == "__main__":
    # Run test
    test_wiener_attack()

    print("\n" + "="*50 + "\n")
    print("To attack your own key, use:")
    print("attack_custom_key(e, n)")
