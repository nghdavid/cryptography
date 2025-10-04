#!/usr/bin/env python3
"""
Coppersmith's Short Pad Attack on RSA

This attack works when the same message M is encrypted twice with the same RSA key (n, e),
but with different short random paddings:
    m1 = M + r1
    m2 = M + r2
    c1 = m1^e mod n
    c2 = m2^e mod n

If r1 and r2 are small, we can recover the padded messages m1 and m2 using Coppersmith's method.

The attack exploits the fact that m1 and m2 differ by a small amount: m1 - m2 = r1 - r2

This implementation uses a Franklin-Reiter style approach for e=3:
- For each possible delta = m2 - m1, compute gcd(x^3 - c1, (x+delta)^3 - c2)
- When delta equals the true difference r2 - r1, the GCD will be linear: (x - m1)
- Solving the linear equation recovers m1, and m2 = m1 + delta

Note: This is a simplified implementation for educational purposes. It works best with e=3
and may fail in some edge cases (e.g., when polynomial coefficients share factors with n).
A production implementation would use lattice reduction for general e and handle all edge cases.

For RSA256, we demonstrate the attack on a 256-bit modulus.
"""

from math import gcd, ceil, isqrt
from typing import Optional, Tuple, List


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm
    Returns (gcd, x, y) where gcd = a*x + b*y
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> Optional[int]:
    """Modular multiplicative inverse"""
    gcd_val, x, _ = extended_gcd(a, m)
    if gcd_val != 1:
        return None
    return (x % m + m) % m


def polynomial_gcd_univariate(f1_coeffs: List[int], f2_coeffs: List[int], n: int) -> List[int]:
    """
    Compute GCD of two univariate polynomials modulo n
    Coefficients are in ascending degree order: [a0, a1, a2, ...] for a0 + a1*x + a2*x^2 + ...

    Returns the GCD polynomial coefficients
    """
    def normalize(coeffs):
        """Remove leading zeros and normalize"""
        while len(coeffs) > 1 and coeffs[-1] == 0:
            coeffs = coeffs[:-1]
        return coeffs

    def degree(coeffs):
        """Get degree of polynomial"""
        coeffs = normalize(coeffs)
        return len(coeffs) - 1

    def poly_mod(dividend, divisor, n):
        """Polynomial division modulo n"""
        dividend = normalize(dividend[:])
        divisor = normalize(divisor[:])

        if degree(divisor) < 0:
            return None
        if degree(dividend) < degree(divisor):
            return dividend

        result = dividend[:]

        while degree(result) >= degree(divisor) and degree(result) >= 0:
            # Get leading coefficients
            lead_result = result[-1]
            lead_divisor = divisor[-1]

            # Compute quotient coefficient
            inv = mod_inverse(lead_divisor, n)
            if inv is None:
                # Cannot divide, try GCD with leading coefficient
                g = gcd(lead_divisor, n)
                if g > 1:
                    # Found a factor!
                    return None
                return result

            coef = (lead_result * inv) % n
            deg_diff = degree(result) - degree(divisor)

            # Subtract divisor * coef * x^deg_diff from result
            for i in range(len(divisor)):
                result[i + deg_diff] = (result[i + deg_diff] - coef * divisor[i]) % n

            result = normalize(result)

        return result

    # Euclidean algorithm for polynomials
    a = normalize(f1_coeffs[:])
    b = normalize(f2_coeffs[:])

    while degree(b) >= 0:
        remainder = poly_mod(a, b, n)
        if remainder is None:
            break
        a = b
        b = remainder

    return normalize(a)


def find_linear_root(poly_coeffs: List[int], n: int) -> Optional[int]:
    """
    Find root of a linear polynomial a0 + a1*x = 0 mod n
    Returns x such that a0 + a1*x ≡ 0 (mod n)
    """
    if len(poly_coeffs) < 2:
        return None

    a0 = poly_coeffs[0] % n
    a1 = poly_coeffs[1] % n

    if a1 == 0:
        if a0 == 0:
            return 0  # Any x works
        return None

    inv = mod_inverse(a1, n)
    if inv is None:
        return None

    return (-a0 * inv) % n


def coppersmith_short_pad_attack(c1: int, c2: int, e: int, n: int, max_pad_bits: int = 64) -> Optional[Tuple[int, int, int]]:
    """
    Coppersmith's Short Pad Attack

    Recovers the original message M when:
    - m1 = M + r1, c1 = m1^e mod n
    - m2 = M + r2, c2 = m2^e mod n
    - r1 and r2 are small (unknown) random pads

    Args:
        c1: first ciphertext
        c2: second ciphertext
        e: public exponent (typically 3 or 65537)
        n: RSA modulus
        max_pad_bits: maximum size of padding in bits (default 64)

    Returns:
        (M, r1, r2) if successful, None otherwise
    """
    print("=" * 70)
    print("Coppersmith's Short Pad Attack on RSA")
    print("=" * 70)
    print(f"Modulus n: {n}")
    print(f"Exponent e: {e}")
    print(f"Ciphertext 1: {c1}")
    print(f"Ciphertext 2: {c2}")
    print(f"Max padding bits: {max_pad_bits}")
    print()

    if e == 3:
        print("Using Franklin-Reiter approach for e=3...")
        print()

        # The key insight: if m2 = m1 + delta for small delta,
        # then gcd(f1(x), f2(x-delta)) where f1(x)=x^3-c1 and f2(x)=x^3-c2
        # will give us (x - m1) when delta = m2 - m1

        X = 2 ** max_pad_bits
        print(f"Searching for padding difference (max delta = ±{X})...")
        print()

        # For e=3, we use optimized Franklin-Reiter:
        # gcd(x^3 - c1, (x+delta)^3 - c2) = (x - m1) when delta = m2-m1

        # To find the gcd efficiently for each delta:
        # f1(x) = x^3 - c1
        # f2(x) = (x+delta)^3 - c2 = x^3 + 3*delta*x^2 + 3*delta^2*x + delta^3 - c2

        # The gcd will be degree 1 (linear) when we have the right delta
        # We can compute gcd more efficiently by noting:
        # If gcd has degree 1, then f1 = (x-m1)*q1 and f2 = (x-m1)*q2

        # More efficient: for e=3, use direct computation
        # f2(x) - f1(x) = 3*delta*x^2 + 3*delta^2*x + delta^3 + c1 - c2

        for delta in range(-X, X + 1):
            if delta == 0:
                continue

            # Compute gcd(x^3 - c1, (x+delta)^3 - c2) using Euclidean algorithm
            # f1(x) = x^3 - c1
            # f2(x) = x^3 + 3*delta*x^2 + 3*delta^2*x + (delta^3 - c2)

            # First reduction: f2 - f1 = 3*delta*x^2 + 3*delta^2*x + (delta^3 + c1 - c2)
            g2_const = (pow(delta, 3, n) + c1 - c2) % n
            g2_x1 = (3 * pow(delta, 2, n)) % n
            g2_x2 = (3 * delta) % n

            # Now we need gcd(x^3 - c1, 3*delta*x^2 + 3*delta^2*x + g2_const)
            # Reduce x^3 - c1 by g2
            # x^3 = (x/3*delta) * g2 - stuff

            # Let's use the standard poly gcd but optimize
            # For degree 3 and degree 2, we do one division:

            # x^3 / (3*delta*x^2) = x/(3*delta)
            inv_coeff = mod_inverse((3*delta) % n, n)
            if inv_coeff is None:
                continue

            # q = x * inv_coeff
            # remainder = (x^3 - c1) - q * (3*delta*x^2 + 3*delta^2*x + g2_const)
            #           = x^3 - c1 - x*inv_coeff*(3*delta*x^2 + 3*delta^2*x + g2_const)
            #           = x^3 - c1 - (x^3 + x^2*3*delta^2*inv_coeff + x*g2_const*inv_coeff)
            #           = -c1 - x^2*3*delta^2*inv_coeff - x*g2_const*inv_coeff

            r1_const = (-c1) % n
            r1_x1 = (-g2_const * inv_coeff) % n
            r1_x2 = (-g2_x1 * inv_coeff) % n

            # Now gcd(3*delta*x^2 + 3*delta^2*x + g2_const, r1_x2*x^2 + r1_x1*x + r1_const)
            # Reduce degree 2 by degree 2

            if r1_x2 == 0:
                # Already degree 1 or less
                if r1_x1 != 0:
                    # Linear: r1_x1*x + r1_const = 0
                    # x = -r1_const/r1_x1
                    m1 = (-r1_const * mod_inverse(r1_x1, n)) % n
                    if pow(m1, 3, n) == c1:
                        m2 = (m1 + delta) % n
                        if pow(m2, 3, n) == c2:
                            # Found m1 and m2!  delta = m2 - m1 = r2 - r1
                            # We know: m1 = M + r1, m2 = M + r2

                            # Note: Without additional constraints, we cannot uniquely
                            # determine (M, r1, r2) from (m1, m2, delta).
                            # We assume both r1 and r2 are small and positive.

                            # Return m1 and m2 - the user can extract M based on
                            # their knowledge of the padding scheme
                            # For demo purposes, we assume r1 and r2 are roughly similar in size

                            # Try to balance r1 and r2 around delta/2
                            if delta >= 0:
                                # r2 > r1, try r1 near half of allowed range
                                # but ensuring both are valid
                                mid_pad = min(delta // 2, X // 2)
                                for r1 in [mid_pad, 0, X - delta - 1]:
                                    if 0 <= r1 < X:
                                        r2 = r1 + delta
                                        if 0 <= r2 < X:
                                            M = m1 - r1
                                            if M > 0:
                                                print(f"✓ Attack successful!")
                                                print(f"\nRecovered padded messages:")
                                                print(f"  m1 = {m1} ({hex(m1)})")
                                                print(f"  m2 = {m2} ({hex(m2)})")
                                                print(f"  delta = r2 - r1 = {delta} ({hex(delta)})")
                                                print(f"\nPossible solution (assuming balanced padding):")
                                                print(f"  M  = {M} ({hex(M)})")
                                                print(f"  r1 = {r1} ({hex(r1)})")
                                                print(f"  r2 = {r2} ({hex(r2)})")
                                                print()
                                                return (M, r1, r2)
                            else:
                                # r1 > r2
                                mid_pad = min((-delta) // 2, X // 2)
                                for r2 in [mid_pad, 0, X + delta - 1]:
                                    if 0 <= r2 < X:
                                        r1 = r2 - delta
                                        if 0 <= r1 < X:
                                            M = m1 - r1
                                            if M > 0:
                                                print(f"✓ Attack successful!")
                                                print(f"\nRecovered padded messages:")
                                                print(f"  m1 = {m1} ({hex(m1)})")
                                                print(f"  m2 = {m2} ({hex(m2)})")
                                                print(f"  delta = r2 - r1 = {delta} ({hex(delta)})")
                                                print(f"\nPossible solution:")
                                                print(f"  M  = {M} ({hex(M)})")
                                                print(f"  r1 = {r1} ({hex(r1)})")
                                                print(f"  r2 = {r2} ({hex(r2)})")
                                                print()
                                                return (M, r1, r2)
            else:
                # Do one more reduction
                inv2 = mod_inverse(r1_x2, n)
                if inv2:
                    q2 = (g2_x2 * inv2) % n
                    # remainder = g2 - q2*r1
                    rem_const = (g2_const - q2 * r1_const) % n
                    rem_x1 = (g2_x1 - q2 * r1_x1) % n

                    if rem_x1 != 0:
                        inv_rem = mod_inverse(rem_x1, n)
                        if inv_rem:
                            m1 = (-rem_const * inv_rem) % n
                            if pow(m1, 3, n) == c1:
                                m2 = (m1 + delta) % n
                                if pow(m2, 3, n) == c2:
                                    # Found m1 and m2!
                                    if delta >= 0:
                                        mid_pad = min(delta // 2, X // 2)
                                        for r1 in [mid_pad, 0]:
                                            if 0 <= r1 < X:
                                                r2 = r1 + delta
                                                if 0 <= r2 < X:
                                                    M = m1 - r1
                                                    if M > 0:
                                                        print(f"✓ Attack successful!")
                                                        print(f"\nRecovered padded messages:")
                                                        print(f"  m1 = {m1} ({hex(m1)})")
                                                        print(f"  m2 = {m2} ({hex(m2)})")
                                                        print(f"  delta = r2 - r1 = {delta} ({hex(delta)})")
                                                        print(f"\nPossible solution:")
                                                        print(f"  M  = {M} ({hex(M)})")
                                                        print(f"  r1 = {r1} ({hex(r1)})")
                                                        print(f"  r2 = {r2} ({hex(r2)})")
                                                        print()
                                                        return (M, r1, r2)
                                    else:
                                        mid_pad = min((-delta) // 2, X // 2)
                                        for r2 in [mid_pad, 0]:
                                            if 0 <= r2 < X:
                                                r1 = r2 - delta
                                                if 0 <= r1 < X:
                                                    M = m1 - r1
                                                    if M > 0:
                                                        print(f"✓ Attack successful!")
                                                        print(f"\nRecovered padded messages:")
                                                        print(f"  m1 = {m1} ({hex(m1)})")
                                                        print(f"  m2 = {m2} ({hex(m2)})")
                                                        print(f"  delta = r2 - r1 = {delta} ({hex(delta)})")
                                                        print(f"\nPossible solution:")
                                                        print(f"  M  = {M} ({hex(M)})")
                                                        print(f"  r1 = {r1} ({hex(r1)})")
                                                        print(f"  r2 = {r2} ({hex(r2)})")
                                                        print()
                                                        return (M, r1, r2)

            if delta % 10000 == 0:
                print(f"  Tested up to delta={delta}...")

        print("✗ Attack failed - pads may be too large")
        return None

    else:
        print(f"Attack for e={e} requires lattice reduction (not fully implemented)")
        print("This implementation focuses on e=3 for demonstration")
        return None


def test_short_pad_attack():
    """Test the short pad attack with various parameters"""

    print("\n" + "=" * 70)
    print("Testing Coppersmith's Short Pad Attack")
    print("=" * 70 + "\n")

    # Test 1: Small RSA with e=3 and small pads
    print("Test 1: RSA256 with e=3 and 16-bit pads")
    print("-" * 70)

    # Generate RSA parameters (256-bit for testing)
    p = 208351617316091241234326746312124448251
    q = 280127847142267892602133859112477035319
    n = p * q
    e = 3

    # Original message
    M = 0xDEADBEEFCAFEBABE

    # Small random pads (16-bit)
    r1 = 0x1234
    r2 = 0x5678

    # Padded messages
    m1 = M + r1
    m2 = M + r2

    # Encrypt
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    print(f"\nOriginal values:")
    print(f"  n = {n}")
    print(f"  e = {e}")
    print(f"  M = {hex(M)}")
    print(f"  r1 = {hex(r1)}")
    print(f"  r2 = {hex(r2)}")
    print(f"  m1 = M + r1 = {hex(m1)}")
    print(f"  m2 = M + r2 = {hex(m2)}")
    print()

    # Attack
    result = coppersmith_short_pad_attack(c1, c2, e, n, max_pad_bits=16)

    if result:
        M_recovered, r1_recovered, r2_recovered = result
        m1_recovered = M_recovered + r1_recovered
        m2_recovered = M_recovered + r2_recovered

        print("Verification:")
        print(f"  Expected: M={hex(M)}, r1={hex(r1)}, r2={hex(r2)}")
        print(f"  Recovered m1={hex(m1_recovered)}, m2={hex(m2_recovered)}")
        print(f"  Expected m1={hex(m1)}, m2={hex(m2)}")

        if m1_recovered == m1 and m2_recovered == m2:
            print("✓ Attack successful - recovered correct padded messages!")
            print(f"  Note: Padding decomposition is one of many valid solutions")
            print(f"  (delta={hex(r2_recovered - r1_recovered)} matches expected {hex(r2-r1)})")
        else:
            print("✗ Attack produced incorrect padded messages")
    else:
        print("✗ Attack failed")
        print("  Note: This simplified implementation may fail on some inputs")
        print("  due to polynomial GCD encountering coefficients that share")
        print("  factors with n. A full implementation would handle this case.")

    print("\n" + "=" * 70 + "\n")

    # Test 2: Different padding sizes
    print("Test 2: RSA256 with e=3 and 8-bit pads")
    print("-" * 70)

    r1 = 0x42
    r2 = 0x87

    m1 = M + r1
    m2 = M + r2

    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    print(f"\nOriginal values:")
    print(f"  M = {hex(M)}")
    print(f"  r1 = {hex(r1)}")
    print(f"  r2 = {hex(r2)}")
    print()

    result = coppersmith_short_pad_attack(c1, c2, e, n, max_pad_bits=8)

    if result:
        M_recovered, r1_recovered, r2_recovered = result
        m1_recovered = M_recovered + r1_recovered
        m2_recovered = M_recovered + r2_recovered

        if m1_recovered == m1 and m2_recovered == m2:
            print("✓ Attack successful - recovered correct padded messages!")
        else:
            print("✗ Attack produced incorrect padded messages")
    else:
        print("✗ Attack failed")
        print("  Note: This simplified implementation may fail on some inputs")
        print("  due to polynomial GCD encountering coefficients that share")
        print("  factors with n. A full implementation would handle this case.")

    print("\n" + "=" * 70 + "\n")


def attack_short_pad(c1: int, c2: int, e: int, n: int, max_pad_bits: int = 64):
    """
    Convenience wrapper for the short pad attack

    Args:
        c1, c2: two ciphertexts of the same message with different pads
        e: RSA public exponent
        n: RSA modulus
        max_pad_bits: maximum padding size in bits
    """
    return coppersmith_short_pad_attack(c1, c2, e, n, max_pad_bits)


if __name__ == "__main__":
    test_short_pad_attack()

    print("\nAvailable attack functions:")
    print("- coppersmith_short_pad_attack(c1, c2, e, n, max_pad_bits)")
    print("- attack_short_pad(c1, c2, e, n, max_pad_bits)")
    print()
    print("Example usage:")
    print("  result = attack_short_pad(c1, c2, e=3, n=..., max_pad_bits=16)")
    print("  if result:")
    print("      M, r1, r2 = result")
    print("      print(f'Message: {M}')")
    print()
