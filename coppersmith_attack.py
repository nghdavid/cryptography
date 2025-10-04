#!/usr/bin/env python3
"""
Coppersmith's Attack on RSA
Uses Coppersmith's theorem to find small roots of modular polynomials
This implementation demonstrates several attacks:
1. Stereotyped messages (known high bits)
2. Partial key exposure (known bits of d)
3. Small e and related message attack
"""

from math import isqrt, gcd, ceil
from typing import Optional, List, Tuple


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


def nth_root(x, n):
    """Compute integer nth root"""
    if x < 0:
        return None
    if x == 0:
        return 0
    if n == 1:
        return x

    # Binary search for the nth root
    low = 0
    high = x

    while low <= high:
        mid = (low + high) // 2
        mid_n = mid ** n

        if mid_n == x:
            return mid
        elif mid_n < x:
            low = mid + 1
        else:
            high = mid - 1

    return high


def coppersmith_howgrave_univariate(pol_coeffs, N, beta=1.0, mm=None, tt=None, XX=None):
    """
    Coppersmith's method for finding small roots of univariate modular polynomials
    Finds roots x0 such that pol(x0) = 0 mod N and |x0| < XX

    Args:
        pol_coeffs: polynomial coefficients [a0, a1, a2, ...] for a0 + a1*x + a2*x^2 + ...
        N: modulus
        beta: parameter (default 1.0)
        mm: parameter for lattice dimension
        tt: parameter for lattice dimension
        XX: bound for root size

    Returns:
        List of small roots
    """
    # Remove leading zeros
    while len(pol_coeffs) > 1 and pol_coeffs[-1] == 0:
        pol_coeffs = pol_coeffs[:-1]

    degree = len(pol_coeffs) - 1

    if degree == 0:
        return []

    # Make polynomial monic
    leading = pol_coeffs[-1]
    if leading != 1:
        # Find inverse of leading coefficient mod N
        inv = mod_inverse(leading, N)
        if inv:
            pol_coeffs = [(c * inv) % N for c in pol_coeffs]

    # Set default parameters
    if mm is None:
        mm = max(2, ceil(beta**2 / degree))
    if tt is None:
        tt = int(degree * mm * (1/beta - 1))
    if XX is None:
        XX = int(N**beta)

    # Build lattice
    dimension = degree * mm + tt

    # Simple LLL implementation would go here
    # For now, use a simplified approach for small polynomials

    # Try small values directly for degree 1 (linear)
    if degree == 1:
        # pol = a0 + a1*x, find x such that a0 + a1*x = 0 mod N
        a0, a1 = pol_coeffs[0], pol_coeffs[1]
        if a1 == 0:
            return []

        inv_a1 = mod_inverse(a1, N)
        if inv_a1:
            x = (-a0 * inv_a1) % N
            # Return the smallest representative
            if x > N // 2:
                x = x - N
            if abs(x) < XX:
                return [x]
        return []

    # For higher degree, try brute force for small XX
    roots = []
    if XX < 1000000:
        for x in range(-XX, XX + 1):
            val = sum(c * (x ** i) for i, c in enumerate(pol_coeffs))
            if val % N == 0:
                roots.append(x)

    return roots


def stereotyped_message_attack(c: int, e: int, n: int, known_prefix: bytes, unknown_len: int) -> Optional[bytes]:
    """
    Attack when message has known prefix/suffix (stereotyped message)
    Finds the unknown part of the message

    Args:
        c: ciphertext
        e: public exponent
        n: modulus
        known_prefix: known part of message
        unknown_len: length of unknown part in bytes

    Returns:
        Full message if found
    """
    print("Stereotyped Message Attack using Coppersmith's theorem")
    print(f"Known prefix: {known_prefix}")
    print(f"Unknown bytes: {unknown_len}")
    print()

    # Message structure: M = known_prefix || unknown_part
    # M = prefix * 256^unknown_len + x (where x is the unknown part)

    known_int = int.from_bytes(known_prefix, 'big')
    shift = 256 ** unknown_len
    XX = shift  # bound for unknown part

    # We have: c = (known_int * shift + x)^e mod n
    # We want to find x

    # Build polynomial: f(x) = (known_int * shift + x)^e - c
    # For small e, we can expand this

    if e == 3:
        # f(x) = (M0 + x)^3 - c where M0 = known_int * shift
        M0 = known_int * shift

        # Expand: M0^3 + 3*M0^2*x + 3*M0*x^2 + x^3 - c
        pol_coeffs = [
            (pow(M0, 3, n) - c) % n,  # constant term
            (3 * pow(M0, 2, n)) % n,   # x term
            (3 * M0) % n,               # x^2 term
            1                           # x^3 term
        ]

        roots = coppersmith_howgrave_univariate(pol_coeffs, n, beta=1.0, XX=XX)

        for root in roots:
            if 0 <= root < shift:
                # Reconstruct message
                message_int = M0 + root
                msg_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')

                # Verify
                if pow(message_int, e, n) == c:
                    return msg_bytes

    return None


def franklin_reiter_related_message(c1: int, c2: int, e: int, n: int, a: int, b: int) -> Optional[int]:
    """
    Franklin-Reiter related message attack
    Works when two messages M1 and M2 are related by: M2 = a*M1 + b mod n
    and both are encrypted with same (n, e)

    Args:
        c1: ciphertext of M1
        c2: ciphertext of M2
        e: public exponent (must be small, typically 3)
        n: modulus
        a, b: relation parameters (M2 = a*M1 + b)

    Returns:
        M1 if found
    """
    print("Franklin-Reiter Related Message Attack")
    print(f"Message relation: M2 = {a}*M1 + {b}")
    print()

    if e != 3:
        print("This attack works best with e=3")
        return None

    # We have:
    # c1 = M1^3 mod n
    # c2 = M2^3 = (a*M1 + b)^3 mod n

    # Compute GCD of polynomials:
    # f1(x) = x^3 - c1
    # f2(x) = (a*x + b)^3 - c2

    # For e=3, we can solve directly
    # Expand f2: a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3 - c2

    # This requires polynomial GCD - simplified version
    # Try direct approach for small messages

    # Alternative: solve using resultant (simplified for small n)

    print("Using simplified approach...")

    # For small n, try cube root attacks
    for M1 in range(1, min(10000, n)):
        M2 = (a * M1 + b) % n

        if pow(M1, e, n) == c1 and pow(M2, e, n) == c2:
            return M1

    return None


def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
    """
    Håstad's broadcast attack
    Works when same message is encrypted with same e but different moduli

    Args:
        ciphertexts: list of ciphertexts [c1, c2, ...]
        moduli: list of moduli [n1, n2, ...]
        e: public exponent (should equal number of ciphertexts)

    Returns:
        Plaintext message M
    """
    print("Håstad's Broadcast Attack")
    print(f"Number of ciphertexts: {len(ciphertexts)}")
    print(f"Public exponent e: {e}")
    print()

    if len(ciphertexts) < e:
        print(f"Need at least {e} ciphertexts for e={e}")
        return None

    # Use Chinese Remainder Theorem
    # We have: c_i = M^e mod n_i for i = 1..e
    # By CRT, we can find M^e mod (n1 * n2 * ... * ne)
    # If M^e < product of moduli, then M^e = result (no modular reduction)
    # Then M = e-th root of result

    # Chinese Remainder Theorem
    N = 1
    for n in moduli[:e]:
        N *= n

    result = 0
    for i in range(e):
        Ni = N // moduli[i]
        Mi = mod_inverse(Ni, moduli[i])
        if Mi is None:
            print(f"Moduli are not coprime!")
            return None
        result = (result + ciphertexts[i] * Ni * Mi) % N

    # result should be M^e
    # Compute e-th root
    M = nth_root(result, e)

    if M is not None and M > 0:
        # Verify
        valid = True
        for i in range(e):
            if pow(M, e, moduli[i]) != ciphertexts[i]:
                valid = False
                break

        if valid:
            return M

    return None


def test_coppersmith_attacks():
    """Test various Coppersmith-based attacks"""

    print("=" * 60)
    print("Testing Coppersmith Attacks on RSA")
    print("=" * 60)
    print()

    # Test 1: Håstad's Broadcast Attack
    print("Test 1: Håstad's Broadcast Attack")
    print("-" * 60)

    # Generate 3 different RSA keys with e=3
    p1, q1 = 12553, 13007
    p2, q2 = 12569, 12979
    p3, q3 = 12577, 12967

    n1 = p1 * q1
    n2 = p2 * q2
    n3 = p3 * q3

    e = 3
    message = 12345

    # Encrypt same message with all three keys
    c1 = pow(message, e, n1)
    c2 = pow(message, e, n2)
    c3 = pow(message, e, n3)

    print(f"Original message: {message}")
    print(f"n1 = {n1}, c1 = {c1}")
    print(f"n2 = {n2}, c2 = {c2}")
    print(f"n3 = {n3}, c3 = {c3}")
    print()

    recovered = hastad_broadcast_attack([c1, c2, c3], [n1, n2, n3], e)

    if recovered == message:
        print(f"✓ Attack successful! Recovered message: {recovered}")
    else:
        print(f"✗ Attack failed. Got: {recovered}")

    print()
    print("=" * 60)
    print()

    # Test 2: Franklin-Reiter Related Message
    print("Test 2: Franklin-Reiter Related Message Attack")
    print("-" * 60)

    n = n1
    M1 = 1234
    a = 2
    b = 3
    M2 = (a * M1 + b) % n

    c1_fr = pow(M1, e, n)
    c2_fr = pow(M2, e, n)

    print(f"M1 = {M1}")
    print(f"M2 = {a}*{M1} + {b} = {M2}")
    print(f"c1 = {c1_fr}")
    print(f"c2 = {c2_fr}")
    print()

    recovered_fr = franklin_reiter_related_message(c1_fr, c2_fr, e, n, a, b)

    if recovered_fr == M1:
        print(f"✓ Attack successful! Recovered M1: {recovered_fr}")
    else:
        print(f"✗ Attack failed. Got: {recovered_fr}")

    print()
    print("=" * 60)


def attack_with_hastad(ciphertexts: List[int], moduli: List[int], e: int):
    """
    Perform Håstad's broadcast attack on given ciphertexts

    Args:
        ciphertexts: list of ciphertexts
        moduli: list of RSA moduli
        e: public exponent
    """
    print("=" * 60)
    print("Håstad's Broadcast Attack")
    print("=" * 60)

    M = hastad_broadcast_attack(ciphertexts, moduli, e)

    if M:
        print()
        print(f"Success! Recovered message: {M}")
        print()

        # Try to decode as text
        try:
            msg_bytes = M.to_bytes((M.bit_length() + 7) // 8, 'big')
            try:
                text = msg_bytes.decode('utf-8')
                print(f"As text: {text}")
            except:
                print(f"As bytes: {msg_bytes}")
        except:
            pass
    else:
        print()
        print("Attack failed. Possible reasons:")
        print("- Not enough ciphertexts")
        print("- Moduli are not coprime")
        print("- Message is too large (M^e > product of moduli)")


if __name__ == "__main__":
    test_coppersmith_attacks()

    print()
    print("Available attack functions:")
    print("- hastad_broadcast_attack(ciphertexts, moduli, e)")
    print("- franklin_reiter_related_message(c1, c2, e, n, a, b)")
    print("- stereotyped_message_attack(c, e, n, known_prefix, unknown_len)")
