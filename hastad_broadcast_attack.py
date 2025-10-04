#!/usr/bin/env python3
"""
Håstad's Broadcast Attack on RSA

This attack exploits a critical vulnerability when:
1. The same message M is encrypted multiple times
2. Using the same small public exponent e (typically e=3)
3. With different RSA moduli (n1, n2, n3, ...)
4. No proper padding is used (textbook RSA)

The attack works because:
- If we have e ciphertexts: c1 = M^e mod n1, c2 = M^e mod n2, ..., ce = M^e mod ne
- Using Chinese Remainder Theorem (CRT), we can compute M^e mod (n1*n2*...*ne)
- If M^e < n1*n2*...*ne (which is likely for small e), then M^e has no modular reduction
- We can then compute the e-th root of M^e to recover M directly

This attack demonstrates why:
- Small public exponents (e=3) are dangerous without proper padding
- The same message should never be sent to multiple recipients without randomization
- PKCS#1 v1.5 or OAEP padding is essential
"""

from math import gcd
from typing import List, Optional, Tuple


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm
    Returns (gcd, x, y) such that a*x + b*y = gcd
    """
    if a == 0:
        return b, 0, 1

    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> Optional[int]:
    """
    Compute modular multiplicative inverse of a modulo m
    Returns a^(-1) mod m, or None if it doesn't exist
    """
    gcd_val, x, _ = extended_gcd(a, m)

    if gcd_val != 1:
        return None  # Inverse doesn't exist

    return (x % m + m) % m


def chinese_remainder_theorem(remainders: List[int], moduli: List[int]) -> Optional[int]:
    """
    Chinese Remainder Theorem
    Given: x ≡ r1 (mod n1), x ≡ r2 (mod n2), ...
    Find: x mod (n1*n2*...)

    Args:
        remainders: [r1, r2, r3, ...]
        moduli: [n1, n2, n3, ...]

    Returns:
        x such that x ≡ ri (mod ni) for all i
    """
    if len(remainders) != len(moduli):
        return None

    # Check that moduli are pairwise coprime
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                print(f"Error: Moduli {moduli[i]} and {moduli[j]} are not coprime!")
                print(f"GCD = {gcd(moduli[i], moduli[j])}")
                return None

    # Compute product of all moduli
    N = 1
    for n in moduli:
        N *= n

    # Apply CRT formula
    result = 0

    for i in range(len(moduli)):
        # Ni = N / ni
        Ni = N // moduli[i]

        # Mi = Ni^(-1) mod ni
        Mi = mod_inverse(Ni, moduli[i])

        if Mi is None:
            print(f"Error: Cannot compute inverse of {Ni} mod {moduli[i]}")
            return None

        # Add contribution: ri * Ni * Mi
        result = (result + remainders[i] * Ni * Mi) % N

    return result


def nth_root(x: int, n: int) -> Optional[int]:
    """
    Compute integer n-th root of x
    Returns the largest integer r such that r^n <= x

    Uses binary search for efficiency
    """
    if x < 0:
        return None
    if x == 0:
        return 0
    if n == 1:
        return x

    # Binary search for the n-th root
    low = 0
    high = x

    # Optimization: better upper bound
    if x > 1:
        high = 1
        while high ** n < x:
            high *= 2

    result = 0

    while low <= high:
        mid = (low + high) // 2
        mid_n = mid ** n

        if mid_n == x:
            return mid
        elif mid_n < x:
            result = mid
            low = mid + 1
        else:
            high = mid - 1

    return result


def hastad_broadcast_attack(ciphertexts: List[int], moduli: List[int], e: int) -> Optional[int]:
    """
    Perform Håstad's Broadcast Attack

    Attack scenario:
    - Same message M is encrypted with same exponent e
    - Using different RSA moduli (different public keys)
    - c_i = M^e mod n_i

    Args:
        ciphertexts: List of ciphertexts [c1, c2, ..., ce]
        moduli: List of moduli [n1, n2, ..., ne]
        e: Public exponent (must equal number of ciphertexts)

    Returns:
        Plaintext message M, or None if attack fails
    """
    print("=" * 70)
    print("Håstad's Broadcast Attack")
    print("=" * 70)
    print()

    # Validate input
    if len(ciphertexts) < e:
        print(f"❌ Error: Need at least {e} ciphertexts for e={e}")
        print(f"   Only have {len(ciphertexts)} ciphertexts")
        return None

    if len(ciphertexts) != len(moduli):
        print(f"❌ Error: Number of ciphertexts ({len(ciphertexts)}) != number of moduli ({len(moduli)})")
        return None

    # Use only first e ciphertexts/moduli
    c_list = ciphertexts[:e]
    n_list = moduli[:e]

    print(f"Attack parameters:")
    print(f"  Public exponent e: {e}")
    print(f"  Number of ciphertexts: {len(c_list)}")
    print()

    for i, (c, n) in enumerate(zip(c_list, n_list), 1):
        print(f"  Ciphertext {i}: c{i} = {c} (mod n{i} = {n})")
    print()

    # Step 1: Apply Chinese Remainder Theorem
    print("Step 1: Applying Chinese Remainder Theorem...")
    print(f"  Finding x such that x ≡ ci (mod ni) for all i")
    print()

    M_to_e = chinese_remainder_theorem(c_list, n_list)

    if M_to_e is None:
        print("❌ CRT failed - moduli may not be coprime")
        return None

    # Compute product of moduli
    N_product = 1
    for n in n_list:
        N_product *= n

    print(f"  CRT result: M^{e} ≡ {M_to_e} (mod N)")
    print(f"  where N = n1 × n2 × ... × n{e}")
    print(f"  N = {N_product}")
    print()

    # Step 2: Check if M^e < N (no modular reduction occurred)
    print("Step 2: Checking if M^e < N...")

    if M_to_e >= N_product:
        print(f"  ❌ Warning: M^{e} >= N")
        print(f"     This means modular reduction occurred")
        print(f"     Attack may fail - message might be too large")
        print()
        # Try anyway
    else:
        print(f"  ✓ M^{e} < N (no modular reduction)")
        print(f"     This means M^{e} = {M_to_e} exactly")
        print()

    # Step 3: Compute e-th root to recover M
    print(f"Step 3: Computing {e}-th root to recover M...")
    print(f"  Finding M such that M^{e} = {M_to_e}")
    print()

    M = nth_root(M_to_e, e)

    if M is None:
        print("❌ Failed to compute e-th root")
        return None

    # Verify the result
    M_e_check = M ** e

    print(f"Step 4: Verification...")
    print(f"  Candidate M = {M}")
    print(f"  M^{e} = {M_e_check}")
    print()

    # Check against all original ciphertexts
    all_valid = True
    for i, (c, n) in enumerate(zip(c_list, n_list), 1):
        computed_c = pow(M, e, n)
        matches = (computed_c == c)
        status = "✓" if matches else "❌"
        print(f"  {status} Ciphertext {i}: {M}^{e} mod {n} = {computed_c} {'==' if matches else '!='} {c}")

        if not matches:
            all_valid = False

    print()

    if all_valid:
        print("✅ Attack successful! Message recovered.")
        return M
    else:
        print("❌ Verification failed - attack unsuccessful")
        return None


def generate_rsa_key_pair(p: int, q: int, e: int) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA key pair from primes p, q and exponent e

    Returns:
        ((e, n), (d, n)) - public key and private key
    """
    n = p * q
    phi = (p - 1) * (q - 1)

    # Check if e is valid
    if gcd(e, phi) != 1:
        raise ValueError(f"e={e} and phi={phi} are not coprime")

    d = mod_inverse(e, phi)

    if d is None:
        raise ValueError(f"Cannot compute d for e={e}")

    return ((e, n), (d, n))


def test_hastad_attack():
    """
    Test Håstad's Broadcast Attack with concrete examples
    """
    print("=" * 70)
    print("TESTING HÅSTAD'S BROADCAST ATTACK")
    print("=" * 70)
    print()

    # Common public exponent (small and dangerous!)
    e = 3

    # Message to encrypt
    message = 42

    print(f"Scenario: Broadcasting message M = {message}")
    print(f"Using public exponent e = {e}")
    print(f"Encrypting with 3 different RSA public keys (no padding!)")
    print()

    # Generate 3 different RSA key pairs with different moduli
    # Using small primes for demonstration

    # Key pair 1
    p1, q1 = 1009, 1013
    n1 = p1 * q1

    # Key pair 2
    p2, q2 = 1021, 1031
    n2 = p2 * q2

    # Key pair 3
    p3, q3 = 1033, 1039
    n3 = p3 * q3

    print("Three recipients with different RSA keys:")
    print(f"  Recipient 1: n1 = {p1} × {q1} = {n1}")
    print(f"  Recipient 2: n2 = {p2} × {q2} = {n2}")
    print(f"  Recipient 3: n3 = {p3} × {q3} = {n3}")
    print()

    # Encrypt the same message with all three public keys
    c1 = pow(message, e, n1)
    c2 = pow(message, e, n2)
    c3 = pow(message, e, n3)

    print("Encrypted messages (intercepted by attacker):")
    print(f"  c1 = {c1}")
    print(f"  c2 = {c2}")
    print(f"  c3 = {c3}")
    print()
    print("-" * 70)
    print()

    # Perform the attack
    recovered_message = hastad_broadcast_attack([c1, c2, c3], [n1, n2, n3], e)

    print("=" * 70)
    print("RESULT")
    print("=" * 70)

    if recovered_message == message:
        print(f"✅ SUCCESS!")
        print(f"   Original message: {message}")
        print(f"   Recovered message: {recovered_message}")
        print()
        print("This demonstrates why:")
        print("  • Small public exponents (e=3) are dangerous without padding")
        print("  • Same message should NEVER be sent to multiple recipients")
        print("  • PKCS#1 v1.5 or OAEP padding is essential")
    else:
        print(f"❌ FAILED")
        print(f"   Expected: {message}")
        print(f"   Got: {recovered_message}")


def test_hastad_with_text():
    """
    Test with a text message
    """
    print("\n" + "=" * 70)
    print("TESTING WITH TEXT MESSAGE")
    print("=" * 70)
    print()

    e = 3

    # Convert text to integer
    message_text = "Hi"
    message = int.from_bytes(message_text.encode(), 'big')

    print(f"Broadcasting message: '{message_text}'")
    print(f"As integer: {message}")
    print()

    # Three different RSA moduli (larger for text)
    p1, q1 = 12553, 12569
    p2, q2 = 12577, 12583
    p3, q3 = 12589, 12601

    n1 = p1 * q1
    n2 = p2 * q2
    n3 = p3 * q3

    # Encrypt
    c1 = pow(message, e, n1)
    c2 = pow(message, e, n2)
    c3 = pow(message, e, n3)

    print(f"Three RSA moduli:")
    print(f"  n1 = {n1}")
    print(f"  n2 = {n2}")
    print(f"  n3 = {n3}")
    print()

    # Attack
    recovered = hastad_broadcast_attack([c1, c2, c3], [n1, n2, n3], e)

    if recovered:
        # Convert back to text
        try:
            recovered_bytes = recovered.to_bytes((recovered.bit_length() + 7) // 8, 'big')
            recovered_text = recovered_bytes.decode('utf-8')

            print("=" * 70)
            print(f"✅ Recovered message: '{recovered_text}'")
            print("=" * 70)
        except:
            print(f"Recovered integer: {recovered}")


if __name__ == "__main__":
    test_hastad_attack()
    print()
    test_hastad_with_text()

    print("\n" + "=" * 70)
    print("USAGE")
    print("=" * 70)
    print()
    print("To attack your own ciphertexts:")
    print("  hastad_broadcast_attack(ciphertexts, moduli, e)")
    print()
    print("Example:")
    print("  ciphertexts = [c1, c2, c3]")
    print("  moduli = [n1, n2, n3]")
    print("  e = 3")
    print("  message = hastad_broadcast_attack(ciphertexts, moduli, e)")
