#!/usr/bin/env python3
"""
Franklin-Reiter Related Message Attack on RSA

This attack exploits a vulnerability when:
1. Two related messages M1 and M2 are encrypted
2. The relation is linear: M2 = a*M1 + b (mod n)
3. Both encrypted with the same RSA modulus n and small exponent e (typically e=3)
4. No proper padding is used

The attack works by:
- We have: C1 = M1^e mod n and C2 = M2^e mod n
- We know M2 = a*M1 + b
- We can construct two polynomials over the same unknown M1
- Using polynomial GCD, we can recover M1

This is a special case of Coppersmith's attack and demonstrates:
- Why related messages are dangerous
- Why small public exponents need padding
- The power of polynomial-based cryptanalysis

Attack variations:
1. Known linear relation: M2 = a*M1 + b
2. Known prefix/suffix: Special case where a=1, b=known_part
3. Multiple related messages
"""

from math import gcd as math_gcd
from typing import Optional, Tuple, List


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm"""
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


class Polynomial:
    """
    Polynomial class for modular arithmetic
    Represents polynomials over Z/nZ
    """

    def __init__(self, coeffs: List[int], modulus: int):
        """
        Create polynomial with coefficients [a0, a1, a2, ...]
        representing a0 + a1*x + a2*x^2 + ...

        Args:
            coeffs: List of coefficients (low to high degree)
            modulus: Modulus for coefficient arithmetic
        """
        self.modulus = modulus
        # Remove leading zeros
        while len(coeffs) > 1 and coeffs[-1] % modulus == 0:
            coeffs.pop()
        self.coeffs = [c % modulus for c in coeffs]

    def degree(self) -> int:
        """Return degree of polynomial"""
        return len(self.coeffs) - 1

    def __repr__(self) -> str:
        """String representation"""
        if not self.coeffs:
            return "0"

        terms = []
        for i, c in enumerate(self.coeffs):
            if c == 0:
                continue

            if i == 0:
                terms.append(str(c))
            elif i == 1:
                if c == 1:
                    terms.append("x")
                else:
                    terms.append(f"{c}*x")
            else:
                if c == 1:
                    terms.append(f"x^{i}")
                else:
                    terms.append(f"{c}*x^{i}")

        return " + ".join(terms) if terms else "0"

    def __add__(self, other):
        """Add two polynomials"""
        if isinstance(other, int):
            result = self.coeffs.copy()
            result[0] = (result[0] + other) % self.modulus
            return Polynomial(result, self.modulus)

        max_len = max(len(self.coeffs), len(other.coeffs))
        result = [0] * max_len

        for i in range(len(self.coeffs)):
            result[i] = self.coeffs[i]

        for i in range(len(other.coeffs)):
            result[i] = (result[i] + other.coeffs[i]) % self.modulus

        return Polynomial(result, self.modulus)

    def __sub__(self, other):
        """Subtract two polynomials"""
        if isinstance(other, int):
            result = self.coeffs.copy()
            result[0] = (result[0] - other) % self.modulus
            return Polynomial(result, self.modulus)

        max_len = max(len(self.coeffs), len(other.coeffs))
        result = [0] * max_len

        for i in range(len(self.coeffs)):
            result[i] = self.coeffs[i]

        for i in range(len(other.coeffs)):
            result[i] = (result[i] - other.coeffs[i]) % self.modulus

        return Polynomial(result, self.modulus)

    def __mul__(self, other):
        """Multiply two polynomials"""
        if isinstance(other, int):
            return Polynomial([c * other for c in self.coeffs], self.modulus)

        result = [0] * (len(self.coeffs) + len(other.coeffs) - 1)

        for i in range(len(self.coeffs)):
            for j in range(len(other.coeffs)):
                result[i + j] = (result[i + j] + self.coeffs[i] * other.coeffs[j]) % self.modulus

        return Polynomial(result, self.modulus)

    def __mod__(self, other):
        """Polynomial division - return remainder"""
        return self.divmod(other)[1]

    def divmod(self, other):
        """
        Polynomial division
        Returns (quotient, remainder)
        """
        if other.degree() == 0 and other.coeffs[0] == 0:
            raise ZeroDivisionError("Division by zero polynomial")

        remainder = Polynomial(self.coeffs.copy(), self.modulus)
        quotient = Polynomial([0], self.modulus)

        while remainder.degree() >= other.degree() and remainder.coeffs:
            # Get leading coefficients
            lead_r = remainder.coeffs[-1]
            lead_d = other.coeffs[-1]

            # Compute leading coefficient of quotient term
            lead_d_inv = mod_inverse(lead_d, self.modulus)
            if lead_d_inv is None:
                break

            coef = (lead_r * lead_d_inv) % self.modulus
            deg_diff = remainder.degree() - other.degree()

            # Build quotient term
            term_coeffs = [0] * (deg_diff + 1)
            term_coeffs[deg_diff] = coef
            term = Polynomial(term_coeffs, self.modulus)

            quotient = quotient + term
            remainder = remainder - (term * other)

        return quotient, remainder

    def evaluate(self, x: int) -> int:
        """Evaluate polynomial at x"""
        result = 0
        x_power = 1

        for c in self.coeffs:
            result = (result + c * x_power) % self.modulus
            x_power = (x_power * x) % self.modulus

        return result


def polynomial_gcd(p1: Polynomial, p2: Polynomial) -> Polynomial:
    """
    Compute GCD of two polynomials using Euclidean algorithm
    """
    a, b = p1, p2

    while b.degree() > 0 or (b.degree() == 0 and b.coeffs[0] != 0):
        _, remainder = a.divmod(b)
        a, b = b, remainder

    return a


def franklin_reiter_attack(c1: int, c2: int, n: int, e: int, a: int, b: int) -> Optional[int]:
    """
    Franklin-Reiter Related Message Attack

    Given:
    - C1 = M1^e mod n
    - C2 = M2^e mod n
    - M2 = a*M1 + b (mod n)

    Recover M1

    Args:
        c1: First ciphertext
        c2: Second ciphertext
        n: RSA modulus
        e: Public exponent (works best with e=3)
        a: Linear coefficient in relation M2 = a*M1 + b
        b: Constant term in relation M2 = a*M1 + b

    Returns:
        M1 (first plaintext message)
    """

    print("=" * 70)
    print("Franklin-Reiter Related Message Attack")
    print("=" * 70)
    print()

    print(f"Given:")
    print(f"  C1 = {c1}")
    print(f"  C2 = {c2}")
    print(f"  n  = {n}")
    print(f"  e  = {e}")
    print(f"  Relation: M2 = {a}*M1 + {b} (mod n)")
    print()

    # Construct polynomials
    # f1(x) = x^e - c1
    # f2(x) = (a*x + b)^e - c2

    print(f"Step 1: Construct polynomials over Z/{n}Z[x]")
    print(f"  f1(x) = x^{e} - {c1}")
    print(f"  f2(x) = ({a}*x + {b})^{e} - {c2}")
    print()

    # Build f1(x) = x^e - c1
    f1_coeffs = [0] * (e + 1)
    f1_coeffs[e] = 1
    f1_coeffs[0] = -c1
    f1 = Polynomial(f1_coeffs, n)

    # Build f2(x) = (a*x + b)^e - c2
    # Expand (a*x + b)^e using binomial theorem
    f2_coeffs = [0] * (e + 1)

    # Binomial expansion
    for k in range(e + 1):
        # Coefficient of x^k in (a*x + b)^e is C(e,k) * a^k * b^(e-k)
        # Compute binomial coefficient C(e, k)
        binom_coeff = 1
        for i in range(k):
            binom_coeff = binom_coeff * (e - i) // (i + 1)

        coeff = (binom_coeff * pow(a, k, n) * pow(b, e - k, n)) % n
        f2_coeffs[k] = coeff

    f2_coeffs[0] = (f2_coeffs[0] - c2) % n
    f2 = Polynomial(f2_coeffs, n)

    print(f"Step 2: Compute GCD of f1(x) and f2(x)")
    print(f"  Both polynomials have (x - M1) as a factor")
    print(f"  Their GCD should be (x - M1) or a scalar multiple")
    print()

    # Compute GCD
    g = polynomial_gcd(f1, f2)

    print(f"  GCD polynomial: {g}")
    print(f"  GCD degree: {g.degree()}")
    print()

    # The GCD should be linear: g(x) = a*(x - M1)
    if g.degree() == 1:
        print("Step 3: Extract M1 from linear GCD")

        # GCD is of form: a1*x + a0
        # Roots: x = -a0/a1 = -a0 * a1^(-1) mod n
        a0 = g.coeffs[0]
        a1 = g.coeffs[1]

        a1_inv = mod_inverse(a1, n)
        if a1_inv is None:
            print(f"  ❌ Cannot compute inverse of {a1} mod {n}")
            return None

        m1 = (-a0 * a1_inv) % n
        m2 = (a * m1 + b) % n
        print(f"  Linear GCD: {a1}*x + {a0}")
        print(f"  Root: x = -{a0} * {a1}^(-1) mod {n}")
        print(f"  M1 = {m1}")
        print(f"  M2 = {m2}")
        print()

        # Verify
        print("Step 4: Verification")
        c1_check = pow(m1, e, n)
        
        c2_check = pow(m2, e, n)

        print(f"  M1 = {m1}")
        print(f"  M1^{e} mod {n} = {c1_check} {'==' if c1_check == c1 else '!='} {c1}")
        print(f"  M2 = {a}*{m1} + {b} = {m2}")
        print(f"  M2^{e} mod {n} = {c2_check} {'==' if c2_check == c2 else '!='} {c2}")
        print()

        if c1_check == c1 and c2_check == c2:
            print("✅ Attack successful!")
            return m1
        else:
            print("❌ Verification failed")
            return None

    elif g.degree() == 0:
        print("  ❌ GCD is constant - polynomials are coprime")
        print("  Attack failed - messages may not be related as specified")
        return None

    else:
        print(f"  ⚠️  GCD has degree {g.degree()} (expected 1)")
        print("  Trying to extract roots...")

        # For small degree, try to find roots by brute force
        if g.degree() <= 2 and n < 1000000:
            for m1 in range(n):
                if g.evaluate(m1) == 0:
                    print(f"  Found root: M1 = {m1}")
                    return m1

        print("  ❌ Cannot extract M1 from high-degree GCD")
        return None

def test_franklin_reiter():
    """Test Franklin-Reiter attack with examples"""

    print("=" * 70)
    print("TESTING FRANKLIN-REITER ATTACK")
    print("=" * 70)
    print()

    # Example 1: Simple relation
    print("Example 1: Simple Linear Relation")
    print("-" * 70)
    print()

    # RSA parameters
    p, q = 1009, 1013
    n = p * q
    e = 3

    # Original messages
    m1 = 123
    a = 2
    b = 5
    m2 = (a * m1 + b) % n

    print(f"Setup:")
    print(f"  RSA modulus: n = {p} × {q} = {n}")
    print(f"  Public exponent: e = {e}")
    print(f"  Message 1: M1 = {m1}")
    print(f"  Message 2: M2 = {a}*M1 + {b} = {m2}")
    print()

    # Encrypt
    c1 = pow(m1, e, n)
    c2 = pow(m2, e, n)

    print(f"Encrypted:")
    print(f"  C1 = {c1}")
    print(f"  C2 = {c2}")
    print()
    print("-" * 70)
    print()

    # Attack
    recovered_m1 = franklin_reiter_attack(c1, c2, n, e, a, b)

    print("=" * 70)
    print("RESULT")
    print("=" * 70)

    if recovered_m1 == m1:
        print(f"✅ SUCCESS!")
        print(f"   Original M1: {m1}")
        print(f"   Recovered M1: {recovered_m1}")
    else:
        print(f"❌ FAILED")
        print(f"   Expected: {m1}")
        print(f"   Got: {recovered_m1}")

if __name__ == "__main__":
    test_franklin_reiter()

    print("\n" + "=" * 70)
    print("USAGE")
    print("=" * 70)
    print()
    print("To attack your own ciphertexts:")
    print("  franklin_reiter_attack(c1, c2, n, e, a, b)")
    print()
    print("Where:")
    print("  c1, c2 = ciphertexts of related messages")
    print("  n = RSA modulus")
    print("  e = public exponent (typically 3)")
    print("  a, b = relation parameters (M2 = a*M1 + b)")
    print()
    print("Common scenarios:")
    print("  • Known difference: a=1, b=M2-M1")
    print("  • Known prefix/suffix: Compute a, b from known parts")
    print("  • Linear relation: Any a*M1 + b relation")
