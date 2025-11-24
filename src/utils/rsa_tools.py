"""
RSA Attack Tools for CTF Challenges

Provides various RSA attack methods including:
- Small exponent attack
- Wiener's attack for small private exponent
- Common modulus attack
- Fermat factorization
- Modular inverse calculation
"""

import math
from typing import Optional, Tuple, Dict, Any
import gmpy2
from gmpy2 import mpz


class RSATools:
    """Collection of RSA attack methods for CTF challenges"""
    
    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Calculate Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean Algorithm
        Returns (gcd, x, y) where ax + by = gcd(a, b)
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = RSATools.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    @staticmethod
    def mod_inverse(e: int, phi: int) -> Optional[int]:
        """Calculate modular inverse of e mod phi"""
        gcd, x, _ = RSATools.extended_gcd(e, phi)
        if gcd != 1:
            return None
        return (x % phi + phi) % phi
    
    @staticmethod
    def fermat_factor(n: int, max_iterations: int = 10000) -> Optional[Tuple[int, int]]:
        """
        Fermat's factorization method
        Works well when p and q are close together
        """
        a = gmpy2.isqrt(n) + 1
        b2 = a * a - n
        
        for _ in range(max_iterations):
            if gmpy2.is_square(b2):
                b = gmpy2.isqrt(b2)
                p = a - b
                q = a + b
                if p * q == n:
                    return int(p), int(q)
            a += 1
            b2 = a * a - n
        
        return None
    
    @staticmethod
    def pollard_rho(n: int, max_iterations: int = 10000) -> Optional[int]:
        """
        Pollard's Rho algorithm for factorization
        """
        if n % 2 == 0:
            return 2
        
        x = 2
        y = 2
        d = 1
        
        def f(x):
            return (x * x + 1) % n
        
        for _ in range(max_iterations):
            x = f(x)
            y = f(f(y))
            d = RSATools.gcd(abs(x - y), n)
            
            if d != 1 and d != n:
                return d
        
        return None
    
    @staticmethod
    def small_e_attack(c: int, e: int, n: int) -> Optional[int]:
        """
        Attack when e is small (typically e=3)
        If m^e < n, then c = m^e and we can just take the e-th root
        """
        if e > 10:
            return None
        
        # Try direct root
        m = gmpy2.iroot(c, e)[0]
        if pow(int(m), e) == c:
            return int(m)
        
        # Try with small multiples of n
        for k in range(100):
            m_candidate = gmpy2.iroot(c + k * n, e)
            if m_candidate[1]:  # Perfect root
                m = int(m_candidate[0])
                if pow(m, e, n) == c:
                    return m
        
        return None
    
    @staticmethod
    def wiener_attack(e: int, n: int) -> Optional[int]:
        """
        Wiener's attack for small private exponent d
        Works when d < (1/3) * n^(1/4)
        """
        # Get continued fraction convergents of e/n
        convergents = RSATools._continued_fraction_convergents(e, n)
        
        for k, d in convergents:
            if k == 0:
                continue
            
            # Check if this d works
            phi_candidate = (e * d - 1) // k
            
            # Solve x^2 - ((n - phi + 1))x + n = 0
            b = n - phi_candidate + 1
            discriminant = b * b - 4 * n
            
            if discriminant >= 0:
                sqrt_d = gmpy2.isqrt(discriminant)
                if sqrt_d * sqrt_d == discriminant:
                    p = (b + int(sqrt_d)) // 2
                    q = (b - int(sqrt_d)) // 2
                    
                    if p * q == n and p > 1 and q > 1:
                        return int(d)
        
        return None
    
    @staticmethod
    def _continued_fraction_convergents(e: int, n: int, max_convergents: int = 100):
        """Generate convergents of e/n continued fraction"""
        convergents = []
        
        # Generate continued fraction
        cf = []
        num, den = e, n
        
        for _ in range(max_convergents):
            if den == 0:
                break
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        
        # Generate convergents from continued fraction
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        
        for q in cf:
            h_next = q * h_curr + h_prev
            k_next = q * k_curr + k_prev
            
            convergents.append((k_next, h_next))
            
            h_prev, h_curr = h_curr, h_next
            k_prev, k_curr = k_curr, k_next
        
        return convergents
    
    @staticmethod
    def common_modulus_attack(c1: int, c2: int, e1: int, e2: int, n: int) -> Optional[int]:
        """
        Common modulus attack
        When same message is encrypted with different exponents using same modulus
        """
        gcd = RSATools.gcd(e1, e2)
        if gcd != 1:
            return None
        
        # Extended GCD to find s1, s2 such that s1*e1 + s2*e2 = 1
        _, s1, s2 = RSATools.extended_gcd(e1, e2)
        
        # Handle negative exponents
        if s1 < 0:
            c1 = RSATools.mod_inverse(c1, n)
            s1 = -s1
        if s2 < 0:
            c2 = RSATools.mod_inverse(c2, n)
            s2 = -s2
        
        # m = (c1^s1 * c2^s2) mod n
        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        return int(m)
    
    @staticmethod
    def decrypt_with_factors(c: int, e: int, p: int, q: int) -> int:
        """
        Decrypt ciphertext given factors p and q
        """
        n = p * q
        phi = (p - 1) * (q - 1)
        d = RSATools.mod_inverse(e, phi)
        
        if d is None:
            raise ValueError("Cannot compute modular inverse")
        
        m = pow(c, d, n)
        return int(m)
    
    @staticmethod
    def attack_rsa(n: int, e: int, c: int) -> Dict[str, Any]:
        """
        Attempt multiple RSA attacks and return results
        
        Returns dict with:
        - success: bool
        - method: str (attack method used)
        - plaintext: int (if successful)
        - factors: tuple (p, q) if found
        """
        result = {
            'success': False,
            'method': None,
            'plaintext': None,
            'factors': None
        }
        
        # Try small e attack
        m = RSATools.small_e_attack(c, e, n)
        if m:
            result['success'] = True
            result['method'] = 'Small exponent attack'
            result['plaintext'] = m
            return result
        
        # Try Fermat factorization
        factors = RSATools.fermat_factor(n)
        if factors:
            p, q = factors
            result['factors'] = (p, q)
            result['method'] = 'Fermat factorization'
            result['plaintext'] = RSATools.decrypt_with_factors(c, e, p, q)
            result['success'] = True
            return result
        
        # Try Pollard's Rho
        factor = RSATools.pollard_rho(n)
        if factor and factor != n:
            p = factor
            q = n // factor
            if p * q == n:
                result['factors'] = (p, q)
                result['method'] = 'Pollard Rho factorization'
                result['plaintext'] = RSATools.decrypt_with_factors(c, e, p, q)
                result['success'] = True
                return result
        
        # Try Wiener's attack
        d = RSATools.wiener_attack(e, n)
        if d:
            m = pow(c, d, n)
            result['success'] = True
            result['method'] = "Wiener's attack"
            result['plaintext'] = m
            return result
        
        return result
