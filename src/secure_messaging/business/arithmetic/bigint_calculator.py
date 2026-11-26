"""Số học số nguyên lớn tự cài để học tập.

Lớp này minh họa thuật toán (Euclid, bình phương-nhân, Miller-Rabin,
Tonelli-Shanks) và **không** thay thế primitive mật mã của thư viện
``cryptography`` trong luồng RSA/ECC thực tế.
"""

import secrets

from secure_messaging.infrastructure.exceptions import CryptoException

# Bộ cơ sở Miller-Rabin: đủ mạnh cho số < 2^64 và là cơ sở khởi đầu cho số lớn hơn.
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
_DETERMINISTIC_LIMIT = 2**64
_RANDOM_ROUNDS = 8


class BigIntCalculator:
    """Tiện ích số học tĩnh cho số nguyên lớn."""

    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Ước chung lớn nhất theo thuật toán Euclid; luôn trả số không âm."""
        BigIntCalculator._require_int(a, "a")
        BigIntCalculator._require_int(b, "b")
        a, b = abs(a), abs(b)
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def mod_pow(base: int, exponent: int, modulus: int) -> int:
        """Lũy thừa modulo bằng bình phương-nhân (square-and-multiply)."""
        BigIntCalculator._require_int(base, "base")
        BigIntCalculator._require_int(exponent, "exponent")
        BigIntCalculator._require_int(modulus, "modulus")
        if modulus <= 0:
            raise CryptoException("Modulus phải là số nguyên dương")
        if exponent < 0:
            raise CryptoException("Số mũ phải không âm")

        result = 1
        base %= modulus
        while exponent:
            if exponent & 1:
                result = result * base % modulus
            base = base * base % modulus
            exponent >>= 1
        return result

    @staticmethod
    def mod_inverse(a: int, modulus: int) -> int:
        """Nghịch đảo modulo bằng Euclid mở rộng; ném lỗi nếu không tồn tại."""
        BigIntCalculator._require_int(a, "a")
        BigIntCalculator._require_int(modulus, "modulus")
        if modulus <= 1:
            raise CryptoException("Modulus phải lớn hơn 1")

        a %= modulus
        if a == 0:
            raise CryptoException("Không tồn tại nghịch đảo modulo của 0")

        old_r, r = a, modulus
        old_s, s = 1, 0
        while r:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s

        if old_r != 1:
            raise CryptoException("Không tồn tại nghịch đảo modulo vì gcd(a, modulus) != 1")
        return old_s % modulus

    @staticmethod
    def mod_sqrt(a: int, prime: int) -> int:
        """Căn bậc hai modulo số nguyên tố lẻ (Tonelli-Shanks).

        Trả một trong hai nghiệm; ném ``CryptoException`` nếu không tồn tại.
        """
        BigIntCalculator._require_int(a, "a")
        BigIntCalculator._require_int(prime, "prime")
        if prime <= 2 or prime % 2 == 0:
            raise CryptoException("Modulus của mod_sqrt phải là số nguyên tố lẻ")
        if not BigIntCalculator.is_probable_prime(prime):
            raise CryptoException("Modulus của mod_sqrt phải là số nguyên tố")

        a %= prime
        if a == 0:
            return 0

        if BigIntCalculator.mod_pow(a, (prime - 1) // 2, prime) != 1:
            raise CryptoException("Không tồn tại căn bậc hai modulo của giá trị đã cho")

        if prime % 4 == 3:
            return BigIntCalculator.mod_pow(a, (prime + 1) // 4, prime)

        # Tonelli-Shanks cho trường hợp p % 4 == 1.
        q = prime - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1

        z = 2
        while BigIntCalculator.mod_pow(z, (prime - 1) // 2, prime) != prime - 1:
            z += 1

        m = s
        c = BigIntCalculator.mod_pow(z, q, prime)
        t = BigIntCalculator.mod_pow(a, q, prime)
        r = BigIntCalculator.mod_pow(a, (q + 1) // 2, prime)

        while t != 1:
            i = 0
            t_squared = t
            while t_squared != 1:
                t_squared = t_squared * t_squared % prime
                i += 1
                if i == m:
                    raise CryptoException("Không thể tính căn bậc hai modulo")
            b = BigIntCalculator.mod_pow(c, 1 << (m - i - 1), prime)
            m = i
            c = b * b % prime
            t = t * c % prime
            r = r * b % prime

        return r

    @staticmethod
    def is_probable_prime(n: int) -> bool:
        """Kiểm tra nguyên tố bằng Miller-Rabin (bắt buộc với số Carmichael)."""
        BigIntCalculator._require_int(n, "n")
        if n < 2:
            return False
        for prime in _SMALL_PRIMES:
            if n == prime:
                return True
            if n % prime == 0:
                return False

        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        bases = list(_SMALL_PRIMES)
        if n >= _DETERMINISTIC_LIMIT:
            bases += [2 + secrets.randbelow(n - 3) for _ in range(_RANDOM_ROUNDS)]

        for base in bases:
            if base % n == 0:
                continue
            x = BigIntCalculator.mod_pow(base, d, n)
            if x in (1, n - 1):
                continue
            for _ in range(s - 1):
                x = x * x % n
                if x == n - 1:
                    break
            else:
                return False
        return True

    @staticmethod
    def generate_prime(bits: int) -> int:
        """Sinh số nguyên tố ngẫu nhiên đúng ``bits`` bit bằng nguồn an toàn."""
        BigIntCalculator._require_int(bits, "bits")
        if bits < 2:
            raise CryptoException("Số bit của số nguyên tố phải lớn hơn hoặc bằng 2")

        while True:
            candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if candidate <= 3:
                continue
            if BigIntCalculator.is_probable_prime(candidate):
                return candidate

    @staticmethod
    def _require_int(value: object, name: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise CryptoException(f"{name} phải là số nguyên")
