import secrets
from collections import namedtuple

from fastecdsa.curve import Curve
from fastecdsa.point import Point

EGCiphertext = namedtuple("Ciphertext", ["u", "v"])


# INSECURE! Learning purposes only. Do not use in production systems!
class EGPublicKey:
    def __init__(self, pk: Point):
        self.pk = pk
        self.curve = pk.curve

    def encrypt(self, m: Point) -> EGCiphertext:
        """Encrypt a message.

        :param m: The message to encrypt
        :return: the ElGamal ciphertext
        """
        r = secrets.randbelow(self.curve.q)
        u = r * self.curve.G

        blind = r * self.pk
        v = m + blind

        return EGCiphertext(u, v)


# INSECURE! Learning purposes only. Do not use in production systems!
class EGSecretKey:
    def __init__(self, sk: int, curve: Curve):
        self._sk = sk
        self.curve = curve
        self._pk = EGPublicKey(sk * curve.G)

    def decrypt(self, ct: EGCiphertext) -> Point:
        """Decrypt an ElGamal ciphertext.

        :param ct: The ciphertext to decrypt
        :return: the decrypted message
        """

        return ct.v - (self._sk * ct.u)

    @property
    def pk(self):
        return self._pk
