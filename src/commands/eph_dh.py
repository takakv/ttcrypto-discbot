import base64
import binascii

import nextcord
from Crypto.Cipher import AES
from Crypto.Hash import SHAKE128
from Crypto.Protocol.DH import key_agreement
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Util.Padding import unpad

PUB_PEM_START = "-----BEGIN PUBLIC KEY-----"
PUB_PEM_END = "-----END PUBLIC KEY-----"


def kdf(s: bytes, keylen: int = 16) -> bytes:
    """Derive a secret from the seed.

    :param s: The KDF seed
    :param keylen: The length of the desired secret
    :return: the derived secret
    """
    return SHAKE128.new(s).read(keylen)


async def get_ec_key(interaction: nextcord.Interaction, pubkey: str) -> EccKey:
    pubkey = pubkey[len(PUB_PEM_START):-len(PUB_PEM_END)].replace(" ", "")

    try:
        key_bytes = base64.b64decode(pubkey, validate=True)
    except binascii.Error:
        await interaction.send("Public key is not valid PEM", ephemeral=True)
        raise RuntimeError()

    try:
        key = ECC.import_key(key_bytes)
    except ValueError:
        await interaction.send("Public keys are not valid ECC keys", ephemeral=True)
        raise RuntimeError()

    if key.has_private():
        await interaction.send("!!!Submitted a private key!!!", ephemeral=True)
        raise RuntimeError()

    if key.curve != "NIST P-384":
        await interaction.send("Wrong elliptic curve", ephemeral=True)
        raise RuntimeError()

    return key


def fetch_session_key(ssk: EccKey, spk: EccKey, esk: EccKey, epk: EccKey) -> bytes:
    return key_agreement(static_priv=ssk, static_pub=spk, eph_priv=esk, eph_pub=epk, kdf=kdf)


async def aes_decrypt(interaction: nextcord.Interaction, ct_hex: str, iv_hex: str, key: bytes) -> str:
    try:
        ct_b = bytes.fromhex(ct_hex)
        iv_b = bytes.fromhex(iv_hex)
    except ValueError:
        await interaction.send("Ciphertext or IV is not valid hex", ephemeral=True)
        raise RuntimeError()

    if len(ct_b) % AES.block_size != 0:
        await interaction.send("Ciphertext is of incorrect length", ephemeral=True)
        raise RuntimeError()

    cipher = AES.new(key, AES.MODE_CBC, iv_b)
    try:
        m = unpad(cipher.decrypt(ct_b), AES.block_size).decode("utf-8")
    except UnicodeDecodeError:
        await interaction.send("Message is not printable, potential decryption failure", ephemeral=True)
        raise RuntimeError()

    return m
