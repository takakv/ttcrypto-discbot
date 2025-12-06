import base64
import os
import secrets
from io import BytesIO

import gmpy2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateNumbers, \
    RSAPublicNumbers, rsa_recover_private_exponent, \
    rsa_crt_dmp1, rsa_crt_dmq1, rsa_crt_iqmp
from nextcord import slash_command, Interaction, File, SlashOption
from nextcord.ext import commands

USER_DATA_DIR = "userdata"
CHALLENGE_DATA_DIR = "userdata/rsa"


def gen_challenge() -> bytes:
    return f"challenge{{{secrets.token_hex(16)}}}".encode()


class Challenge(commands.Cog):
    @slash_command(name="chal", description="Various challenges.")
    async def chal(self, interaction: Interaction):
        pass

    @chal.subcommand(description="Get the RSA challenge.")
    async def get(self, interaction: Interaction):
        user_id = interaction.user.id
        user_key_file = f"{CHALLENGE_DATA_DIR}/{user_id}.pem"
        user_challenge_file = f"{CHALLENGE_DATA_DIR}/{user_id}.txt"

        if os.path.isfile(user_key_file):
            with open(user_key_file, "rb") as f_key:
                sk = serialization.load_pem_private_key(f_key.read(), password=None)
            with open(user_challenge_file, "rb") as f_chal:
                challenge = f_chal.read()
        else:
            sk = gen_rsa()
            challenge = gen_challenge()

            with open(user_key_file, "wb") as f_key:
                f_key.write(sk.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption()))

            with open(user_challenge_file, "wb") as f_chal:
                f_chal.write(challenge)

        pk = sk.public_key()
        ciphertext = pk.encrypt(challenge, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

        ciphertext_b64 = base64.b64encode(ciphertext)
        pem_file = BytesIO(pk.public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo))

        await interaction.response.send_message(f"Ciphertext:```{ciphertext_b64.decode()}```"
                                                f"\nHint: `openssl rsa -pubin -in {user_id}.pem -modulus -noout`",
                                                file=File(pem_file, filename=f"{user_id}.pem"), ephemeral=True)

    @chal.subcommand(description="Submit the RSA challenge.")
    async def post(self, interaction: Interaction,
                   answer: str = SlashOption("answer", "The decrypted challenge.")):
        user_id = interaction.user.id
        user_challenge_file = f"{CHALLENGE_DATA_DIR}/{user_id}.txt"
        user_answer_file = f"{CHALLENGE_DATA_DIR}/{user_id}.ok"

        if not os.path.isfile(user_challenge_file):
            await interaction.response.send_message("You must first request a challenge with `/chal get`",
                                                    ephemeral=True)
            return

        with open(user_challenge_file, "r") as f_chal:
            challenge = f_chal.read()

        if answer != challenge:
            await interaction.response.send_message("Wrong answer!", ephemeral=True)
            return

        with open(user_answer_file, "wb") as f:
            f.write(b"OK")

        await interaction.response.send_message("Congrats!", ephemeral=True)


def get_primes(bit_length: int) -> tuple[int, int]:
    lb_len = bit_length - 1
    lb = secrets.randbits(lb_len)
    rand = (1 << lb_len) | lb
    p = gmpy2.next_prime(rand)
    q = gmpy2.next_prime(p)
    return int(p), int(q)


def gen_rsa(e: int = 65537, sec_param: int = 3072) -> RSAPrivateKey:
    p, q = get_primes(sec_param)
    assert gmpy2.is_prime(p) and gmpy2.is_prime(q)

    d = rsa_recover_private_exponent(e, p, q)
    pn = RSAPrivateNumbers(p, q, d,
                           rsa_crt_dmp1(d, p),
                           rsa_crt_dmq1(d, q),
                           rsa_crt_iqmp(p, q),
                           RSAPublicNumbers(e, p * q))
    return pn.private_key(unsafe_skip_rsa_key_validation=True)
