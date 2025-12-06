import base64
import binascii
import secrets
from hashlib import sha256

from nextcord import Interaction, slash_command, SlashOption
from nextcord.ext import commands

from src.utils.constants import Secrets

G_SIZE = 3072
RFC3526_P_3072 = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF"""
P = int.from_bytes(bytes.fromhex(RFC3526_P_3072), "big")  # Field order
Q = (P - 1) // 2  # Group order
G = 2

# Public key for fake-log purposes.
EX_SECRET = secrets.randbelow(Q)
EX_PK = pow(G, EX_SECRET, P)


def to_bytes(i: int) -> bytes:
    bl = (i.bit_length() + 7) // 8
    return i.to_bytes(bl, "big")


def generate_transcript() -> tuple[int, int, int]:
    """Generate an accepting transcript.

    The purpose of this generator is to avoid having to
    keep a log of actual authentications and transcripts.
    :return: An accepting transcript
    """
    rand = secrets.randbelow(Q)
    comm = pow(G, rand, P)

    # For ‘security’, the server only allows users who know the secret
    # to submit their public keys (i.e. loose authentication).
    fs_seed = to_bytes(comm) + Secrets.WFS_SECRET

    # Fiat-Shamir instantiated with SHA256.
    challenge_bytes = sha256(fs_seed).digest()
    challenge = int.from_bytes(challenge_bytes, "big")

    resp = ((EX_SECRET * challenge) + rand) % Q
    return EX_PK, challenge, resp


class WeakFSChallenge(commands.Cog):
    @slash_command(name="chal", description="Various challenges.")
    async def chal(self, interaction: Interaction):
        pass

    @chal.subcommand(description="Get the previous public key and proof transcript.")
    async def log(self, interaction: Interaction):
        # Generate a transcript and present it as the previous successful submission.
        prev_pk, prev_chal, prev_resp = generate_transcript()

        await interaction.response.send_message(f"\nPublic key:```{base64.b64encode(to_bytes(prev_pk)).decode()}```"
                                                f"\nChallenge: ```{base64.b64encode(to_bytes(prev_chal)).decode()}```"
                                                f"\nResponse: ```{base64.b64encode(to_bytes(prev_resp)).decode()}```",
                                                ephemeral=True)

    @chal.subcommand(description="Submit your public key and proof.")
    async def post(self, interaction: Interaction,
                   pk: str = SlashOption("pubkey", "The public key (b64-encoded integer)."),
                   comm: str = SlashOption("commitment", "The proof commitment (b64-encoded integer)."),
                   resp: str = SlashOption("response", "The challenge response (b64-encoded integer).")):

        try:
            pk = int.from_bytes(base64.b64decode(pk), "big")
            comm = int.from_bytes(base64.b64decode(comm), "big")
            resp = int.from_bytes(base64.b64decode(resp), "big")
        except binascii.Error:
            await interaction.response.send_message(
                "At least one of the outputs is not a valid base64-encoded integer.",
                ephemeral=True)
            return

        if pk == EX_PK:
            await interaction.response.send_message(
                "Public key already submitted.",
                ephemeral=True)
            return

        fs_seed = to_bytes(comm) + Secrets.WFS_SECRET

        # Fiat-Shamir instantiated with SHA256.
        challenge_bytes = sha256(fs_seed).digest()
        challenge = int.from_bytes(challenge_bytes, "big")

        gz = pow(G, resp, P)  # g^z
        hc = pow(pk, challenge, P)  # h^c
        rhs = (comm * hc) % P  # u * h^c

        if gz != rhs:
            await interaction.response.send_message(
                "Could not verify private key ownership.",
                ephemeral=True)
            return

        await interaction.response.send_message("Success! DM the solve script to Taka.", ephemeral=True)
