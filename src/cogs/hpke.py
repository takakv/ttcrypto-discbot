import base64

from Crypto.Protocol import HPKE
from nextcord import slash_command, Interaction, SlashOption
from nextcord.ext import commands

from src.commands.eph_dh import get_ec_key
from src.utils.constants import Keys


class BotHPKE(commands.Cog):
    @slash_command(name="hpke", description="HPKE base mode.")
    async def hpke(self, interaction: Interaction):
        pass

    @hpke.subcommand(description="Get server public key.")
    async def pub(self, interaction: Interaction):
        pub = Keys.P384.public_key()
        # Use singe quotes here since the backticks confuse some interpreters.
        pub_pem = f'```{pub.export_key(format="PEM")}```'
        await interaction.send(pub_pem, ephemeral=True)

    @hpke.subcommand(description="Establish AES-128-GCM key and receive ciphertext.")
    async def challenge(self, interaction: Interaction,
                        pubkey: str = SlashOption(description="Your ephemeral public key.")):
        try:
            key = await get_ec_key(interaction, pubkey)
        except RuntimeError:
            return

        encryptor = HPKE.new(receiver_key=key,
                             aead_id=HPKE.AEAD.AES128_GCM,
                             info="ITC8280 week 6".encode())
        ct = encryptor.seal(f"Hello {interaction.user.name}!".encode())

        try:
            message = base64.b64encode(ct).decode()
        except RuntimeError:
            return

        capsule = base64.b64encode(encryptor.enc).decode()
        await interaction.send(
            f'KEM capsule:\n```{capsule}```\n'
            f'AES-128-GCM encrypted ciphertext:\n```{message}```',
            ephemeral=True)
