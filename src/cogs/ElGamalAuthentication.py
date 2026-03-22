from fastecdsa.curve import P384
from fastecdsa.encoding.sec1 import SEC1Encoder, InvalidSEC1PublicKey
from nextcord import slash_command, Interaction, SlashOption, IntegrationType
from nextcord.ext import commands
from peewee import DoesNotExist

from src.algos.elgamal import EGCiphertext
from src.utils.constants import Keys, Secrets
from src.utils.database import EGToken


class ElGamalAuthentication(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="eg_auth",
                   description="Authenticate using ElGamal.",
                   integration_types=[IntegrationType.guild_install])
    async def authenticate(self, interaction: Interaction):
        pass

    @authenticate.subcommand(description="Show the public key.")
    async def pk(self, interaction: Interaction):
        await interaction.send(f"```{Keys.P384.public_key().export_key(format='PEM')}```", ephemeral=True)

    @authenticate.subcommand(description="Show the previous successful token.")
    async def show_token(self, interaction: Interaction):
        try:
            token = EGToken.select().where(EGToken.accepted).order_by(EGToken.id.desc()).get()
        except DoesNotExist:
            await interaction.send("No successful authentications yet.", ephemeral=True)
            return

        s = token.token.split(" ")
        u = s[0]
        v = s[1]

        await interaction.send(f'```u=\n{u}\nv=\n{v}```', ephemeral=True)

    @authenticate.subcommand(description="Connect to the server.")
    async def connect(self, interaction: Interaction,
                      u: str = SlashOption(description="The randomness component."),
                      v: str = SlashOption(description="The message component.")):
        try:
            u_bytes = bytes.fromhex(u)
            v_bytes = bytes.fromhex(v)
        except ValueError:
            await interaction.send("The components must be hex-encoded!", ephemeral=True)
            return

        serialised = f"{u} {v}"

        curve = P384
        try:
            u = SEC1Encoder.decode_public_key(u_bytes, curve)
            v = SEC1Encoder.decode_public_key(v_bytes, curve)
        except InvalidSEC1PublicKey:
            await interaction.send("The components are not valid P-384 encoded points!", ephemeral=True)
            return

        uid = interaction.user.id
        token_is_accepted = False

        try:
            EGToken.get(EGToken.token == serialised)
        except DoesNotExist:
            token_is_accepted = True

        ct = EGCiphertext(u, v)
        try:
            res = Keys.EG.decrypt(ct)
        except ValueError as e:
            await interaction.send(str(e), ephemeral=True)
            raise RuntimeError

        message = "Invalid token! Access denied."

        match = Secrets.SYM_SECRET * curve.G
        if res == match:
            message = "Access granted."
            token_is_valid = True
            if not token_is_accepted:
                # Do not check usage before verifying decryption to
                # help students detect whether their token would have worked.
                message = "Token has already been used."
        else:
            token_is_valid = False
            token_is_accepted = False

        EGToken.create(token=serialised, accepted=token_is_accepted, valid=token_is_valid, author=uid)
        await interaction.send(message, ephemeral=True)
