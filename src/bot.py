import binascii
import logging
import os
from typing import Literal

from dotenv import load_dotenv

from src.algos.shift import ShiftCipher, BShiftCipher
from src.cogs.CSR import CSR
from src.cogs.ElGamalAuthentication import ElGamalAuthentication
from src.cogs.account import Account
from src.cogs.hpke import BotHPKE
from src.cogs.shoup import Shoup
from src.cogs.wFSChallenge import WeakFSChallenge
from src.utils import userdata
from src.utils.constants import Client, init_keys, Keys

logging.basicConfig(level=logging.INFO)

load_dotenv()
GUILD_IDS = [int(os.getenv("GUILD_ID"))]
ROLE_ID = int(os.getenv("ROLE_ID"))

USED_TOKENS_FILE = "used_tokens.txt"

if not os.path.isfile(USED_TOKENS_FILE):
    open(USED_TOKENS_FILE, "w").close()

userdata.USER_DATA_DIR.mkdir(exist_ok=True)

import nextcord
from nextcord.ext import commands, application_checks
from nextcord.ext.application_checks import ApplicationMissingPermissions
from nextcord import SlashOption, IntegrationType

bot = commands.Bot()


@bot.event
async def on_ready():
    logging.info(f"Logged in as {bot.user}")


@bot.slash_command(description="Who am I?", guild_ids=GUILD_IDS)
async def whoami(interaction: nextcord.Interaction):
    student = userdata.load(interaction.user.id)
    if student is None:
        await interaction.send("I don't know :(", ephemeral=True)
        return

    await interaction.send(student.uni_id, ephemeral=True)


@bot.slash_command(description="Identify the member.", guild_ids=GUILD_IDS)
@application_checks.has_guild_permissions(administrator=True)  # Server integration failsafe
async def whois(interaction: nextcord.Interaction, user: nextcord.Member):
    student = userdata.load(user.id)
    if student is None:
        await interaction.send("unknown", ephemeral=True)
        return

    await interaction.send(student.uni_id, ephemeral=True)


@whois.error
async def whois_error(interaction: nextcord.Interaction, error):
    if isinstance(error, ApplicationMissingPermissions):
        await interaction.send("Unauthorised", ephemeral=True)


MSG_LEN_MAX = 100


@bot.slash_command(description="Use the shift cipher.",
                   integration_types=[IntegrationType.user_install, IntegrationType.guild_install])
async def shift(interaction: nextcord.Interaction,
                action: Literal["enc", "dec"] = SlashOption(
                    description="The operation to perform.",
                    choices=["enc", "dec"]),
                key: int = SlashOption(
                    description="The shift key.",
                    min_value=0, max_value=25),
                data: str = SlashOption(
                    description=f"The plaintext or the ciphertext (max {MSG_LEN_MAX} characters).",
                    max_length=MSG_LEN_MAX)):
    cipher = ShiftCipher(key)
    try:
        match action:
            case "enc":
                res = cipher.encrypt(data)
            case "dec":
                res = cipher.decrypt(data)
            case _:
                await interaction.send(f"Unknown action '{action}'", ephemeral=True)
                return

        await interaction.send(res, ephemeral=True)
    except RuntimeError as e:
        await interaction.send(f"The {str(e)}!", ephemeral=True)


@bot.slash_command(description="Use the binary shift cipher.",
                   integration_types=[IntegrationType.user_install, IntegrationType.guild_install])
async def bshift(interaction: nextcord.Interaction,
                 action: Literal["enc", "dec"] = SlashOption(
                     description="The operation to perform.",
                     choices=["enc", "dec"]),
                 key: int = SlashOption(
                     description="The shift key.",
                     min_value=0, max_value=255),
                 data: str = SlashOption(
                     description=f"The plaintext or the ciphertext (max {MSG_LEN_MAX} characters). "
                                 "Ciphertexts must be base64-encoded!",
                     max_length=MSG_LEN_MAX)):
    cipher = BShiftCipher(key)
    match action:
        case "enc":
            res = cipher.encrypt_strings(data)
        case "dec":
            try:
                res = cipher.decrypt_strings(data)
            except binascii.Error:
                await interaction.send("Ciphertext is not a valid base64 string!", ephemeral=True)
                return
        case _:
            await interaction.send(f"Unknown action '{action}'", ephemeral=True)
            return

    await interaction.send(res, ephemeral=True)


@bot.slash_command(description="List public keys.", integration_types=[IntegrationType.guild_install])
async def lpk(interaction: nextcord.Interaction):
    pub = Keys.P384.public_key()
    # Use singe quotes here since the backticks confuse some interpreters.
    pub_pem = f'```{pub.export_key(format="PEM")}```'
    await interaction.send(pub_pem, ephemeral=True)
    await interaction.send(Keys.EG.pk, ephemeral=True)


init_keys()

from src.utils import database

database.connect()

bot.add_cog(ElGamalAuthentication(bot))
bot.add_cog(CSR(bot))
bot.add_cog(Account(bot))
bot.add_cog(WeakFSChallenge(bot))
bot.add_cog(BotHPKE(bot))
bot.add_cog(Shoup(bot))

bot.run(Client.TOKEN)
