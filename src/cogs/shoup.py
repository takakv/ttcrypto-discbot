import io
import os
import re
import shutil
import zipfile

import nextcord
from nextcord import slash_command, Interaction, SlashOption, Attachment
from nextcord.ext import commands, application_checks
from nextcord.ext.application_checks import ApplicationMissingPermissions

SERVER_DATA_DIR = "serverdata"

SHOUP_VK_FILE = f"{SERVER_DATA_DIR}/shoup_vk.der"
SHOUP_PUB_FILE = f"{SERVER_DATA_DIR}/shoup_pub.pem"
SHOUP_THRESHOLD_FILE = f"{SERVER_DATA_DIR}/shoup_threshold.txt"
SHOUP_SHARES_DIR = f"{SERVER_DATA_DIR}/shoup_shares"
SHOUP_VKS_DIR = f"{SERVER_DATA_DIR}/shoup_vks"
SHOUP_SIGS_DIR = f"{SERVER_DATA_DIR}/signatures"


class Shoup(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="shoup", description="Shoup threshold signature scheme.")
    async def shoup(self, interaction: Interaction):
        pass

    @shoup.subcommand(description="Initialise the Shoup scheme with key material.")
    @application_checks.has_guild_permissions(administrator=True)
    async def init(self, interaction: Interaction,
                   keys: Attachment = SlashOption(description="ZIP containing shares/, vks/, vk.der, pub.pem."),
                   threshold: int = SlashOption(description="Minimum number of shares required.", min_value=1)):
        try:
            data = await keys.read()
        except Exception:
            await interaction.send("Failed to read the attachment.", ephemeral=True)
            return

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            await interaction.send("Attachment is not a valid ZIP file.", ephemeral=True)
            return

        names = zf.namelist()

        # Validate required root files
        for required in ("vk.der", "pub.pem"):
            if required not in names:
                await interaction.send(f"ZIP is missing required file: `{required}`", ephemeral=True)
                return

        # Validate at least one share and one vk entry
        share_files = [n for n in names if n.startswith("shares/") and n.endswith(".der") and n != "shares/"]
        vk_files = [n for n in names if n.startswith("vks/") and n.endswith(".der") and n != "vks/"]

        if not share_files:
            await interaction.send("ZIP must contain at least one `shares/*-x.der` file.", ephemeral=True)
            return

        if not vk_files:
            await interaction.send("ZIP must contain at least one `vks/*-x.der` file.", ephemeral=True)
            return

        os.makedirs(SHOUP_SHARES_DIR, exist_ok=True)
        os.makedirs(SHOUP_VKS_DIR, exist_ok=True)

        # Clear existing share and vk files
        for f in os.listdir(SHOUP_SHARES_DIR):
            os.remove(os.path.join(SHOUP_SHARES_DIR, f))
        for f in os.listdir(SHOUP_VKS_DIR):
            os.remove(os.path.join(SHOUP_VKS_DIR, f))

        with open(SHOUP_VK_FILE, "wb") as f:
            f.write(zf.read("vk.der"))

        with open(SHOUP_PUB_FILE, "wb") as f:
            f.write(zf.read("pub.pem"))

        for share_path in share_files:
            filename = os.path.basename(share_path)
            with open(os.path.join(SHOUP_SHARES_DIR, filename), "wb") as f:
                f.write(zf.read(share_path))

        for vk_path in vk_files:
            filename = os.path.basename(vk_path)
            with open(os.path.join(SHOUP_VKS_DIR, filename), "wb") as f:
                f.write(zf.read(vk_path))

        with open(SHOUP_THRESHOLD_FILE, "w") as f:
            f.write(str(threshold))

        vks_buf = io.BytesIO()
        with zipfile.ZipFile(vks_buf, "w", zipfile.ZIP_DEFLATED) as zout:
            for vk_path in vk_files:
                zout.writestr(os.path.basename(vk_path), zf.read(vk_path))
        vks_buf.seek(0)

        await interaction.send(
            f"Shoup scheme initialised: {len(share_files)} shares, {len(vk_files)} VKs, threshold={threshold}.",
            files=[
                nextcord.File(io.BytesIO(zf.read("vk.der")), filename="vk.der"),
                nextcord.File(io.BytesIO(zf.read("pub.pem")), filename="pub.pem"),
                nextcord.File(vks_buf, filename="vks.zip"),
            ])

    @init.error
    async def init_error(self, interaction: Interaction, error):
        if isinstance(error, ApplicationMissingPermissions):
            await interaction.send("Unauthorised.", ephemeral=True)

    @shoup.subcommand(description="Receive a share and its verification key.")
    async def request(self, interaction: Interaction):
        if not os.path.isfile(SHOUP_PUB_FILE):
            await interaction.send("No session is ongoing.", ephemeral=True)
            return

        if not os.path.isdir(SHOUP_SHARES_DIR) or not os.path.isdir(SHOUP_VKS_DIR):
            await interaction.send("No shares available.", ephemeral=True)
            return

        def parse_index(filename: str) -> int | None:
            m = re.search(r"-(\d+)\.der$", filename)
            return int(m.group(1)) if m else None

        shares = {parse_index(f): f for f in os.listdir(SHOUP_SHARES_DIR) if f.endswith(".der")}
        shares.pop(None, None)

        if not shares:
            await interaction.send("No shares remaining.", ephemeral=True)
            return

        idx = sorted(shares)[0]
        share_path = os.path.join(SHOUP_SHARES_DIR, shares[idx])

        with open(share_path, "rb") as f:
            share_data = f.read()

        await interaction.send(
            files=[nextcord.File(io.BytesIO(share_data), filename=shares[idx])],
            ephemeral=True,
        )

        os.remove(share_path)

    @shoup.subcommand(description="Submit your threshold signature share.")
    async def submit(self, interaction: Interaction,
                     signature: Attachment = SlashOption(description="Your signature share file.")):
        if not os.path.isfile(SHOUP_PUB_FILE):
            await interaction.send("No session is ongoing.", ephemeral=True)
            return

        dest_filename = f"{interaction.user.name}.sig"

        os.makedirs(SHOUP_SIGS_DIR, exist_ok=True)
        if os.path.isfile(os.path.join(SHOUP_SIGS_DIR, dest_filename)):
            await interaction.send("You have already submitted a signature.", ephemeral=True)
            return

        try:
            data = await signature.read()
        except Exception:
            await interaction.send("Failed to read the attachment.", ephemeral=True)
            return

        with open(os.path.join(SHOUP_SIGS_DIR, dest_filename), "wb") as f:
            f.write(data)

        await interaction.send("Signature submitted.", ephemeral=True)

    @shoup.subcommand(description="Show how many signature shares have been submitted.")
    async def track(self, interaction: Interaction):
        if not os.path.isfile(SHOUP_THRESHOLD_FILE):
            await interaction.send("The Shoup scheme has not been initialised yet.", ephemeral=True)
            return

        with open(SHOUP_THRESHOLD_FILE, "r") as f:
            threshold = int(f.read().strip())

        count = len(os.listdir(SHOUP_SIGS_DIR)) if os.path.isdir(SHOUP_SIGS_DIR) else 0
        status = "threshold reached" if count >= threshold else "threshold not yet reached"
        await interaction.send(f"{count}/{threshold} shares submitted — {status}.", ephemeral=True)

    @shoup.subcommand(description="Zip and publish all submitted signatures, then clean up.")
    @application_checks.has_guild_permissions(administrator=True)
    async def finish(self, interaction: Interaction):
        # Remove the public key file first to mark the session as finished and avoid race conditions
        # with the other commands.
        if os.path.isfile(SHOUP_PUB_FILE):
            os.remove(SHOUP_PUB_FILE)

        sig_files = os.listdir(SHOUP_SIGS_DIR) if os.path.isdir(SHOUP_SIGS_DIR) else []

        threshold = None
        if os.path.isfile(SHOUP_THRESHOLD_FILE):
            with open(SHOUP_THRESHOLD_FILE, "r") as f:
                threshold = int(f.read().strip())

        count = len(sig_files)
        threshold_met = threshold is not None and count >= threshold

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in sig_files:
                zf.write(os.path.join(SHOUP_SIGS_DIR, name), arcname=name)
        buf.seek(0)

        if threshold_met:
            msg = f"Signing session finished ({count}/{threshold})."
        else:
            status = f"{count}/{threshold}" if threshold is not None else str(count)
            msg = f"Signing session finished without reaching the threshold ({status})."
        await interaction.send(msg, file=nextcord.File(buf, filename="signatures.zip"))

        for path in (SHOUP_SHARES_DIR, SHOUP_VKS_DIR, SHOUP_SIGS_DIR):
            if os.path.isdir(path):
                shutil.rmtree(path)
        for path in (SHOUP_VK_FILE, SHOUP_THRESHOLD_FILE):
            if os.path.isfile(path):
                os.remove(path)

    @finish.error
    async def finish_error(self, interaction: Interaction, error):
        if isinstance(error, ApplicationMissingPermissions):
            await interaction.send("Unauthorised.", ephemeral=True)
