import os
import subprocess

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from dotenv import load_dotenv
from nextcord import slash_command, Interaction, SlashOption, Attachment, IntegrationType
from nextcord.ext import commands

USER_DATA_DIR = "userdata"
SERVER_DATA_DIR = "serverdata"

load_dotenv()
CA_PWD = os.getenv("CA_PWD")


class CSR(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="req",
                   description="Request a new TLS client certificate.",
                   integration_types=[IntegrationType.user_install, IntegrationType.guild_install])
    async def get_tls_cert(self, interaction: Interaction,
                           csr: Attachment = SlashOption(description="The certificate signing request.")):
        user_id = interaction.user.id
        user_datafile = f"{USER_DATA_DIR}/{user_id}.txt"

        if not os.path.isfile(user_datafile):
            await interaction.send("Not authorised to request certificates!", ephemeral=True)
            return

        with open(user_datafile, "r") as f:
            user_data = f.readlines()

        legal_name = user_data[0].strip()
        ttu_id = user_data[1].strip()
        tempfile = f"{ttu_id}.temp"
        certfile = f"{ttu_id}.crt"

        try:
            data = await csr.read()
        except Exception:
            await interaction.send("Internal error", ephemeral=True)
            return

        try:
            csr = x509.load_pem_x509_csr(data)
        except ValueError as e:
            await interaction.send(str(e), ephemeral=True)

        subject = csr.subject
        serialised = subject.rfc4514_string({NameOID.EMAIL_ADDRESS: "E"})
        expected = f"E={ttu_id}@taltech.ee,CN={legal_name},OU=ITC8280,O=TalTech,C=EE"
        if serialised != expected:
            await interaction.send(f"Certificate subject should be:\n`{expected}`\nbut was\n`{serialised}`",
                                   ephemeral=True)
            return

        with open(tempfile, "wb") as f:
            f.write(data)

        try:
            subprocess.run(["openssl", "x509", "-req",
                            "-extfile", f"{SERVER_DATA_DIR}/mtls.itc.ext",
                            "-CA", f"{SERVER_DATA_DIR}/ca.cert.pem",
                            "-CAkey", f"{SERVER_DATA_DIR}/ca.key.pem",
                            # "-passin", f"pass:{CA_PWD}",
                            "-CAcreateserial", "-sha256",
                            # "-days", "1",
                            "-not_after", "20260531145959Z",
                            "-in", tempfile,
                            "-out", certfile], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(e)
            os.remove(tempfile)
            await interaction.send("Internal server error", ephemeral=True)
            return

        with open(certfile, "r") as f:
            cert = f.read()

        os.remove(tempfile)
        os.remove(certfile)
        await interaction.send(f'```{cert}```', ephemeral=True)
