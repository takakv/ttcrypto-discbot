import os
import subprocess
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from dotenv import load_dotenv
from nextcord import slash_command, Interaction, SlashOption, Attachment, IntegrationType
from nextcord.ext import commands

from src.utils import userdata

SERVER_DATA_DIR = "serverdata"

load_dotenv()
CA_PWD = os.getenv("CA_PWD")

COURSE_TZ = ZoneInfo("Europe/Tallinn")


def load_ou() -> str:
    ou = os.getenv("CERT_OU", "").strip()
    if not ou:
        raise RuntimeError("CERT_OU is not set.")
    return ou


def load_not_after() -> str:
    raw = os.getenv("CERT_NOT_AFTER", "").strip()
    if not raw:
        raise RuntimeError("CERT_NOT_AFTER is not set.")

    try:
        exp = datetime.fromisoformat(raw)
    except ValueError as err:
        raise RuntimeError(f"CERT_NOT_AFTER is not a valid ISO 8601 date or datetime: '{raw}'") from err

    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=COURSE_TZ)

    return exp.astimezone(timezone.utc).strftime("%Y%m%d%H%M%SZ")


CERT_OU = load_ou()
CERT_NOT_AFTER = load_not_after()


class CSR(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @slash_command(name="req",
                   description="Request a new TLS client certificate.",
                   integration_types=[IntegrationType.user_install, IntegrationType.guild_install])
    async def get_tls_cert(self, interaction: Interaction,
                           csr: Attachment = SlashOption(description="The certificate signing request.")):
        student = userdata.load(interaction.user.id)
        if student is None:
            await interaction.send("Not authorised to request certificates!", ephemeral=True)
            return

        tempfile = f"{student.uni_id}.temp"
        certfile = f"{student.uni_id}.crt"

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
        expected = f"E={student.uni_id}@taltech.ee,CN={student.name},OU={CERT_OU},O=TalTech,C=EE"
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
                            "-not_after", CERT_NOT_AFTER,
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
