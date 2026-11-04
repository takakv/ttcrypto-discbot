import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography import x509
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv
from nextcord import slash_command, Interaction, SlashOption, Attachment, IntegrationType
from nextcord.ext import commands

from src.utils import ca, userdata

load_dotenv()

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

        try:
            data = await csr.read()
        except Exception:
            await interaction.send("Internal error", ephemeral=True)
            return

        try:
            csr = x509.load_pem_x509_csr(data)
        except ValueError as e:
            await interaction.send(str(e), ephemeral=True)
            return

        subject = csr.subject
        serialised = subject.rfc4514_string({NameOID.EMAIL_ADDRESS: "E"})
        expected = f"E={student.uni_id}@taltech.ee,CN={student.name},OU={CERT_OU},O=TalTech,C=EE"
        if serialised != expected:
            await interaction.send(f"Certificate subject should be:\n`{expected}`\nbut was\n`{serialised}`",
                                   ephemeral=True)
            return

        with tempfile.TemporaryDirectory() as tmp:
            csr_file = Path(tmp) / "req.pem"
            cert_file = Path(tmp) / "cert.pem"
            csr_file.write_bytes(data)

            try:
                ca.issue(csr_file, cert_file, CERT_NOT_AFTER)
            except ca.CAError:
                await interaction.send("Internal server error", ephemeral=True)
                return

            cert = cert_file.read_text()

        new_serial = x509.load_pem_x509_certificate(cert.encode()).serial_number
        try:
            superseded = ca.supersede(f"{student.uni_id}@taltech.ee", new_serial)
        except ca.CAError:
            note = "\nCouldn't revoke your previous certificate."
        else:
            serials = ", ".join(f"`{s}`" for s in superseded)
            note = f"\nYour certificate {serials} has been revoked (superseded)." if superseded else ""

        await interaction.send(f'```{cert}```{note}', ephemeral=True)

    @slash_command(name="revoke",
                   description="Revoke your TLS client certificate.",
                   integration_types=[IntegrationType.user_install, IntegrationType.guild_install])
    async def revoke_cert(self, interaction: Interaction,
                          reason: str = SlashOption(description="Why the certificate is revoked.",
                                                    choices=ca.REVOKE_REASONS, default="unspecified",
                                                    required=False)):
        student = userdata.load(interaction.user.id)
        if student is None:
            await interaction.send("Not authorised to revoke certificates!", ephemeral=True)
            return

        entries = ca.active(f"{student.uni_id}@taltech.ee")
        if not entries:
            await interaction.send("You have no active certificate.", ephemeral=True)
            return

        try:
            ca.revoke(entries, reason)
        except ca.CAError:
            await interaction.send("Internal server error", ephemeral=True)
            return

        serials = ", ".join(f"`{e.serial}`" for e in entries)
        await interaction.send(f"Revoked certificate {serials}.", ephemeral=True)
