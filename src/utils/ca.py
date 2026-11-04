import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple

from cryptography import x509
from cryptography.x509.oid import NameOID

SERVER_DATA_DIR = Path("serverdata")
CONFIG = SERVER_DATA_DIR / "ca.cnf"
EXTENSIONS = SERVER_DATA_DIR / "mtls.ext"

DB_DIR = SERVER_DATA_DIR / "ca"
INDEX = DB_DIR / "index.txt"
NEW_CERTS = DB_DIR / "newcerts"
CRL = DB_DIR / "crl.pem"

REVOKE_REASONS = {
    "Unspecified": "unspecified",
    "Key compromise": "keyCompromise",
    "No longer needed": "cessationOfOperation",
}


class CAError(Exception):
    pass


class Entry(NamedTuple):
    status: str
    serial: str

    @property
    def cert_path(self) -> Path:
        return NEW_CERTS / f"{self.serial}.pem"


def _openssl_ca(*args: str) -> None:
    try:
        subprocess.run(["openssl", "ca", "-batch", "-config", str(CONFIG), *args],
                       check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        logging.error("openssl ca %s failed: %s", args[0], e.stderr.strip())
        raise CAError(e.stderr) from e


def issue(csr_path: Path, cert_path: Path, not_after: str) -> None:
    _openssl_ca("-notext", "-extfile", str(EXTENSIONS), "-enddate", not_after,
                "-in", str(csr_path), "-out", str(cert_path))


def revoke(entries: list[Entry], reason: str) -> None:
    for entry in entries:
        _openssl_ca("-revoke", str(entry.cert_path), "-crl_reason", reason)
    _openssl_ca("-gencrl", "-out", str(CRL))


def active(email: str) -> list[Entry]:
    now = datetime.now(timezone.utc)
    found = []
    for line in INDEX.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) != 6 or fields[0] != "V":
            continue
        entry = Entry(fields[0], fields[3])
        cert = x509.load_pem_x509_certificate(entry.cert_path.read_bytes())
        emails = cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)
        if emails and emails[0].value == email and cert.not_valid_after_utc > now:
            found.append(entry)
    return found


def supersede(email: str, new_serial: int) -> list[str]:
    old = [e for e in active(email) if int(e.serial, 16) != new_serial]
    if old:
        revoke(old, "superseded")
    return [e.serial for e in old]
