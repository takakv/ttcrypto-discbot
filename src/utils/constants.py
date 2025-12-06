import logging
import os
from typing import NamedTuple

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from dotenv import load_dotenv

from src.algos.elgamal import EGSecretKey

load_dotenv()


class Client(NamedTuple):
    TOKEN = os.getenv("BOT_TOKEN")


class Secrets(NamedTuple):
    JWT_SECRET = os.getenv("JWT_SECRET")
    SYM_SECRET = int(os.getenv("SYM_SECRET"), 16)
    KEY_PWD = os.getenv("KEY_PWD")
    WFS_SECRET = bytes.fromhex(os.getenv("WFS_SECRET"))


class Keys(NamedTuple):
    P384: EccKey
    EG: EGSecretKey


def init_keys():
    with open("p384.pem", "rt") as f:
        data = f.read()
        Keys.P384 = ECC.import_key(data, Secrets.KEY_PWD)

    with open("egkey.txt", "r") as f:
        data = f.readline().strip()
        secret = int(data, 10)
        Keys.EG = EGSecretKey(secret)

    logging.info("Private keys initialised!")
