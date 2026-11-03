import os

from peewee import *

DB_DIR = "data"
os.makedirs(DB_DIR, exist_ok=True)

db = SqliteDatabase(os.path.join(DB_DIR, "bot.db"))


class EGToken(Model):
    token = CharField()
    accepted = BooleanField()
    valid = BooleanField()
    author = CharField()

    class Meta:
        table_name = "egtoken"
        database = db


def connect():
    db.connect()
    print("Connected to DB!")
    db.create_tables([EGToken])
