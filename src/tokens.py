import csv
import os
from datetime import datetime
from zoneinfo import ZoneInfo

import jwt
from dotenv import load_dotenv
from unidecode import unidecode

load_dotenv()
SECRET = os.getenv("JWT_SECRET")


def get_jwt(name: str, uni_id: str, student_code: str) -> str:
    return jwt.encode({
        "exp": datetime(2026, 2, 11, tzinfo=ZoneInfo("Europe/Tallinn")),
        "name": name,
        "uniID": uni_id,
        "studentCode": student_code,
    }, SECRET, algorithm="HS256")


def get_student_token(first_name: str, last_name: str) -> str | None:
    with open("students.csv") as sf:
        csv_reader = csv.reader(sf, delimiter=";")
        for row in csv_reader:
            if unidecode(row[3].lower()) == unidecode(last_name.lower()) and unidecode(row[2].lower()) == unidecode(
                    first_name.lower()):
                return get_jwt(f"{row[2]} {row[3]}", row[1], row[0])
    return None


def main():
    with open("students.csv") as sf:
        csv_reader = csv.reader(sf, delimiter=";")
        for row in csv_reader:
            match = ""
            if row[1] == match:
                print("Token for", match)
                print(get_jwt(f"{row[2]} {row[3]}", row[1], row[0]))


if __name__ == "__main__":
    main()
