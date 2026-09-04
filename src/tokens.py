import argparse
import csv
import os
from datetime import datetime
from typing import Iterator, NamedTuple
from zoneinfo import ZoneInfo

import jwt
from dotenv import load_dotenv
from unidecode import unidecode

load_dotenv()
SECRET = os.getenv("JWT_SECRET")

TOKEN_EXP_VAR = "TOKEN_EXP"
COURSE_TZ = ZoneInfo("Europe/Tallinn")

STUDENTS_FILE = "students.csv"


def normalise_name(name: str) -> str:
    return unidecode(name.strip().lower())


class StudentRecord(NamedTuple):
    student_code: str
    uni_id: str
    first_name: str
    last_name: str

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def matches(self, first_name: str, last_name: str) -> bool:
        return (normalise_name(self.first_name) == normalise_name(first_name)
                and normalise_name(self.last_name) == normalise_name(last_name))


def read_students() -> Iterator[StudentRecord]:
    with open(STUDENTS_FILE) as sf:
        rows = csv.reader(sf, delimiter=";")
        next(rows, None)  # Headings
        for row in rows:
            if len(row) < len(StudentRecord._fields):
                continue
            yield StudentRecord(*row[:len(StudentRecord._fields)])


def load_expiry() -> datetime:
    raw = os.getenv(TOKEN_EXP_VAR)
    if not raw:
        raise RuntimeError(
            f"{TOKEN_EXP_VAR} is not set. Expected an ISO 8601 date or datetime.")

    try:
        exp = datetime.fromisoformat(raw.strip())
    except ValueError as err:
        raise RuntimeError(
            f"{TOKEN_EXP_VAR} is not a valid ISO 8601 date or datetime: '{raw}'") from err

    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=COURSE_TZ)

    return exp


EXPIRY = load_expiry()


def get_jwt(name: str, uni_id: str, student_code: str) -> str:
    return jwt.encode({
        "exp": EXPIRY,
        "name": name,
        "uniID": uni_id,
        "studentCode": student_code,
    }, SECRET, algorithm="HS256")


def get_student_token(first_name: str, last_name: str) -> str | None:
    for student in read_students():
        if student.matches(first_name, last_name):
            return get_jwt(student.full_name, student.uni_id, student.student_code)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("uni_id", nargs="+")
    args = parser.parse_args()

    wanted = set(args.uni_id)
    for student in read_students():
        if student.uni_id in wanted:
            wanted.discard(student.uni_id)
            print("Token for", student.uni_id)
            print(get_jwt(student.full_name, student.uni_id, student.student_code))

    for uni_id in sorted(wanted):
        print(f"No student with UNI-ID '{uni_id}' in {STUDENTS_FILE}")
    return 1 if wanted else 0


if __name__ == "__main__":
    raise SystemExit(main())
