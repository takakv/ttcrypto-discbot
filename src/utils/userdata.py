import logging
from pathlib import Path
from typing import NamedTuple

USER_DATA_DIR = Path("userdata")


class UserData(NamedTuple):
    name: str
    uni_id: str
    student_code: str

    def serialise(self) -> str:
        return "".join(f"{field}\n" for field in self)


def path_for(user_id: int) -> Path:
    return USER_DATA_DIR / f"{user_id}.txt"


def is_registered(user_id: int) -> bool:
    return path_for(user_id).is_file()


def load(user_id: int) -> UserData | None:
    path = path_for(user_id)
    if not path.is_file():
        return None

    lines = path.read_text().splitlines()
    if len(lines) != len(UserData._fields):
        logging.error(f"'{path}' holds {len(lines)} lines, expected {len(UserData._fields)}")
        return None

    return UserData(*(line.strip() for line in lines))


def store(user_id: int, data: UserData) -> None:
    USER_DATA_DIR.mkdir(exist_ok=True)
    path_for(user_id).write_text(data.serialise())
