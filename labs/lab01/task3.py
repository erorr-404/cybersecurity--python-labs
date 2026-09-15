import csv
import hashlib
import json
from datetime import datetime
from functools import wraps
from pathlib import Path
from zoneinfo import ZoneInfo

from rich.console import Console
from rich.table import Table

from shared import student

SALT = f"{student.VARIANT_NUMBER:05}"
MINIMUM_PASSWORD_LENGTH = 8
USER_CSV_DB_PATH = "labs/lab01/data/users.csv"
JSON_LOG_PATH = "labs/lab01/data/log.json"
ERROR_STYLE = "bold red"

users_db: dict[str, str] = {}
console = Console()


class ValidationError(Exception):
    """Raised when user data fails validation."""


def log_event(func):
    """Decorate a login function with console and JSON event logging."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        username = kwargs.get("username") or (args[0] if args else "Unknown")

        # display login status in the console
        if result:
            text = f"Successful login for {username}"
            style = "green"
        else:
            text = f"Failed login for {username}"
            style = ERROR_STYLE
        console.print(text, style=style)

        # dict that will be written into JSON logfile
        json_log = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now(tz=ZoneInfo("Europe/Kyiv")).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),  # "YYYY-MM-DD HH:MM:SS"
            "args": list(args),
            "kwargs": kwargs,
        }

        try:
            # create file and parent directories if they do not exist
            log_path = Path(JSON_LOG_PATH)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            if not log_path.exists():
                log_path.write_text("[]", encoding="utf-8")

            # write to the log-file
            with open(log_path, "r+", encoding="utf-8") as file:
                data_list: list[dict] = json.load(file)
                data_list.append(json_log)
                file.seek(0)
                json.dump(data_list, file, indent=4)
                file.truncate()

        except json.JSONDecodeError:
            console.print("JSONDecodeError: can not read JSON file.")

        except FileNotFoundError:
            console.print(
                f"FileNotFoundError: can not find file {JSON_LOG_PATH}.",
                style=ERROR_STYLE,
            )

        except PermissionError:
            console.print(
                f"PermissionError: can not open file {JSON_LOG_PATH} due to insufficient permissions.",
                style=ERROR_STYLE,
            )

        except OSError:
            console.print(f"IOError during work with file {JSON_LOG_PATH}.")

        return result

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    """Return a salted SHA-1 hash of a password."""

    if not password:
        raise ValueError("Password can not be empty.")

    if not salt:
        raise ValueError("Salt can not be empty.")

    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password can not be shorter than {MINIMUM_PASSWORD_LENGTH} (password={password})."
        )

    h = (password + salt).encode("utf-8")
    return hashlib.sha1(h).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Return a username and its salted password hash."""

    h = generate_hash(password, SALT)
    return (username, h)


def create_users(users_list):
    """Hash users and write them to the CSV database."""

    # create users
    users = []
    for user in users_list:
        users.append(create_user(*user))

    # ensure, that user db and its parent folders exist
    file_path = Path(USER_CSV_DB_PATH)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # write to file
    with open(file_path, mode="w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerows(users)


def user_exists(username: str) -> bool:
    """Return whether the username exists in the in-memory database."""

    return bool(users_db.get(username, False))


@log_event
def login(username: str, password: str) -> bool:
    """Authenticate a user against the in-memory database."""

    if not username or not password:
        raise ValueError("Password and username can not be empty.")

    if not user_exists(username):
        return False

    return users_db[username] == generate_hash(password, SALT)


def create_users_table() -> Table:
    """Return a Rich table showing all users stored in the in-memory database."""
    table = Table(title="Created users", title_style="bold green")
    table.add_column("Username")
    table.add_column("Password-hash")
    for username, password_hash in users_db.items():
        table.add_row(username, password_hash)
    return table


def main():

    users_to_register = (
        ("admin", "admin12345"),
        ("kali", "kali12345"),
        ("root", "root12345"),
        ("user1", "password"),
        ("ubuntu", "12345678"),
        ("politech", "bezpeka123"),
        ("linux", "lj,hbqltym"),
        ("12345", "adminadmin"),
        ("guest", "admin123"),
        ("test", "Pass@123"),
    )

    # create users and save them to file
    if not Path(USER_CSV_DB_PATH).exists():
        try:
            create_users(users_to_register)
            console.print("Users created!", style="green")
        except ValidationError:
            console.print(
                "ValidationError occurred during user registering.", style=ERROR_STYLE
            )
    else:
        console.print("Users already created.", style="yellow", justify="center")

    # read the file and print users to the stdout
    try:
        with open(USER_CSV_DB_PATH, mode="r", encoding="utf-8", newline="") as file:
            reader = csv.reader(file)
            table = Table(title="Users", title_style="bold green")
            table.add_column("Username")
            table.add_column("Password-hash")

            for row in reader:
                users_db[row[0]] = row[1]
                table.add_row(*row)

            console.print(table, justify="center")
            console.print(
                "To see interactive exec shell, launch module using this command: [bold]python -m labs.lab01.task3[/bold]",
                justify="center",
            )

    except FileNotFoundError:
        console.print(
            f"FileNotFoundError: can not find file {USER_CSV_DB_PATH}.",
            style=ERROR_STYLE,
        )

    except PermissionError:
        console.print(
            f"PermissionError: can not open file {USER_CSV_DB_PATH} due to insufficient permissions.",
            style=ERROR_STYLE,
        )

    except OSError:
        console.print(f"IOError during work with file {USER_CSV_DB_PATH}.")


if __name__ == "__main__":
    main()

    console.print(
        "Interactive shell will start now. Type exit to finnish. Type help to show available commands."
    )
    console.rule("Shell", style="bold")

    while True:
        try:
            command = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print("\nInteractive shell finished.")
            break

        if command in {"exit", "quit"}:
            console.print("Interactive shell finished.")
            break

        if command in {"help", "?"}:
            console.print("Available commands: login, users, help, exit, quit")
            continue

        # prints all registered users
        if command == "users":
            table = create_users_table()
            console.print(table, justify="center")
            continue

        if command == "login":
            username = input("Username: ").strip()
            password = input("Password: ")
            try:
                login(username=username, password=password)
            except (ValueError, ValidationError) as error:
                console.print(f"{type(error).__name__}: {error}", style=ERROR_STYLE)
            continue

        console.print(
            "Unknown command. Type 'help' to see available commands.",
            style=ERROR_STYLE,
        )
