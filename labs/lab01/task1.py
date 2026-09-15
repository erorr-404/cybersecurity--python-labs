import random
import string

from rich.console import Console
from rich.table import Table

DIGITS = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "0"}
UPPER = set(string.ascii_uppercase)
LOWER = set(string.ascii_lowercase)
SPECIAL = set(string.punctuation)

passwords = [
    "UserPass1!",
    "temp",
    "Cyber$ecur1ty",
    "guest",
    "P0w3rful@Pass",
    "login",
    "Defens3#2023",
    "abc123",
    "Elit3@Secur",
    "demo",
]
criteria = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}
forbidden_passwords = {"temp", "guest", "login", "demo", "abc123", "user"}


def has(s: str, symbols: set) -> bool:
    for d in symbols:
        if d in s:
            return True
    return False


def has_digits(passwd: str) -> bool:
    return has(passwd, DIGITS)


def has_upper(passwd: str) -> bool:
    return has(passwd, UPPER)


def has_lower(passwd: str) -> bool:
    return has(passwd, LOWER)


def has_special(passwd: str) -> bool:
    return has(passwd, SPECIAL)


def has_two_out_of_three(ls: tuple) -> bool:
    return (ls[0] and ls[1]) or (ls[0] and ls[2]) or (ls[1] and ls[2])


def is_unique(passwd: str, passwds: list) -> bool:
    return passwds.count(passwd) == 1


def validate_password(passwd: str, passwds) -> str:
    passwd_length = len(passwd)
    passwd_has_digits = not criteria.get("require_digits") or has_digits(passwd)
    passwd_has_upper = not criteria.get("require_upper") or has_upper(passwd)
    passwd_has_lower = not criteria.get("require_lower") or has_lower(passwd)
    passwd_has_special = not criteria.get("require_special") or has_special(passwd)

    if passwd in forbidden_passwords or passwd_length < criteria["min_length"]:
        return "Forbidden"

    if all((passwd_has_digits, passwd_has_upper, passwd_has_special)):
        if passwd_length >= criteria["min_length"] + 4 and is_unique(passwd, passwds):
            return "Very strong"
        return "Strong"

    if has_two_out_of_three((passwd_has_digits, passwd_has_upper, passwd_has_special)):
        return "Medium"

    if any((passwd_has_digits, passwd_has_upper, passwd_has_special, passwd_has_lower)):
        return "Weak"

    return "Error: validation failed."


def main():
    console = Console()
    initial_passwords_len = len(passwords)

    for i in range(3):
        random_index = random.randint(0, initial_passwords_len - 1)
        passwords.append(passwords[random_index])

    table = Table(title="Passwords security", title_style="bold magenta")
    table.add_column("№", no_wrap=True)
    table.add_column("Password")
    table.add_column("Result")

    for i, password in enumerate(passwords):
        result = validate_password(password, passwords)
        result_colors = {
            "Forbidden": "red",
            "Weak": "orange1",
            "Medium": "yellow",
            "Strong": "green",
            "Very strong": "bold blue",
        }
        color = result_colors.get(result)
        styled_result = f"[{color}]{result}[/{color}]" if color else result
        table.add_row(f"{i:02}", password, styled_result)

    console.print(table, justify="center")


if __name__ == "__main__":
    main()
