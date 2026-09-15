import random
import string

from rich.console import Console
from rich.table import Table

DIGITS = set(string.digits)  # = "0123456789"
UPPER = set(string.ascii_uppercase)  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWER = set(string.ascii_lowercase)  # "abcdefghijklmnopqrstuvwxyz"
SPECIAL = set(string.punctuation)  # "!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"


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


def has(s: str, symbols: set[str]) -> bool:
    """Returns True, if `s` contains on of symbol from `symbols`, else False. \n
    `symbols` - set, which contains string with one symbol in each
    """
    for d in symbols:
        if d in s:
            return True
    return False


def has_digits(passwd: str) -> bool:
    """Returns True, if `passwd` contains at least one character from `DIGITS` set."""
    return has(passwd, DIGITS)


def has_upper(passwd: str) -> bool:
    """Return whether ``passwd`` contains at least one uppercase letter."""
    return has(passwd, UPPER)


def has_lower(passwd: str) -> bool:
    """Return whether ``passwd`` contains at least one lowercase letter."""
    return has(passwd, LOWER)


def has_special(passwd: str) -> bool:
    """Return whether ``passwd`` contains at least one special character."""
    return has(passwd, SPECIAL)


def has_two_out_of_three(ls: tuple) -> bool:
    """Return whether at least two of the three values in ``ls`` are true."""
    return (ls[0] and ls[1]) or (ls[0] and ls[2]) or (ls[1] and ls[2])


def is_unique(passwd: str, passwords: list) -> bool:
    """Return whether ``passwd`` occurs exactly once in ``passwords``."""
    return passwords.count(passwd) == 1


def validate_password(passwd: str, passwords: list[str]) -> str:
    """Evaluate a password against the configured security criteria.

    Return a strength classification based on the password's length,
    character composition, forbidden-password status, and uniqueness.
    """

    # check if password is forbidden and its minimum length
    if passwd in forbidden_passwords or len(passwd) < criteria["min_length"]:
        return "Forbidden"

    # criteria check
    passwd_has_digits: bool = has_digits(passwd)
    passwd_has_upper: bool = has_upper(passwd)
    passwd_has_lower: bool = has_lower(passwd)
    passwd_has_special: bool = has_special(passwd)

    rule_check = []

    # list of required criteria
    if criteria.get("require_digits"):
        rule_check.append(passwd_has_digits)
    if criteria.get("require_upper"):
        rule_check.append(passwd_has_upper)
    if criteria.get("require_special"):
        rule_check.append(passwd_has_special)

    # calculate how many rules are met
    rules_met = sum(rule_check)
    total_rules = len(rule_check)

    # all rules met
    if rules_met == total_rules:
        # unique and long enough
        if len(passwd) >= criteria["min_length"] + 4 and is_unique(passwd, passwords):
            return "Very strong"
        return "Strong"

    if rules_met >= 2:
        return "Medium"

    if rules_met >= 1 or passwd_has_lower:
        return "Weak"

    return "Forbidden"


def main():
    console = Console()
    initial_passwords_len = len(passwords)

    # generates 3 random password duplicates
    for i in range(3):
        random_index = random.randint(0, initial_passwords_len - 1)
        passwords.append(passwords[random_index])

    # creates table for password security level test results
    table = Table(title="Passwords security", title_style="bold magenta")
    table.add_column("№", no_wrap=True)
    table.add_column("Password")
    table.add_column("Result")

    # fills the table, with color based on the validation result
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
