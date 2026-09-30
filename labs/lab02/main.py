import argparse
from datetime import datetime, timedelta, timezone

from labs.lab02.task1 import Admin, UserAccount


def run_demo():
    print("=== 1. Account Creation and Successful Login ===")
    account = UserAccount("Arch", "max@student.ua", "student", "StrongPass123!")
    print(f"Account created: {account['username']}, email: {account['email']}")

    success = account.login("Arch", "StrongPass123!", "192.168.1.100")
    print(f"Login attempt with correct password: {'Success' if success else 'Failed'}")
    print(f"Is user authenticated? {account.is_authenticated()}")

    print("\n=== 2. Failed Login ===")
    fail_success = account.login("Arch", "WrongPassword", "192.168.1.101")
    print(
        f"Login attempt with wrong password: {'Success' if fail_success else 'Denied'}"
    )

    print("\n=== 3. Email Change with Validation ===")
    try:
        account["email"] = "new_valid_email@lpnu.ua"
        print(f"Email successfully changed to: {account['email']}")

        print("Attempting to set an invalid email ('invalid-mail')...")
        account["email"] = "invalid-mail"
    except ValueError as e:
        print(f"Validation caught the error! Error: {e}")

    print("\n=== 4. Administrator Permissions ===")
    admin_account = UserAccount("admin", "admin@lpnu.ua", "admin", "AdminPass!")
    admin_account.user = Admin(
        "admin", "admin@lpnu.ua", "admin", "AdminPass!", {"read_logs"}
    )

    print(f"Initial permissions: {admin_account['permissions']}")
    admin_account["permissions"] = {"read_logs", "delete_users", "ban_ip"}
    print(f"Updated permissions via __setitem__: {admin_account['permissions']}")

    print("\n=== 5. Session Timeout ===")
    print("Changing last_activity to 20 minutes ago...")
    account["last_activity"] = datetime.now(timezone.utc) - timedelta(
        minutes=20
    )  # manually change last_activity time for demo
    print(f"Is session active now? {account.is_authenticated()}")

    print("\n=== 6. Logout ===")
    account.login("Arch", "StrongPass123!", "192.168.1.100")
    print(f"Before logout (is_authenticated): {account.is_authenticated()}")
    account.logout()
    print(f"After logout (is_authenticated): {account.is_authenticated()}")

    print("\n=== 7. AuditLog Entries ===")
    logs = account.audit_log.show_all()
    for log in logs:
        print(log)


def main():
    parser = argparse.ArgumentParser(description="Lab 02: Console Utilities")
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )

    # demo command for task1.py
    subparsers.add_parser("demo", help="OOP classes demonstration (Task 1)")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()


if __name__ == "__main__":
    main()
