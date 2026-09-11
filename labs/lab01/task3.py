import hashlib
import csv

from shared import student
from rich.console import Console
from rich.table import Table
from pathlib import Path
from functools import wraps
import json
from datetime import datetime


SALT = f"{student.VARIANT_NUMBER:05}"
MINIMUM_PASSWORD_LENGTH = 8
HASH_ALGORITHM = "sha1"
USER_CSV_DB_PATH = "labs/lab01/data/users.csv"
JSON_LOG_PATH = "labs/lab01/data/log.json"
ERROR_STYLE = "bold red"

users_db: dict[str, str] = dict()
console = Console()

class ValidationError(Exception):
    pass

def log_event(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        username = kwargs.get("username") or (args[0] if args else "Unknown")
        
        if result:
            text = f"Successful login for {username}"
            style = "green"
        else:
            text = f"Failed login for {username}"
            style = ERROR_STYLE
        
        console.print(text, style=style)
        
        json_log = {
            "event": "login",
            "user": username,
            "result": "success" if result else "failure",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), #"YYYY-MM-DD HH:MM:SS"
            "args": [],
            "kwargs": {}
        }
        
        try:
            log_path = Path(JSON_LOG_PATH)
            log_path.parent.mkdir(parents=True, exist_ok=True) # create file if it does not exists
            
            if not log_path.exists():
                log_path.write_text("[]", encoding="utf-8")
            
            with open(log_path, "r+", encoding="utf-8") as file:
                data_list: list[dict] = json.load(file)
                data_list.append(json_log)
                file.seek(0)
                json.dump(data_list, file, indent=4)
                file.truncate()
        
        except json.JSONDecodeError:
            console.print(f"JSONDecodeError: can not read JSON file to")
        
        except FileNotFoundError:
            console.print(f"FileNotFoundError: can not find file {JSON_LOG_PATH}.", style=ERROR_STYLE)
        
        except PermissionError:
            console.print(f"PermissionError: can not open file {JSON_LOG_PATH} due to insufficient permissions.", style=ERROR_STYLE)
        
        except IOError:
            console.print(f"IOError during work with file {JSON_LOG_PATH}.")  

        
        return result
    return wrapper

def generate_hash(password: str, salt: str = "00000") -> str:
    
    if not password:
        raise ValueError("Password can not be empty.")
    
    if not salt:
        raise ValueError("Salt can not be empty.")
    
    if len(password) < MINIMUM_PASSWORD_LENGTH:
        raise ValidationError(f"Password can not be shorter than {MINIMUM_PASSWORD_LENGTH} (password={password}).")
    
    h = hashlib.pbkdf2_hmac(HASH_ALGORITHM, password.encode(), salt.encode(), 100000)
    return h.decode(errors="ignore")

def create_user(username: str, password: str) -> tuple[str, str]:
    h = generate_hash(password, SALT)
    return (username, h)

def create_users(users_list):
    users = []
    for user in users_list:
        users.append(create_user(*user))
    
    file_path = Path(USER_CSV_DB_PATH)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, mode='w', encoding='utf-8', newline="") as file:
        writer = csv.writer(file)
        writer.writerows(users)

def user_exists(username: str) -> bool:
    return bool(users_db.get(username, False))

@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Password and username can not be empty.")
    
    if not user_exists(username):
        return False
    
    hashed_password = generate_hash(password, SALT)
    if users_db[username] == hashed_password:
        return True
    
    return False

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
        ("test", "Pass@123")
    )
    
    if not Path(USER_CSV_DB_PATH).exists:
        try:
            create_users(users_to_register)
            console.print("Users created!", style="green")
        except ValidationError:
            console.print(f"ValidationError occured during user registering.", style=ERROR_STYLE)
    else:
        console.print("Users already created.", style="magenta")
    
    try:
        with open(USER_CSV_DB_PATH, mode='r', encoding='utf-8', newline='') as file:
            reader = csv.reader(file)
            table = Table(title="Users", title_style="bold green")
            table.add_column("Username")
            table.add_column("Password-hash")
            
            for row in reader:
                users_db[row[0]] = row[1]
                table.add_row(*row)
            
            console.print(table)
    
    except FileNotFoundError:
        console.print(f"FileNotFoundError: can not find file {USER_CSV_DB_PATH}.", style=ERROR_STYLE)
    
    except PermissionError:
        console.print(f"PermissionError: can not open file {USER_CSV_DB_PATH} due to insufficient permissions.", style=ERROR_STYLE)
    
    except IOError:
        console.print(f"IOError during work with file {USER_CSV_DB_PATH}.")  
    
if __name__ == "__main__":
    main()
    
    console.print("Interactive shell will start now. Type exit() to finnish.")
    console.rule("Shel", style="bold")
    while True:
        exec(input("> "))
    