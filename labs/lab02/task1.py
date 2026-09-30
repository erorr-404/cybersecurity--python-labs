import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum


class User:
    """Represent an authenticated user with validated contact and password data. Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes."""
    EMAIL_PATTERN = r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@.+\..+$"
    ITERATIONS = 100_000
    
    username: str
    __email: str
    role: str
    active: bool
    
    __password_hash: bytes
    __password_salt: bytes
    
    def __init__(self, uname: str, mail: str, role: str, pwd: str) -> None:
        self.username = uname
        self.email = mail
        self.role = role
        self.set_password(pwd)
        self.active = True
    
    @property
    def email(self):
        return self.__email
    
    @email.setter
    def email(self, value: str):
        result = re.match(self.EMAIL_PATTERN, value)
        if result:
            self.__email = value
        else:
            raise ValueError("Invalid email")
    
    def set_password(self, pwd: str):
        if not pwd:
            raise ValueError("Password can not be empty or None.")
        
        self.__password_salt = os.urandom(128)
        self.__password_hash = self.generate_hash(pwd.encode("utf-8"), self.__password_salt)
    
    def check_password(self, pwd: str) -> bool:
        if not pwd:
            raise ValueError("Password can not be empty or None.")
        
        # cryptographic compare (prevents timing analysis)
        return hmac.compare_digest(self.__password_hash, self.generate_hash(pwd.encode("utf-8"), self.__password_salt))
    
    def generate_hash(self, pwd: bytes, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(hash_name="sha256", password=pwd, salt=salt, iterations=self.ITERATIONS)
    
    def deactivate(self):
        self.active = False
    
    def __str__(self) -> str:
        return f"User username={self.username} email={self.email} role={self.role} active={self.active}"


class Admin(User):
    """A user with permission-management capabilities."""
    permissions: set[str]
    
    def __init__(self, uname: str, mail: str, role: str, pwd: str, permissions: set[str]) -> None:
        super().__init__(uname, mail, role, pwd)
        self.permissions = set(permissions)
    
    def grant_permission(self, permission: str):
        self.permissions.add(permission)
    
    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions
    
    def revoke_permission(self, permission: str):
        self.permissions.remove(permission)
    
    def __str__(self) -> str:
        return f"Admin username={self.username} email={self.email} role={self.role} active={self.active} permissions={self.permissions}"


class Session:
    """Represent a user's session and track its activity timestamps."""
    
    ip: str
    login_time: datetime
    last_activity: datetime
    
    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = datetime.now(timezone.utc)
        self.last_activity = datetime.now(timezone.utc)
    
    def touch(self):
        self.last_activity = datetime.now(timezone.utc)
    
    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec can not be empty.")
        return datetime.now(timezone.utc) - self.last_activity <= timedelta(seconds=timeout_sec)


class AuditLogAction(Enum):
    USER_CREATED = "user_created"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"


@dataclass
class AuditLogEntry:
    """Represents a single entry in logs. Time must be UTC timezone."""
    time: datetime
    username: str
    action: AuditLogAction
    
    def __str__(self) -> str:
        return f"{self.time.isoformat()}: username={self.username} action={self.action}"


class AuditLog:
    """Store and display audit entries for account activity."""
    
    logs: list
    
    def __init__(self) -> None:
        self.logs = []
    
    def add_log(self, username: str, action: AuditLogAction):
        self.logs.append(AuditLogEntry(datetime.now(timezone.utc), username, action))

    def show_all(self) -> list[str]:
        result: list[str] = []
        for log_entry in self.logs:
            result.append(str(log_entry))
        return result


class UserAccount:
    """Represent a user account with session management and audit logging."""
    
    SESSION_TIMEOUT_SEC = 900
    
    user: User
    session: Session | None
    audit_log: AuditLog
    
    def __init__(self, username: str, email: str, role: str, password: str) -> None:
        self.audit_log = AuditLog()
        self.user = User(username, email, role, password)        
        self.audit_log.add_log(username, AuditLogAction.USER_CREATED)
    
    def login(self, username: str, password: str, ip: str):
        authenticated = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )

        if not authenticated:
            self.audit_log.add_log(username, AuditLogAction.LOGIN_FAILURE)
            return False

        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, AuditLogAction.LOGIN_SUCCESS)
        return True
    
    def is_authenticated(self) -> bool:
        return self.session is not None and self.session.is_active(self.SESSION_TIMEOUT_SEC)
    
    def logout(self):
        if self.session is None:
            return
        
        self.audit_log.add_log(self.user.username, AuditLogAction.LOGOUT)
        self.session = None
    
    def __setitem__(self, key, value):
        if value is None:
            raise ValueError("Value can not be None.")
        
        match key:
            case "username":
                self.user.username = value
            
            case "email":
                self.user.email = value
            
            case "role":
                self.user.role = value
            
            case "active":
                if not isinstance(value, bool):
                    raise TypeError("User.active must be bool.")
                self.user.active = value
            
            case "permissions":
                if not isinstance(self.user, Admin):
                    raise KeyError("User is not an Admin.")
                
                # all permissions must by str type
                if not all(isinstance(permission, str) for permission in value):
                    raise TypeError("Permissions must be set[str].")
                self.user.permissions = set(value)
            
            case "ip":
                if self.session is None:
                    raise KeyError("Can not change IP, because Session is None.")
                self.session.ip = value
            
            case "login_time":
                if self.session is None:
                    raise KeyError("Can not change login_time, because Session is None.")
                self.session.login_time = value
            
            case "last_activity":
                if self.session is None:
                    raise KeyError("Can not change last_activity, because Session is None.")
                self.session.last_activity = value
            
            case _:
                raise KeyError("Invalid key.")
                
    def __getitem__(self, key):
        match key:
            case "username":
                return self.user.username
            
            case "email":
                return self.user.email
            
            case "role":
                return self.user.role
            
            case "active":
                return self.user.active
            
            case "permissions":
                if not isinstance(self.user, Admin):
                    raise KeyError("User is not an Admin.")
                return self.user.permissions
            
            case "ip":
                if self.session is None:
                    return None
                return self.session.ip
            
            case "login_time":
                if self.session is None:
                    return None
                return self.session.login_time
            
            case "last_activity":
                if self.session is None:
                    return None
                return self.session.last_activity
            
            case "logs":
                return self.audit_log.show_all()
            
            case _:
                raise KeyError("Invalid key.")