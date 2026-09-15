from rich.console import Console
from rich.table import Table

users = {
    "security_chief": {
        "role": "security_officer",
        "clearance": 4,
        "department": "Security",
        "active": True,
    },
    "network_admin": {
        "role": "network_admin",
        "clearance": 3,
        "department": "Network",
        "active": True,
    },
    "help_desk": {
        "role": "support",
        "clearance": 1,
        "department": "Support",
        "active": True,
    },
    "auditor_ext": {
        "role": "auditor",
        "clearance": 3,
        "department": "Audit",
        "active": True,
    },
    "temp_worker": {
        "role": "temporary",
        "clearance": 1,
        "department": "Temp",
        "active": False,
    },
}
resources = [
    ("incident_reports", 4),
    ("network_topology", 3),
    ("user_manual", 1),
    ("vulnerability_scans", 3),
    ("root_access", 4),
    ("help_tickets", 1),
    ("penetration_tests", 4),
    ("firewall_rules", 3),
    ("software_licenses", 2),
    ("faq_docs", 1),
]
security_levels: tuple = ("Unrestricted", "Limited", "Sensitive", "Classified")
blocked_users = {"temp_worker", "fired_employee", "compromised_acc"}

sec_level_colors = {
            "Classified": "red",
            "Sensitive": "orange1",
            "Limited": "yellow",
            "Unrestricted": "green",
        }

def get_table_of_resources(rc: list[tuple[str, int]], lvls: tuple[str]) -> Table:
    table = Table(title="Resources", title_style="bold magenta")
    table.add_column("Resource", style="cyan")
    table.add_column("Security Level", style="yellow")
    
    for resource in rc:
        security_level = lvls[resource[1] - 1]
        color = sec_level_colors.get(security_level)
        styled_level = f"[{color}]{security_level}[/{color}]" if color else security_level
        table.add_row(resource[0], styled_level)
    
    return table

def can_user_access_resource(user: str, resource: tuple[str, int]) -> tuple[bool, str]:
    if user not in users:
        return (False, "User not found")
    
    user_data = users.get(user, {})
    
    if user in blocked_users:
        return (False, "User is blocked")
    
    if not user_data.get("active"):
        return (False, "Account inactive")
    
    if user_data.get("clearance", 0) < resource[1]:
        return (False, "Insufficient clearance")
    
    return (True, "")

def main():
    console = Console()
    resource_table = get_table_of_resources(resources, security_levels)
    console.print(resource_table, justify="center")
    
    users_to_check = list(users.keys()) + list(blocked_users)
    
    user_access_table = Table(title="User access table", title_style="bold green")
    user_access_table.add_column("Username")
    user_access_table.add_column("Resource")
    user_access_table.add_column("Access")
    
    for username in users_to_check:        
        for resource in resources:
            access = can_user_access_resource(username, resource)
            third_column_text = "[green]ALLOW[/green]" if access[0] else f"[red]DENY[/red] ({access[1]})"
            user_access_table.add_row(username, resource[0], third_column_text)
    console.print(user_access_table, justify="center")

if __name__ == "__main__":
    main()
