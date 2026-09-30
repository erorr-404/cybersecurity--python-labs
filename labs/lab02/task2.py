import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from ipaddress import AddressValueError, IPv4Address, IPv4Network, NetmaskValueError
from pathlib import Path
from typing import Any, Literal

from rich import box
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table


class ParsingError(Exception):
    pass


class Action(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    BLOCK = "BLOCK"


@dataclass
class Rule:
    id: int
    source: IPv4Network | IPv4Address
    destination: IPv4Address
    port: int | Literal["ANY"]
    action: Action


@dataclass
class InvalidRecord:
    id: int
    reason: str


@dataclass
class RuleConflict:
    rule1: Rule
    rule2: Rule
    reason: str


@dataclass
class VulnerableRuleBlueprint:
    # None means no verification
    source: IPv4Network | IPv4Address | None = None
    destination: IPv4Address | None = None
    port: int | Literal["ANY"] | None = None
    action: Action | None = None
    reason: str = "Admin said."


def setup_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validates and analyzes firewall configuration."
    )

    parser.add_argument(
        "--rules-file",
        type=Path,
        required=True,
        help="Path to file with firewall rules.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to output file with fixed rules.",
    )

    parser.add_argument(
        "--check-conflicts", action="store_true", help="Enable conflict verification."
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "LOG", "WARNING", "ERROR", "CRITICAL"],
        default="INFO",
        help="Debug logs level (default is INFO).",
    )

    return parser


def setup_logging(log_level_str: str):
    numeric_level = getattr(logging, log_level_str.upper(), logging.INFO)

    logging.basicConfig(
        level=numeric_level,
        format="%(message)s",  # RichHandler handles time and level by itself
        datefmt="[%Y-%m-%d %H:%M:%S]",
        handlers=[RichHandler(rich_tracebacks=True, markup=True)],
    )


def parse_rules(path: Path) -> tuple[list[Rule], list[InvalidRecord]]:
    if not path.exists():
        raise ValueError("Invalid path.")

    with open(path, "r") as file:
        try:
            data: list[dict[str, Any]] = json.load(file)

            # type validation
            if not isinstance(data, list):
                raise TypeError("Expected to find a list.")
            if not all(isinstance(entry, dict) for entry in data):
                raise TypeError("List must contain dictionaries.")

            result: list[Rule] = []
            invalid_records: list[InvalidRecord] = []

            for entry in data:
                # id validation and parsing
                if (raw_id := entry.get("id")) is None:
                    raise ValueError("Rule id is required.")
                id: int = int(raw_id)

                # source validation and parsing
                raw_source = entry.get("source", None)
                try:
                    if raw_source is None:
                        invalid_records.append(InvalidRecord(id, "Source is None"))
                        continue
                    if "/" in raw_source:
                        source = IPv4Network(raw_source)
                    else:
                        source = IPv4Address(raw_source)

                except AddressValueError:
                    invalid_records.append(
                        InvalidRecord(id, f"Invalid source address: {raw_source!s}")
                    )
                    continue

                except NetmaskValueError:
                    invalid_records.append(
                        InvalidRecord(id, f"Invalid source mask: {raw_source!s}")
                    )
                    continue

                # destination validation and parsing
                raw_dest = entry.get("destination", None)
                try:
                    if raw_dest is None:
                        invalid_records.append(
                            InvalidRecord(id, "Destination is None.")
                        )
                        continue
                    destination = IPv4Address(raw_dest)

                except AddressValueError:
                    invalid_records.append(
                        InvalidRecord(id, f"Invalid destination: {raw_dest!s}")
                    )
                    continue

                # port validation and parsing
                if (raw_port := entry.get("port", None)) is None:
                    invalid_records.append(InvalidRecord(id, "Port is None."))
                    continue
                if raw_port == "ANY":
                    port = "ANY"
                elif 0 <= (int_port := int(raw_port)) <= 65535:
                    port = int_port
                else:
                    invalid_records.append(
                        InvalidRecord(
                            id,
                            f"Port can by 'ANY' or int from 0 to 65535. Got: {raw_port}",
                        )
                    )
                    continue

                # action validation and parsing
                if (raw_action := entry.get("action", None)) is None:
                    invalid_records.append(InvalidRecord(id, "Action is None."))
                    continue
                if not isinstance(raw_action, str):
                    invalid_records.append(
                        InvalidRecord(
                            id, f"Action must be a string. Actions: {raw_action}"
                        )
                    )
                    continue
                try:
                    action = Action(raw_action)
                except ValueError:
                    invalid_records.append(
                        InvalidRecord(
                            id,
                            f"Action must be one of: {', '.join(item.value for item in Action)}. Got: {raw_action}",
                        )
                    )
                    continue

                rule = Rule(id, source, destination, port, action)

                result.append(rule)

            return result, invalid_records

        except json.JSONDecodeError as e:
            raise ParsingError(f"Reason: {e}")


def analyze_logic(rules: list[Rule]) -> tuple[list[list[Rule]], list[RuleConflict]]:
    grouped_rules = defaultdict(list)

    # grouping rule by source, destination and port
    for rule in rules:
        key = (rule.source, rule.destination, rule.port)
        grouped_rules[key].append(rule)

    duplicates: list[list[Rule]] = []
    conflicts: list[RuleConflict] = []

    for key, matching_rules in grouped_rules.items():
        if len(matching_rules) <= 1:
            continue

        # set does not allow duplicates
        actions = {rule.action for rule in matching_rules}

        # if set contains only one item, it means the second item was the same
        if len(actions) == 1:
            duplicates.append(matching_rules)

        # it means we have 2 rules with the same source, destination and port, but different actions
        else:
            conflict = RuleConflict(
                matching_rules[0],
                matching_rules[1],
                f"Conflicting actions for same targets: {matching_rules[0].action.value} and {matching_rules[1].action.value}",
            )
            conflicts.append(conflict)

    return duplicates, conflicts


def analyze_security(rules: list[Rule]):
    # if something looks like rule from this list, it is unsecure
    VULNERABLE_RULES = [
        VulnerableRuleBlueprint(
            source=IPv4Network("0.0.0.0/0"),
            port="ANY",
            action=Action.ALLOW,
            reason="Unlimited exposure (Action: ALLOW for ANY port from 0.0.0.0/0)",
        ),
        VulnerableRuleBlueprint(
            source=IPv4Network("0.0.0.0/0"),
            port=22,
            action=Action.ALLOW,
            reason="SSH is publicly accessible from 0.0.0.0/0",
        ),
    ]

    high_risk_rules: list[tuple[Rule, str]] = []

    for rule in rules:
        for blueprint in VULNERABLE_RULES:
            # verifying every field
            match_source = (blueprint.source is None) or (
                rule.source == blueprint.source
            )
            match_dest = (blueprint.destination is None) or (
                rule.destination == blueprint.destination
            )
            match_port = (blueprint.port is None) or (rule.port == blueprint.port)
            match_action = (blueprint.action is None) or (
                rule.action == blueprint.action
            )

            if match_source and match_dest and match_port and match_action:
                high_risk_rules.append((rule, blueprint.reason))
                continue

    return high_risk_rules


def export_clean_rules(
    rules: list[Rule],
    conflicts: list[RuleConflict],
    duplicates: list[list[Rule]],
    output_path: Path,
):
    exclude_ids = set()

    # exclude conflict rules
    for conflict in conflicts:
        exclude_ids.add(conflict.rule1.id)
        exclude_ids.add(conflict.rule2.id)

    # choose only one rule from duplicate pairs
    for dup_group in duplicates:
        for duplicate_rule in dup_group[1:]:
            exclude_ids.add(duplicate_rule.id)

    # filter rules
    clean_rules = [rule for rule in rules if rule.id not in exclude_ids]

    # convert dataclasses back to dictionaries
    json_data = []
    for rule in clean_rules:
        json_data.append(
            {
                "id": rule.id,
                "source": str(rule.source),
                "destination": str(rule.destination),
                "port": rule.port,
                "action": rule.action.value,  # getting value (allow or deny) from Enum
            }
        )

    # creating directory and file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=4)

    return len(clean_rules)


def main():
    parser = setup_argparse()
    args = parser.parse_args()

    # setup logging
    setup_logging(args.log_level)
    log = logging.getLogger("firewall_audit")

    console = Console()

    log.info(f"Starting parsing from file: [bold cyan]{args.rules_file}[/bold cyan]")

    try:
        rules, invalid_rules = parse_rules(args.rules_file)
        log.info(f"Successfully read [green]{len(rules)}[/green] rules.")
    except ParsingError as e:
        log.critical(f"Critical exception during parsing: {e}", exc_info=True)
        sys.exit(1)

    if invalid_rules:
        log.warning(
            f"Found [yellow]{len(invalid_rules)}[/yellow] rules with invalid IP/Mask."
        )

    duplicates, conflicts = [], []
    if args.check_conflicts:
        log.debug("Conflict check is enabled. Analyzing logic...")
        duplicates, conflicts = analyze_logic(rules)
        if conflicts:
            log.error(f"Found [red]{len(conflicts)}[/red] conflicts!")

    log.debug("Initializing check for vulnerable rules.")
    high_risk_rules = analyze_security(rules)
    if high_risk_rules:
        log.critical(f"Found [red]{len(high_risk_rules)}[/red] vulnerable rules.")

    # export clean rules
    log.info(f"Exporting clean rules {args.output}...")
    clean_count = export_clean_rules(rules, conflicts, duplicates, args.output)
    log.info(f"Export finished: {clean_count} rules saved.")

    console.rule("[bold blue]Firewall Configuration Audit Report")

    console.print(f"Invalid IP Formats  : {len(invalid_rules)}")
    console.print(f"Conflict Rules      : {len(conflicts)}")
    console.print(f"Duplicate Rules     : {len(duplicates)}")
    console.print(f"High-Risk Rules     : {len(high_risk_rules)}\n")

    if len(invalid_rules) > 0:
        console.rule("[bold red]Invalid Rules")
        invalid_rules_table = Table(
            "Rule ID", "Reason", highlight=True, box=box.SIMPLE, expand=True
        )
        for invalid_rule in invalid_rules:
            invalid_rules_table.add_row(
                f"[bold]{invalid_rule.id}[/bold]", invalid_rule.reason
            )
        console.print(invalid_rules_table)
        console.print()

    if len(conflicts) > 0:
        console.rule("[bold yellow]Conflicts")
        conflicts_table = Table(
            "First Rule",
            "Second Rule",
            "Reason",
            highlight=True,
            box=box.SIMPLE,
            expand=True,
        )
        for c in conflicts:
            r1_str = f"[bold]#{c.rule1.id}[/bold] {c.rule1.action.value} {c.rule1.source} -> {c.rule1.destination}:{c.rule1.port}"
            r2_str = f"[bold]#{c.rule2.id}[/bold] {c.rule2.action.value} {c.rule2.source} -> {c.rule2.destination}:{c.rule2.port}"
            conflicts_table.add_row(r1_str, r2_str, c.reason)
        console.print(conflicts_table)
        console.print()

    if len(duplicates) > 0:
        console.rule("[bold yellow]Duplicates")
        duplicates_table = Table(
            "Rule IDs",
            "Configuration",
            "Action",
            highlight=True,
            box=box.SIMPLE,
            expand=True,
        )
        for dup_group in duplicates:
            first_rule = dup_group[0]
            ids = ", ".join(f"#{r.id}" for r in dup_group)
            config = (
                f"{first_rule.source} -> {first_rule.destination}:{first_rule.port}"
            )
            duplicates_table.add_row(ids, config, first_rule.action.value)
        console.print(duplicates_table)
        console.print()

    if len(high_risk_rules) > 0:
        console.rule("[bold red]High-Risk Rules")
        high_risk_rules_table = Table(
            "Rule ID",
            "Configuration",
            "Risk Reason",
            highlight=True,
            box=box.SIMPLE,
            expand=True,
        )
        for rule, reason in high_risk_rules:
            config = (
                f"{rule.action.value} {rule.source} -> {rule.destination}:{rule.port}"
            )
            high_risk_rules_table.add_row(f"[bold]#{rule.id}[/bold]", config, reason)
        console.print(high_risk_rules_table)


if __name__ == "__main__":
    main()
