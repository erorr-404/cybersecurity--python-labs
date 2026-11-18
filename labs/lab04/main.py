# Аргументи, виклик функції, повідомлення

import argparse
import re
import json
import sys
import labs.lab04.api_client as api_client
import labs.lab04.analysis as analysis
import shared.student as student
from rich import print_json
import requests
import labs.lab04.utils as utils
from labs.lab04.utils import error, debug
import pydantic
import pathlib

CVE_PATTERN = r"CVE-[0-9]{4}-[0-9]{4,}"


def setup_argparse():

    parser = argparse.ArgumentParser(
        prog="NVD Client", description="CLI client, that can get data from NVD API."
    )

    parser.add_argument(
        "-v",
        "--verbose",
        required=False,
        action="store_true",
        help="Output additional info. Also prints report in human-readable formatted style.",
    )

    parser.add_argument(
        "--cve", required=True, help="Name of CVE you are searching for."
    )

    parser.add_argument("--input", required=False)

    return parser


def validate_cve(text: str) -> bool:
    return bool(re.fullmatch(CVE_PATTERN, text))


def load_response(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):

    # * перевірка student.VARIANT_NUMBER

    if type(student.VARIANT_NUMBER) is not int:
        error("student.VARIANT_NUMBER must be integer.")
        return 2

    if (student.VARIANT_NUMBER < 1) or (student.VARIANT_NUMBER > 15):
        error("student.VARIANT_NUMBER must be integer from 1 to 15.")
        return 2

    # * налаштування парсера аргументів

    parser = setup_argparse()
    args = parser.parse_args(argv)

    cve: str = args.cve
    input_file = args.input
    utils.VERBOSE = bool(args.verbose)
    response = None

    # * валідація синтаксису CVE

    if not validate_cve(cve):
        error("Error: invalid CVE")
        return 2

    # * надсилання запиту до NVD API

    if not input_file:
        debug("Sending request to NVD API...")
        try:
            response = api_client.fetch_response(cve)

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else None
            error(f"HTTP error: {status}")
            return 1

        except requests.exceptions.ConnectionError as e:
            error("Could not connect to NVD API.")
            return 1

        except requests.exceptions.Timeout as e:
            error("NVD API request timed out.")
            return 1

        except requests.exceptions.JSONDecodeError as e:
            error("NVD returned invalid JSON.")
            return 1

        except ValueError as e:
            error("Unexpected response.")
            return 1

    # * аналіз із файлу

    else:
        file = pathlib.Path(input_file)
        if not file.exists():
            error("File does not exist.")
            return 1

        if not file.is_file():
            error("Path must lead to a file.")
            return 1

        try:
            debug("Analyzing from file...")
            response = load_response(input_file)

        except OSError as e:
            error(e)
            return 1

        except json.JSONDecodeError:
            error("Invalid JSON format.")
            return 1

    # * аналіз response і створення звіту

    try:
        result = analysis.extract_payload(response, cve)
        report = analysis.build_report(
            record=result, cve_id=cve, variant=student.VARIANT_NUMBER
        )

    except ValueError as e:
        error(f"Error during validation or report building: {e}")
        return 1

    if utils.VERBOSE:
        print_json(data=report)
    else:
        print(json.dumps(report, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
