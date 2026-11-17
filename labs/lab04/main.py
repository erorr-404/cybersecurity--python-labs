# Аргументи, виклик функції, повідомлення

import argparse
import re
import json
import sys
import labs.lab04.api_client as api_client
import labs.lab04.analysis as analysis
import shared.student as student
from rich import print_json
from requests import HTTPError
import labs.lab04.utils as utils
from labs.lab04.utils import error, debug

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
        help="Output additional info.",
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

    if not isinstance(student.VARIANT_NUMBER, int):
        error("student.VARIANT_NUMBER must be integer.")
        return 1

    if (student.VARIANT_NUMBER < 1) or (student.VARIANT_NUMBER > 15):
        error("student.VARIANT_NUMBER must be integer from 1 to 15.")
        return 1

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
        except HTTPError as e:
            error(e)
            return 3

    # * аналіз із файлу

    else:
        try:
            debug("Analyzing from file...")
            response = load_response(input_file)
        except OSError as e:
            error(e)
            return 4

    # * аналіз response

    if isinstance(response, dict):
        result: analysis.ExtractionResult | None = analysis.extract_payload(
            response, cve
        )

    else:
        error("Response must be a dict.")
        return 5

    # * створення звіту

    if response is not None:
        report = analysis.build_report(result, cve, student.VARIANT_NUMBER)
        print_json(data=report, highlight=False)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
