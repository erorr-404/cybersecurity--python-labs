# початкове заповнення бази з JSON
import json
import logging
from pathlib import Path

from pydantic import ValidationError

from labs.lab03 import repository
from labs.lab03.schemas import CategoryRead, RecordCreate

BASE_DIR = Path(__file__).resolve().parent
seed_path = BASE_DIR / "data" / "seed.json"

logger = logging.getLogger(__name__)


def main() -> None:
    logger.info("Filling DB with initial data.")
    logger.info("Reading %s", seed_path)

    try:
        with seed_path.open("r", encoding="utf-8") as seed_file:
            data = json.load(seed_file)

        if not isinstance(data, dict):
            raise TypeError("The JSON root must be an object.")

        raw_categories = data.get("categories")
        raw_records = data.get("records")
        if not isinstance(raw_categories, list) or not isinstance(raw_records, list):
            raise TypeError("The JSON object must contain category and record lists.")

        categories = [CategoryRead.model_validate(item) for item in raw_categories]
        records = [RecordCreate.model_validate(item) for item in raw_records]
        logger.info("Successfully read and validated %s.", seed_path)

    except (
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
        ValidationError,
    ) as error:
        logger.error("Could not load valid initial data from %s: %s", seed_path, error)
        return

    try:
        if repository.seed_database(categories=categories, records=records):
            logger.info("Initial data stored to database.")
        else:
            logger.info("Database is already filled; no changes were made.")
    except repository.SeedDataError as error:
        logger.error("%s", error)


if __name__ == "__main__":
    main()
