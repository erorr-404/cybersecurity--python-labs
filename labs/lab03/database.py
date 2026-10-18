# виконання готового sql та з'єднання
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "data" / "lab3.sqlite3"
SCHEMA_PATH = BASE_DIR / "schema.sql"

logger = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    """Відкрити з’єднання з перевіркою зовнішніх ключів."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        return connection
    except sqlite3.Error as e:
        logger.error("Error while connecting to DB: %s", e)
        connection.close()
        raise


def initialize_database() -> None:
    """Створити таблиці за готовим SQL-скриптом."""

    if not DATABASE_PATH.exists():
        logger.info("DB file not found. Creating new db...")

    else:
        logger.info("DB file is already exists.")

    script = SCHEMA_PATH.read_text(encoding="utf-8")
    with closing(get_connection()) as connection:
        try:
            connection.executescript(script)
            logger.info("DB has been successfully initialized.")

        except sqlite3.Error as e:
            logger.error("Error during DB init: %s", e)
            connection.rollback()
            raise


if __name__ == "__main__":
    initialize_database()
