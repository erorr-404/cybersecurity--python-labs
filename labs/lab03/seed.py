# початкове заповнення бази з JSON
import json
from pathlib import Path
import logging
from typing import Any
import labs.lab03.database as database
from sqlite3 import Connection, IntegrityError


log_path = Path("labs/lab03/data/logs/seed.log").absolute().resolve()
seed_path = Path("labs/lab03/data/seed.json").absolute().resolve()


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.FileHandler(log_path, mode="a"), logging.StreamHandler()],
)


def main():
    logging.info(f"Reading {seed_path}")

    try:
        with open(seed_path, "r") as f:
            data: dict[str, list[dict[str, Any]]] = json.load(f)

            categories: list[dict[str, int | str]] | None = data.get("categories")
            records: list[dict[str, Any]] | None = data.get("records")

            if categories is None:
                logging.error(f"JSON file ({seed_path}) does not have categories.")
                return

            if records is None:
                logging.error(f"JSON file ({seed_path}) does not have records.")
                return

            logging.info(f"Successfully read {seed_path} file.")

    except json.JSONDecodeError as e:
        logging.exception(e)
        return

    con: Connection = database.get_connection()

    try:
        cursor = con.execute("SELECT COUNT(*) FROM categories")
        if cursor.fetchone()[0] > 0:
            logging.info("Database is already filled.")
            return

        with con:
            logging.info("Writing categories.")

            categories_data = [(c["id"], c["name"]) for c in categories]
            con.executemany(
                "INSERT INTO categories (id, name) VALUES (?, ?)", categories_data
            )

            logging.info("Writing records.")

            records_data = [
                (
                    r["code"],
                    r["title"],
                    r["category_id"],
                    r["value"],
                    r["status"],
                )
                for r in records
            ]
            con.executemany(
                "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                records_data,
            )

    except IntegrityError as e:
        logging.exception(e)
        logging.info("Changes not accepted.")

    finally:
        con.close()

    logging.info("Data stored to database.")


if __name__ == "__main__":
    main()


# Для нової порожньої бази додайте три категорії та вісім записів в одній транзакції. Вставляйте
# категорії з id , визначеними в JSON; у звичайному API ідентифікатори створює база.

# Якщо початкові дані некоректні або будь-яке додавання порушує обмеження, скасуйте весь пакет
# змін і виведіть зрозуміле повідомлення.

# Повторне заповнення непорожньої бази має завершуватися повідомленням без зміни даних і без
# дублікатів. Не використовуйте INSERT OR IGNORE , щоб приховувати помилки в початковому
# наборі.
