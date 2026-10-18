# параметризовані sql-запити
import logging
import sqlite3
from collections.abc import Callable
from functools import wraps
from typing import Any

import labs.lab03.database as db
from labs.lab03.schemas import *

logger = logging.getLogger(__name__)


class NameDuplicateError(Exception):
    pass


class InternalDBError(Exception):
    pass


class NoSuchCategoryError(Exception):
    pass


class CategoryIsNotEmpty(Exception):
    pass


class InvalidRecordID(Exception):
    pass


class CodeDuplicateError(Exception):
    pass


class SeedDataError(Exception):
    pass


# custom decorator for db tasks
def with_connection(func: Callable) -> Callable:
    """Automatically closes session management, commits and transactions."""

    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        con = db.get_connection()
        try:
            with con:
                return func(*args, con=con, **kwargs)
        finally:
            con.close()

    return wrapper


@with_connection
def create_category(
    con: sqlite3.Connection, category: CategoryCreate
) -> dict[str, str | int]:
    """Creates category and returns dictionary with keys: id, name."""
    try:
        cursor = con.execute(
            "INSERT INTO categories (name) VALUES (?)", (category.name,)
        )

        new_id: int | None = cursor.lastrowid

        if new_id is None:
            raise InternalDBError("Internal db error.")

        return {"id": new_id, "name": category.name}

    except sqlite3.IntegrityError as e:
        logger.exception("Failed to create category.")
        if "unique" in str(e).lower():
            raise NameDuplicateError("Name must be unique.")
        raise InternalDBError(e.with_traceback)


@with_connection
def get_categories(con: sqlite3.Connection) -> list[dict[str, int | str]]:
    """Returns list of all categories. Dictionary keys: id, name"""
    cursor = con.execute("SELECT * FROM categories ORDER BY id ASC")
    rows = cursor.fetchall()
    return [{"id": row[0], "name": row[1]} for row in rows]


@with_connection
def remove_category(con: sqlite3.Connection, id: int):
    """Removes empty categories. Raises exception if category is not empty."""
    cursor = con.execute("SELECT COUNT(*) FROM categories WHERE id = ?", (id,))

    if cursor.fetchone()[0] == 0:
        raise NoSuchCategoryError("There is no category with such id.")

    try:
        con.execute("DELETE FROM categories WHERE id = ?", (id,))
    except sqlite3.IntegrityError:
        logger.exception("Failed to remove category.")
        raise CategoryIsNotEmpty(
            "Can not remove category if there is records, that refers it."
        )


@with_connection
def add_record(con: sqlite3.Connection, r: RecordCreate) -> RecordRead:
    """Raises exception if category not found or code is not unique."""
    try:
        cursor = con.execute(
            """
            INSERT INTO records (code, title, category_id, value, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (r.code, r.title, r.category_id, r.value, r.status),
        )

        new_id = cursor.lastrowid

        cursor = con.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (new_id,),
        )

        row = cursor.fetchone()

        return RecordRead(
            id=row[0],
            code=row[1],
            title=row[2],
            category_id=row[3],
            value=row[4],
            status=row[5],
            category_name=row[6],
        )

    except sqlite3.IntegrityError as e:
        logger.exception("Failed to add record.")
        error_msg = str(e).lower()

        if "foreign key" in error_msg:
            raise NoSuchCategoryError("Category not found.")

        elif "unique" in error_msg:
            raise CodeDuplicateError("Code can not duplicate.")

        else:
            raise


@with_connection
def get_record_by_id(con: sqlite3.Connection, record_id: int) -> RecordRead:
    cursor = con.execute(
        """
        SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE r.id = ?        
        """,
        (record_id,),
    )

    row = cursor.fetchone()

    if row is None:
        raise InvalidRecordID("There is no record with such id.")

    return RecordRead(
        id=row[0],
        code=row[1],
        title=row[2],
        category_id=row[3],
        value=row[4],
        status=row[5],
        category_name=row[6],
    )


@with_connection
def get_records(con: sqlite3.Connection, filter: RecordsFilter) -> list[dict[str, Any]]:
    query = """
        SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
        FROM records r
        JOIN categories c ON r.category_id = c.id
        WHERE 1=1
    """

    values = []

    if filter.category_id is not None:
        query += " AND r.category_id = ?"
        values.append(filter.category_id)

    if filter.status is not None:
        query += " AND r.status = ?"
        values.append(filter.status)

    if filter.min_value is not None:
        query += " AND r.value >= ?"
        values.append(filter.min_value)

    if filter.q is not None:
        query += " AND instr(r.title, ?) > 0"
        values.append(filter.q)

    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    values.append(filter.limit)
    values.append(filter.offset)

    cursor = con.execute(query, values)
    rows = cursor.fetchall()

    result = []
    for row in rows:
        result.append(
            {
                "id": row[0],
                "code": row[1],
                "title": row[2],
                "category_id": row[3],
                "value": row[4],
                "status": row[5],
                "category_name": row[6],
            }
        )

    return result


@with_connection
def update_record(
    con: sqlite3.Connection, record_id: int, record: RecordCreate
) -> RecordRead:
    cursor = con.execute("SELECT 1 FROM records WHERE id = ?", (record_id,))

    if cursor.fetchone() is None:
        raise InvalidRecordID("Record with given id does not exist.")

    try:
        con.execute(
            """
            UPDATE records
            SET code = ?, title = ?, category_id = ?, value = ?, status = ?
            WHERE id = ?
            """,
            (
                record.code,
                record.title,
                record.category_id,
                record.value,
                record.status,
                record_id,
            ),
        )

        cursor = con.execute(
            """
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id = ?
            """,
            (record_id,),
        )

        row = cursor.fetchone()

        if row is None:
            raise InternalDBError("row is None")

        return RecordRead(
            id=row[0],
            code=row[1],
            title=row[2],
            category_id=row[3],
            value=row[4],
            status=row[5],
            category_name=row[6],
        )

    except sqlite3.IntegrityError as e:
        logger.exception("Failed to update record.")
        error_msg = str(e).lower()

        if "foreign key" in error_msg:
            raise NoSuchCategoryError("Category with this id does not exist.")

        elif "unique" in error_msg:
            raise CodeDuplicateError("Code must be unique.")

        else:
            raise


@with_connection
def remove_record(con: sqlite3.Connection, record_id: int):
    cursor = con.execute("SELECT 1 FROM records WHERE id = ?", (record_id,))

    if cursor.fetchone() is None:
        raise InvalidRecordID("Category with given id was not found.")

    con.execute("DELETE FROM records WHERE id = ?", (record_id,))


@with_connection
def add_records(
    con: sqlite3.Connection, records: list[RecordCreate]
) -> list[RecordRead]:
    inserted_ids = []

    try:
        for record in records:
            cursor = con.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                ),
            )
            inserted_ids.append(cursor.lastrowid)

        placeholders = ", ".join(["?"] * len(inserted_ids))

        cursor = con.execute(
            f"""
            SELECT r.id, r.code, r.title, r.category_id, r.value, r.status, c.name
            FROM records r
            JOIN categories c ON r.category_id = c.id
            WHERE r.id IN ({placeholders})
            ORDER BY r.id ASC
            """,
            inserted_ids,
        )

        rows = cursor.fetchall()

        result: list[RecordRead] = []
        for row in rows:
            result.append(
                RecordRead(
                    id=row[0],
                    code=row[1],
                    title=row[2],
                    category_id=row[3],
                    value=row[4],
                    status=row[5],
                    category_name=row[6],
                )
            )

        return result

    except sqlite3.IntegrityError as e:
        logger.exception("Failed to add records.")
        error_msg = str(e).lower()

        if "foreign key" in error_msg:
            raise NoSuchCategoryError("Category with such ID not found.")

        elif "unique" in error_msg:
            raise CodeDuplicateError("Code can not duplicate.")

        else:
            raise


@with_connection
def seed_database(
    con: sqlite3.Connection,
    categories: list[CategoryRead],
    records: list[RecordCreate],
) -> bool:
    """Insert the initial dataset atomically when the database is empty."""
    cursor = con.execute("SELECT COUNT(*) FROM categories")
    if cursor.fetchone()[0] > 0:
        return False

    try:
        con.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(category.id, category.name) for category in categories],
        )
        con.executemany(
            """
            INSERT INTO records (code, title, category_id, value, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                )
                for record in records
            ],
        )
    except sqlite3.IntegrityError as e:
        logger.exception("Failed to seed database.")
        raise SeedDataError(
            f"Initial data was rejected and no changes were stored: {e}"
        ) from e

    return True
