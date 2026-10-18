# fast-api застосунок
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI

import shared.student as stud
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.seed import main as fill_initial_data

BASE_DIR = Path(__file__).resolve().parent
log_path = BASE_DIR / "data" / "logs" / "app.log"
log_path.parent.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(log_path, mode="a", encoding="utf-8"),
        logging.StreamHandler(),
    ],
    force=True,
)

for _log in ("uvicorn", "uvicorn.error", "uvicorn.access"):
    uvicorn_logger = logging.getLogger(_log)
    uvicorn_logger.handlers.clear()  # removes default uvicorn logs
    uvicorn_logger.propagate = (
        True  # allows uvicorn log stream to head in custom logger
    )

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Launching App...")

    initialize_database()
    fill_initial_data()

    logger.info("App is ready.")
    yield

    logger.info("Shutting down...")


app = FastAPI(
    title="Реєстр вразливостей робочих станцій",
    description="Сервіс обліку знахідок перевірки робочих станцій. Категорія визначає тип програмного забезпечення, value — оцінку небезпеки, status — стан опрацювання.",
    lifespan=lifespan,
)


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/student")
def student():
    return {
        "student_name": stud.STUDENT_NAME,
        "group_name": stud.GROUP_NAME,
        "variant_number": stud.VARIANT_NUMBER,
    }


app.include_router(categories.router, prefix="/categories")
app.include_router(records.router, prefix="/records")


if __name__ == "__main__":
    uvicorn.run(
        "labs.lab03.main:app", host="127.0.0.1", port=8000, reload=True, log_config=None
    )
