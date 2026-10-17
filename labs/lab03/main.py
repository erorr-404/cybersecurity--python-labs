# fast-api застосунок
from fastapi import FastAPI
import shared.student as stud
from labs.lab03.routers import records as records, categories as categories
from contextlib import asynccontextmanager
from labs.lab03.database import initialize_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Реєстр вразливостей робочих станцій",
    description="Сервіс обліку знахідок перевірки робочих станцій. Категорія визначає тип програмного забезпечення, value — оцінку небезпеки, status — стан опрацювання.",
    lifespan=lifespan
)

@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/student")
def student():
    return {
        "student_name": stud.STUDENT_NAME,
        "group_name": stud.GROUP_NAME,
        "variant_number": stud.VARIANT_NUMBER
    }

app.include_router(categories.router, prefix="/categories")
app.include_router(records.router, prefix="/records")