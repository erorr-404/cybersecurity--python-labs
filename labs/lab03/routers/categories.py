from fastapi import APIRouter, HTTPException
from labs.lab03 import repository as repo, schemas


router = APIRouter()


@router.get("/")
def get_categories():
    return repo.get_categories()


@router.post("/", response_model=schemas.CategoryRead, status_code=201)
def create_category(category_in: schemas.CategoryCreate):
    try:
        new_category = repo.create_category(category=category_in)
        return new_category
    
    except repo.NameDuplicateError:
        raise HTTPException(409, "Name must be unique.")
    
    except repo.InternalDBError as e:
        raise HTTPException(500, str(e))


@router.delete("/{category_id}", status_code=204)
def delete_category(category_id: int):
    try:
        repo.remove_category(id=category_id)
    
    except repo.CategoryIsNotEmpty as e:
        raise HTTPException(409, str(e))
    
    except repo.NoSuchCategoryError as e:
        raise HTTPException(404, str(e))