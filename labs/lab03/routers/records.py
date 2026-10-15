from fastapi import APIRouter, Depends, HTTPException, Body
from labs.lab03.schemas import RecordsFilter, RecordRead, RecordCreate
from labs.lab03 import repository as repo


router = APIRouter()


@router.get("/{record_id}", status_code=200, response_model=RecordRead)
def get_record(record_id: int):
    return repo.get_record_by_id(record_id=record_id)


@router.get("/", status_code=200, response_model=list[RecordRead])
def get_records(filter: RecordsFilter = Depends()):
    return repo.get_records(filter=filter)


@router.post("/", status_code=201, response_model=RecordRead)
def create_record(record_in: RecordCreate):
    try:
        return repo.add_record(r=record_in)
    
    except repo.NoSuchCategoryError:
        raise HTTPException(404, "There is no category with such ID.")
    
    except repo.CodeDuplicateError:
        raise HTTPException(409, "Record code must be unique.")
    
    except Exception as e:
        raise HTTPException(500, str(e))

@router.put("/{record_id}", status_code=200, response_model=RecordRead)
def update_record(record_id: int, record: RecordCreate):
    try:
        return repo.update_record(record_id=record_id, record=record)
    
    except repo.NoSuchCategoryError as e:
        raise HTTPException(404, "Category with this id does not exist.")
    
    except repo.CodeDuplicateError:
        raise HTTPException(409, "Record code must be unique.")
    
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/{record_id}", status_code=204)
def delete_record(record_id: int):
    try:
        repo.remove_record(record_id=record_id)
    
    except repo.InvalidRecordID:
        raise HTTPException(404, "No record with given id.")
    
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/bulk", status_code=201, response_model=list[RecordRead])
def create_bulk_records(records: list[RecordCreate] = Body(..., min_length=1, max_length=100)):
    try:
        return repo.add_records(records=records)
    
    except repo.NoSuchCategoryError as e:
        raise HTTPException(404, str(e))
    
    except repo.CodeDuplicateError as e:
        raise HTTPException(409, str(e))
    
    except Exception as e:
        raise HTTPException(500, str(e))