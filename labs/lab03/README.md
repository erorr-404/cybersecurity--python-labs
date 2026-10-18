# Інструкція

## Інсталяція та запуск сервера

1. **Завантаження з репозиторію**

```bash
git clone 'https://github.com/erorr-404/cybersecurity--python-labs'
```

2. **Створення віртуального середовища `venv`**

- Для **Linux**:

```bash
cd ./cybersecurity--python-labs
python3 -m venv .venv
source ./venv/bin/activate
```

- Для **Windows**:

```sh
cd ./cybersecurity--python-labs
python -m venv .venv
./venv/Scripts/activate
```

3. **Встановлення залежностей**

```bash
pip install < requirements.txt
```

4. **Створення тестових даних**

Ця команда не обов'язкова, оскільки сервер при запуску автоматично створює тестові дані, якщо база даних пуста.

```bash
python -m labs.lab03.database
python -m labs.lab03.seed
```

5. **Безпосередній запуск сервера**

```bash
python -m labs.lab03.main
```

6. **Перевірка доступності**

```bash
curl -i 'http://127.0.0.1/ping'
```

Якщо сервер працює, отримаєте `{"status": "ok"}`.

## Приклади запитів

- **Отримання даних студента**

```bash
curl -i 'http://127.0.0.1:8000/student'
```

- **Отримання списку записів із фільтрацією та поділом на сторінки**

```bash
curl -i 'http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0](http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0)'
```

- **Створення нової категорії**

```bash
curl -i -X POST 'http://127.0.0.1:8000/categories' -H 'Content-Type: application/json' -d '{"name": "antivirus"}'
```

- **Створення нового запису**

```bash
curl -i -X POST 'http://127.0.0.1:8000/records' -H 'Content-Type: application/json' -d '{"code": "V03-TEST", "title": "Знахідка станції - тестова", "category_id": 1, "value": 8.5, "status": "new"}'
```

- **Пакетне створення записів (Bulk)**

```bash
curl -i -X POST 'http://127.0.0.1:8000/records/bulk' -H 'Content-Type: application/json' -d '[
  {"code": "V03-BULK-01", "title": "Знахідка станції 1", "category_id": 2, "value": 4.5, "status": "in_progress"},
  {"code": "V03-BULK-02", "title": "Знахідка станції 2", "category_id": 3, "value": 9.2, "status": "done"}
]'
```

- **Видалення запису**

```bash
curl -i -X DELETE 'http://127.0.0.1:8000/records/1'
```
