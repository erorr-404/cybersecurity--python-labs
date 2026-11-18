
# Інструкція

## Встановлення

### 1. **Завантаження з репозиторію**

```bash
git clone 'https://github.com/erorr-404/cybersecurity--python-labs'
```

### 2. **Створення віртуального середовища `venv`**

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

### 3. **Встановлення залежностей**

```bash
pip install < requirements.txt
```

## Запуск

### Пошук вразливості онлайн із NVD API

```bash
python -m labs.lab04.main --cve CVE-YYYY-XXXXXX
```

### Завантаження відповіді NVD API із файлу

```bash
python -m labs.lab04.main --cve CVE-YYYY-XXXXXX --input path/to/file
```

### Додаткові налаштування

Програма підтримує роботу із NVD **API-ключем**. Для вибору ключа його необхідно зберегти у змінну середовища із назвою `NVD_API_KEY`. Програма автоматично його знайде та застосує.

Прапорець `-v` виводить додаткову інформацію про процес обробки та підсвічує синтаксис JSON-звіту.  

**Програма виконує такі дії:**

1. Перевіряє правильність CVE-ідентифікатора
2. Робить запит до NVD API
3. Отримує JSON з інформацією про вразливість
4. Перевіряє правильність структури отриманих даних
5. Знаходить оцінку CVSS v3.1
6. Застосовує правило для варіанту №3 (`privilegesRequired = NONE`)
7. Виводить JSON-звіт із результатом аналізу

## Приклад виводу

### Звичайний

Зручний для подальшої роботи в інших програмах.

```bash
(venv) [cybersecurity--python-labs]$ python -m labs.lab04.main --cve CVE-2021-44228
{"cve_id": "CVE-2021-44228", "variant": 3, "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.", "vuln_status": "Analyzed", "cvss_version": "3.1", "score": 10.0, "score_source": "nvd@nist.gov", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "rule": {"threshold": 7.0, "field": "privilegesRequired", "expected": "NONE"}, "observed": "NONE", "decision": "review"}
```

### Детальний

Зручний для читання та аналізу людиною чи ШІ.

```bash
(venv) [cybersecurity--python-labs]$ python -m labs.lab04.main --cve CVE-2021-44228 -v
Sending request to NVD API...
API key was not found. Running anonymously. 
Request URL: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228
Request completed with status code: 200
{
  "cve_id": "CVE-2021-44228",
  "variant": 3,
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default.From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
  "vuln_status": "Analyzed",
  "cvss_version": "3.1",
  "score": 10.0,
  "score_source": "nvd@nist.gov",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "rule": {
    "threshold": 7.0,
    "field": "privilegesRequired",
    "expected": "NONE"
  },
  "observed": "NONE",
  "decision": "review"
}
```

## Автоматизовані тести

Запуск тестів:

```bash
python -m pytest labs/lab04/tests -v
```

Тести знаходяться в директорії `labs/lab04/tests`.
