# Учебный сервис заметок

FastAPI и PostgreSQL, только вымышленные данные и тестовые пароли.
В сервисе намеренно оставлены SQL injection, IDOR и открытое хранение паролей.
Стенд предназначен для локальной практики.

## Запуск

Нужны Docker и плагин Docker Compose:

```bash
docker compose up --build -d
```

Swagger: <http://127.0.0.1:8000/docs>. Приложение ждёт успешной проверки
готовности БД. Порт PostgreSQL на хост не публикуется.
При первом запуске создаются `alice / alice` и `bob / bob`, по две заметки
у каждого. Повторный запуск не дублирует данные.

## Примеры запросов

Для примеров нужны `curl` и `python3`. Выполняйте команды в одной Bash-сессии.

```bash
BASE=http://127.0.0.1:8000
ALICE_TOKEN=$(curl -fsS "$BASE/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
BOB_TOKEN=$(curl -fsS "$BASE/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

# Создать заметку Alice и посмотреть её список.
curl -fsS "$BASE/notes" -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"Новая заметка","body":"Вымышленное содержимое"}'
curl -fsS "$BASE/notes" -H "Authorization: Bearer $ALICE_TOKEN"

# Обычный поиск возвращает только заметки Bob.
curl -fsS -G "$BASE/notes/search" \
  -H "Authorization: Bearer $BOB_TOKEN" --data-urlencode 'q=планы'

# IDOR: Bob читает заметку Alice по её ID.
ALICE_NOTE_ID=$(curl -fsS "$BASE/notes" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
curl -fsS "$BASE/notes/$ALICE_NOTE_ID" -H "Authorization: Bearer $BOB_TOKEN"

# SQL injection: поиск от имени Bob возвращает заметки всех пользователей.
curl -fsS -G "$BASE/notes/search" \
  -H "Authorization: Bearer $BOB_TOKEN" \
  --data-urlencode "q=' OR TRUE -- "
```

В Swagger сначала вызовите `/login`, затем нажмите **Authorize** и вставьте
значение `access_token`. Все маршруты заметок требуют Bearer-токен.
Отсутствующий/неизвестный токен и неверный пароль дают `401`,
несуществующий ID — `404`, пустой результат поиска — `[]`.
Создание требует непустой строковый `title` и строковый `body`.

## Где находятся уязвимости

- `main.py`, `search_notes`: `q` вставляется в SQL через f-строку.
  Условие `OR TRUE` обходит ограничение по владельцу. Остальные значения
  в запросах к БД передаются через параметры psycopg.
- `main.py`, `get_note`: запись выбирается только по `id`, без проверки
  её `user_id`. Вход обязателен, но Bob может читать заметки Alice.
- `users.password`: учебные пароли хранятся открытым текстом.

Токены случайные, находятся в словаре Python и действуют до перезапуска
приложения. Запускается один процесс Uvicorn. После перезапуска нужно
получить новые токены; заметки сохраняются в Docker volume `notes_data`.

```bash
docker compose restart
docker compose logs app
docker compose down
```

`down` сохраняет volume. Для полного сброса учебных данных используйте
`docker compose down -v` — эта команда удаляет volume с заметками.
