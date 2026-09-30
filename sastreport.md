Описал 2 тестовых примера соотвествующщему тестовому стенду в файле test_rules.yml

1 - Warning
Ругается если параметр id передан в запрос и кидает варнинг на проверку прав

2 - ERROR

Ругается если параметр q передается напряммую в sql запрос а не параметрами функции execute



Анализ пакетов





├──────────────────────┼────────────────┼──────────┤        ├───────────────────┼───────────────┼──────────────────────────────────────────────────────────────┤
│ starlette (METADATA) │ CVE-2025-62727 │ HIGH     │        │ 0.46.2            │ 0.49.1        │ starlette: Starlette DoS via Range header merging            │ - Не применима в текущей конфигурации: приложение и подключённые компоненты не используют FileResponse/StaticFiles, уязвимый обработчик недоступен.
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2025-62727                   │
│                      ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤ 
│                      │ CVE-2026-48818 │          │        │                   │ 1.1.0         │ starlette: Starlette: SSRF and NTLM credential theft via UNC │ - Не применима: приложение работает в Linux-контейнере на Debian. Дополнительно: StaticFiles не используется.
│                      │                │          │        │                   │               │ paths in StaticFiles...                                      │
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-48818                   │
│                      ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│                      │ CVE-2026-54283 │          │        │                   │ 1.3.1         │ starlette: Starlette: request.form() limits silently ignored │ - Не применима: обработчики принимают JSON; разбор form-urlencoded через request.form() и зависимости, использующие его, отсутствует.
│                      │                │          │        │                   │               │ for application/x-www-form-urlencoded enable DoS             │
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-54283                   │
│                      ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│                      │ CVE-2025-54121 │ MEDIUM   │        │                   │ 0.47.2        │ starlette: Starlette denial-of-service                       │ - Не применима: приложение не разбирает multipart-запросы и не использует загрузку файлов через UploadFile/File.
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2025-54121                   │
│                      ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│                      │ CVE-2026-48710 │          │        │                   │ 1.0.1         │ starlette: Starlette: Security restriction bypass via        │ - Требует проверки: используются ли request.url/request.url.path для выбора правил авторизации или других ограничений.
│                      │                │          │        │                   │               │ malformed HTTP Host header                                   │
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-48710                   │
│                      ├────────────────┤          │        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│                      │ CVE-2026-48817 │          │        │                   │ 1.1.0         │ starlette: Starlette: Information disclosure and unintended  │ - Не применима, если используются только обычные обработчики FastAPI @app.get/post/..., а подклассы HTTPEndpoint с описанной конфигурацией отсутствуют.
│                      │                │          │        │                   │               │ method execution via non-standard HTTP methods...            │
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-48817                   │
│                      ├────────────────┼──────────┤        │                   ├───────────────┼──────────────────────────────────────────────────────────────┤
│                      │ CVE-2026-54282 │ LOW      │        │                   │ 1.3.0         │ starlette: Starlette: Information disclosure due to improper │ - Требует проверки: использование request.url.hostname/netloc и возможность доставки некорректного пути до приложения.
│                      │                │          │        │                   │               │ HTTP request path validation                                 │
│                      │                │          │        │                   │               │ https://avd.aquasec.com/nvd/cve-2026-54282                   │
└──────────────────────┴────────────────┴──────────┴────────┴───────────────────┴───────────────┴──────────────────────────────────────────────────────────────┘


установить starrlete 1.3.0 невозхможно иза за конфликта с fastatpi
ERROR: Cannot install -r requirements.txt (line 1) and starlette==1.3.0 because these package versions have conflicting dependencies.

The conflict is caused by:
    The user requested starlette==1.3.0
    fastapi 0.115.12 depends on starlette<0.47.0 and >=0.40.0


Сделано для следующих requriments:
fastapi==0.115.12
uvicorn==0.34.2
psycopg[binary]==3.2.6


пересбор с 

fastapi==0.134.0
uvicorn==0.34.2
psycopg[binary]==3.2.6
starlette==1.3.1

пофиксил конфликт и убрал уязвимости в пакетах starlette
