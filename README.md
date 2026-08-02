# Laravel IP Blocker

[![Latest Version](https://img.shields.io/packagist/v/zoolok/laravel-ip-blocker.svg)](https://packagist.org/packages/zoolok/laravel-ip-blocker)
[![PHP Version](https://img.shields.io/packagist/php-v/zoolok/laravel-ip-blocker.svg)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-10--13-red.svg)](https://laravel.com)

Блокировка подозрительных IP-адресов для Laravel. Поддерживает nginx и Apache.

## Возможности

- ✅ **Middleware** — отслеживает подозрительные ответы, проверяет блокировку, возвращает 403
- ✅ **Парсинг логов** — читает access.log (nginx combined, Apache common/combined)
- ✅ **Автоопределение формата** — определяет nginx или Apache по первой строке файла
- ✅ **Обнаружение сканеров** — по User-Agent и путям даже при ответе 200 (ExchangeScanner, zgrab и т.п.)
- ✅ **Автоматическая блокировка** — анализирует подозрительную активность и блокирует IP
- ✅ **Генерация deny-конфига** — создаёт nginx deny или Apache Require not ip конфигурацию
- ✅ **Ежедневный отчёт** — email-рассылка со статистикой блокировок
- ✅ **MoonShine 3.x / 4.x** — опциональный админ-ресурс для просмотра блокировок
- ✅ **Инкрементальный парсинг** — запоминает позицию в логе для последующих проходов

## Требования

- PHP ^8.1
- Laravel ^10.0|^11.0|^12.0|^13.0
- MoonShine ^3.0|^4.0 (только для интеграции с админ-панелью)
- nginx или Apache (для генерации deny-конфигов)

## Установка

```bash
composer require zoolok/laravel-ip-blocker
```

Публикация конфига и миграций (опционально):

```bash
php artisan vendor:publish --tag=ip-blocker-config
php artisan vendor:publish --tag=ip-blocker-migrations
php artisan migrate
```

## Быстрый старт

### 1. Подключите Middleware

В `bootstrap/app.php` (Laravel 11+) или `Http/Kernel.php`:

```php
// Глобально — на все запросы
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps::class);
})

// Или на группу роутов
Route::middleware('suspicious-ip')->group(function () {
    // ...
});
```

### 2. Настройте конфиг

```env
IP_BLOCKER_LOG_PATH=/var/log/nginx/access.log
IP_BLOCKER_LOG_FORMAT=auto
IP_BLOCKER_SERVER_TYPE=nginx
IP_BLOCKER_DENY_PATH=/etc/nginx/conf.d/blocked-ips.conf
IP_BLOCKER_RELOAD_CMD="nginx -s reload"
```

### 3. Запустите парсинг логов *(опционально)*

Middleware фиксирует только **новые** 4xx-запросы с момента установки, поэтому база `suspicious_requests` изначально пуста. Чтобы сразу анализировать историю, заполните её из существующего access.log:

```bash
php artisan ip:parse-log
```

Опции:
- `--path` — путь к лог-файлу (переопределяет конфиг)
- `--format` — формат (auto, nginx-combined, apache-common, apache-combined)
- `--dry-run` — только вывод, без сохранения в БД
- `--from-beginning` — парсить с начала файла (игнорировать сохранённую позицию)
- `--block` — после парсинга сразу запустить `ip:block` (удобно для cron)

### 4. Заблокируйте подозрительные IP

```bash
php artisan ip:block
```

Опции:
- `--ip` — заблокировать конкретный IP
- `--reason` — причина блокировки
- `--dry-run` — показать, кто будет заблокирован, без блокировки
- `--force` — пропустить подтверждение
- `--no-nginx` — не генерировать deny-конфиг

### Автоматизация (cron / планировщик)

Для автоматической защиты по логам используйте связку `ip:parse-log --block`:

```bash
*/5 * * * * php /path/to/artisan ip:parse-log --block --no-interaction
```

Пакет запоминает позицию в логе, поэтому каждый запуск обрабатывает только новые строки, а затем `--block` анализирует и блокирует нарушителей. Middleware при этом продолжает работать независимо: он фиксирует запросы в реальном времени и возвращает 403 уже заблокированным IP, но **сам блокировки не создаёт** — за это отвечает только `ip:block`. Записи одного и того же запроса могут попасть в `suspicious_requests` дважды (через middleware и через парсинг лога), это не мешает блокировке.

#### Встроенный планировщик

Пакет может сам регистрировать задачу `ip:parse-log --block` в Laravel-планировщике — отдельный cron не нужен. Достаточно включить в конфиге (или `.env`):

```bash
IP_BLOCKER_SCHEDULER_ENABLED=true
# IP_BLOCKER_SCHEDULER_SCHEDULE=*/5 * * * *   # по умолчанию каждые 5 минут
```

При этом у Laravel должен быть запущен планировщик:

```bash
* * * * * php /path/to/artisan schedule:run
```

Задача использует `withoutOverlapping()`, чтобы параллельные запуски не пересекались.

## Интеграция с MoonShine

Пакет предоставляет готовый ресурс для админ-панели [MoonShine](https://getmoonshine.app) для просмотра заблокированных IP. Совместим с **MoonShine 3.x и 4.x**. Ресурс автоматически регистрируется, когда включён в конфиге:

```env
IP_BLOCKER_MOONSHINE_ENABLED=true
```

Если в вашем приложении меню админ-панели формируется вручную (переопределён метод `menu()` в лейауте), добавьте пункт меню автоматически:

```bash
php artisan ip:install-moonshine
```

Команда сама найдёт активный лейаут MoonShine (по конфигу `moonshine.layout`), добавит `use`-импорт ресурса и пункт меню «Заблокированные IP». Команда идемпотентна — повторный запуск ничего не дублирует. Для принудительной перевставки используйте `--force`.

## Поддерживаемые форматы логов

| Формат | Конфиг | Пример |
|--------|--------|--------|
| nginx combined | `nginx-combined` | `192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"` |
| Apache common | `apache-common` | `192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123` |
| Apache combined | `apache-combined` | `192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"` |
| Автоопределение | `auto` | Пробует nginx-combined → apache-combined → apache-common |

## Переменные окружения

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `IP_BLOCKER_LOG_PATH` | `/var/log/nginx/access.log` | Путь к лог-файлу |
| `IP_BLOCKER_LOG_FORMAT` | `auto` | Формат лога |
| `IP_BLOCKER_LOG_LEVEL` | `debug` | Уровень логирования |
| `IP_BLOCKER_ANALYSIS_WINDOW` | `5` | Окно анализа (минуты) |
| `IP_BLOCKER_MAX_404` | `10` | Порог 404 для блокировки |
| `IP_BLOCKER_MAX_REQUESTS` | `100` | Порог запросов для блокировки |
| `IP_BLOCKER_MAX_UNIQUE_URLS` | `20` | Порог уникальных URL |
| `IP_BLOCKER_BLOCK_DURATION` | `60` | Длительность блокировки (минуты) |
| `IP_BLOCKER_SERVER_TYPE` | `nginx` | Тип веб-сервера (nginx/apache) |
| `IP_BLOCKER_DENY_PATH` | `/etc/nginx/conf.d/blocked-ips.conf` | Путь для deny-конфига |
| `IP_BLOCKER_RELOAD_CMD` | `nginx -s reload` | Команда перезагрузки сервера |
| `IP_BLOCKER_REPORT_EMAIL` | — | Email для отчётов |
| `IP_BLOCKER_MOONSHINE_ENABLED` | `false` | Включить MoonShine-ресурс |
| `IP_BLOCKER_RETENTION_DAYS` | `30` | Дней хранить записи |
| `IP_BLOCKER_SCHEDULER_ENABLED` | `false` | Авторегистрация `ip:parse-log --block` в планировщике |
| `IP_BLOCKER_SCHEDULER_SCHEDULE` | `*/5 * * * *` | Cron-выражение для задачи парсинга |

### Обнаружение сканеров (по User-Agent и путям)

По умолчанию пакет отслеживает запросы со статусом **4xx/5xx**. Но сканеры
(ExchangeScanner, zgrab, японские IoT-сканеры и т.п.) часто получают ответ
**200** — например, когда SPA-приложение отдаёт index.html на любой путь.
Такие запросы раньше не попадали в базу и IP не блокировался.

Начиная с v1.3.0 запрос считается подозрительным, если:

- статус >= 400, **или**
- User-Agent совпадает с шаблоном из `ip-blocker.suspicious.user_agents`, **или**
- путь URL совпадает с шаблоном из `ip-blocker.suspicious.paths`

Шаблоны User-Agent — регистронезависимые подстроки с подстановкой `*`.
Шаблоны путей поддерживают wildcard-синтаксис `Str::is()` (например `/owa*`).
Списки настраиваются в опубликованном конфиге `config/ip-blocker.php`:

```php
'suspicious' => [
    'block_on_user_agent' => true,  // блокировать IP при совпадении UA (по умолчанию вкл.)
    'block_on_path' => false,       // блокировать IP при совпадении пути (по умолчанию выкл.)
    'user_agents' => ['*exchangescanner*', '*zgrab*', '*sqlmap*'],
    'paths' => ['/owa*', '/ews*', '/cgi-bin*', '/wp-admin*'],
],
```

#### Блокировка по паттерну (v1.6.0)

Начиная с v1.6.0 IP блокируется **сразу при совпадении с подозрительным
User-Agent**, даже если сделан всего один запрос и ответ был 200 (раньше
нужно было превысить пороги по количеству запросов). Это позволяет ловить
сканирование ExchangeScanner/zgrab/etc. в один запрос.

- `block_on_user_agent = true` — включено по умолчанию. Безопасно: UA вида
  `*zgrab*`, `*exchangescanner*`, `*sqlmap*` не встречаются у реальных
  пользователей.
- `block_on_path = false` — выключено по умолчанию. Широкие паттерны путей
  вроде `/vendor*` могут совпадать с легитимными ассетами админ-панели
  (например `/vendor/moonshine/assets/app.js`), поэтому включайте с
  осторожностью и после проверки списка `paths`.

Переменные окружения:

| Переменная | По умолчанию | Описание |
|-----------|-------------|----------|
| `IP_BLOCKER_BLOCK_ON_UA` | `true` | Блокировать IP при совпадении с подозрительным User-Agent |
| `IP_BLOCKER_BLOCK_ON_PATH` | `false` | Блокировать IP при совпадении с подозрительным путём |

## Тестирование

```bash
composer test
```

## Лицензия

MIT
