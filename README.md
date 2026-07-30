# Laravel IP Blocker

[![Latest Version](https://img.shields.io/packagist/v/zoolok/laravel-ip-blocker.svg)](https://packagist.org/packages/zoolok/laravel-ip-blocker)
[![PHP Version](https://img.shields.io/packagist/php-v/zoolok/laravel-ip-blocker.svg)](https://php.net)
[![Laravel Version](https://img.shields.io/badge/Laravel-10--13-red.svg)](https://laravel.com)

Блокировка подозрительных IP-адресов для Laravel. Поддерживает nginx и Apache.

## Возможности

- ✅ **Middleware** — отслеживает 404+ ответы, проверяет блокировку, возвращает 403
- ✅ **Парсинг логов** — читает access.log (nginx combined, Apache common/combined)
- ✅ **Автоопределение формата** — определяет nginx или Apache по первой строке файла
- ✅ **Автоматическая блокировка** — анализирует подозрительную активность и блокирует IP
- ✅ **Генерация deny-конфига** — создаёт nginx deny или Apache Require not ip конфигурацию
- ✅ **Ежедневный отчёт** — email-рассылка со статистикой блокировок
- ✅ **MoonShine** — опциональный админ-ресурс для просмотра блокировок
- ✅ **Инкрементальный парсинг** — запоминает позицию в логе для последующих проходов

## Требования

- PHP ^8.1
- Laravel ^10.0|^11.0|^12.0|^13.0
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

### 3. Запустите парсинг логов

```bash
php artisan ip:parse-log
```

Опции:
- `--path` — путь к лог-файлу (переопределяет конфиг)
- `--format` — формат (auto, nginx-combined, apache-common, apache-combined)
- `--dry-run` — только вывод, без сохранения в БД
- `--from-beginning` — парсить с начала файла (игнорировать сохранённую позицию)

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

## Тестирование

```bash
composer test
```

## Лицензия

MIT
