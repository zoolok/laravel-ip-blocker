# Конфигурация

Полный конфиг публикуется командой:

```bash
php artisan vendor:publish --tag=ip-blocker-config
```

## Параметры

### `log_path`

Путь к access.log веб-сервера.

```php
'log_path' => env('IP_BLOCKER_LOG_PATH', '/var/log/nginx/access.log'),
```

### `log_format`

Формат лог-файла:

- `auto` — автоопределение (nginx-combined → apache-combined → apache-common)
- `nginx-combined` — nginx combined формат
- `apache-common` — Apache common (CLF)
- `apache-combined` — Apache combined

```php
'log_format' => env('IP_BLOCKER_LOG_FORMAT', 'auto'),
```

### `analysis_window_minutes`

Окно анализа в минутах. IpAnalyzer смотрит запросы за этот период.

```php
'analysis_window_minutes' => (int) env('IP_BLOCKER_ANALYSIS_WINDOW', 5),
```

### `thresholds`

Пороги срабатывания блокировки:

```php
'thresholds' => [
    'max_404_per_window' => (int) env('IP_BLOCKER_MAX_404', 10),
    'max_requests_per_window' => (int) env('IP_BLOCKER_MAX_REQUESTS', 100),
    'max_unique_urls_per_window' => (int) env('IP_BLOCKER_MAX_UNIQUE_URLS', 20),
],
```

IP блокируется, если **любой** из порогов превышен.

### `block_duration_minutes`

Длительность блокировки. `0` — перманентная блокировка.

```php
'block_duration_minutes' => (int) env('IP_BLOCKER_BLOCK_DURATION', 60),
```

### `server`

Настройки веб-сервера:

```php
'server' => [
    'type' => env('IP_BLOCKER_SERVER_TYPE', 'nginx'),
    'deny_path' => env('IP_BLOCKER_DENY_PATH', '/etc/nginx/conf.d/blocked-ips.conf'),
    'reload_command' => env('IP_BLOCKER_RELOAD_CMD', 'nginx -s reload'),
    'allow_override_path' => env('IP_BLOCKER_ALLOW_OVERRIDE_PATH', '/var/www/html/.htaccess'),
],
```

- `type`: `nginx` или `apache`
- `deny_path`: путь для nginx deny-конфига
- `reload_command`: команда перезагрузки сервера после обновления конфига
- `allow_override_path`: путь для Apache .htaccess

### `moonshine`

Включение MoonShine-ресурса:

```php
'moonshine' => [
    'enabled' => env('IP_BLOCKER_MOONSHINE_ENABLED', false),
],
```

Требует установленного `moonshine/moonshine`.

### `report`

Настройки ежедневного отчёта:

```php
'report' => [
    'enabled' => env('IP_BLOCKER_REPORT_ENABLED', true),
    'email' => env('IP_BLOCKER_REPORT_EMAIL'),
    'schedule' => env('IP_BLOCKER_REPORT_SCHEDULE', '0 9 * * *'),
],
```

- `enabled`: включать/отключать отчёт
- `email`: получатель
- `schedule`: cron-выражение (по умолчанию ежедневно в 9:00)

### `cleanup`

Очистка старых записей:

```php
'cleanup' => [
    'retention_days' => (int) env('IP_BLOCKER_RETENTION_DAYS', 30),
    'enabled' => env('IP_BLOCKER_CLEANUP_ENABLED', true),
],
```

### `exclude_paths`

Пути, которые не отслеживаются:

```php
'exclude_paths' => [
    '/healthcheck',
    '/api/documentation',
    '/favicon.ico',
    '/robots.txt',
],
```

Поддерживает wildcard-шаблоны (`Str::is()`).

### `log`

```php
'log' => [
    'channel' => env('IP_BLOCKER_LOG_CHANNEL', 'stack'),
    'level' => env('IP_BLOCKER_LOG_LEVEL', 'debug'),
],
```
