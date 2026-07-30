# Использование

## Защита через Middleware

Middleware `TrackSuspiciousIps` регистрируется как `suspicious-ip`:

### Глобально (Laravel 11+)

В `bootstrap/app.php`:

```php
return Application::configure()
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(\Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps::class);
    })
    ->create();
```

### Группа роутов

```php
Route::middleware('suspicious-ip')->group(function () {
    Route::get('/admin', [AdminController::class, 'index']);
});
```

### Как это работает

1. Запрос проходит через middleware
2. Если ответ имеет статус 400+, запись сохраняется в `suspicious_requests`
3. Если IP есть в `blocked_ips` (активная блокировка) — возвращается 403:
   ```json
   {
     "error": "Your IP has been blocked",
     "code": "IP_BLOCKED"
   }
   ```
4. Пути из `exclude_paths` игнорируются

## Парсинг логов

### Инкрементальный парсинг

```bash
php artisan ip:parse-log
```

Парсер запоминает позицию в файле (создаёт `.ip-blocker-pos` рядом с логом). При повторном запуске обрабатываются только новые строки.

### Полный парсинг

```bash
php artisan ip:parse-log --from-beginning
```

### Сухой прогон

```bash
php artisan ip:parse-log --dry-run
```

### Указать формат

```bash
php artisan ip:parse-log --format=apache-combined
```

## Блокировка IP

### Автоматический анализ

```bash
php artisan ip:block
```

Анализирует `suspicious_requests` за последние N минут (по умолчанию 5) и блокирует подозрительные IP.

### Сухой прогон

```bash
php artisan ip:block --dry-run
```

### Блокировка конкретного IP

```bash
php artisan ip:block --ip=192.168.1.1 --reason="Manual block" --force
```

### Без генерации deny-конфига

```bash
php artisan ip:block --no-nginx
```

## Интеграция с MoonShine

Включите MoonShine-ресурс в конфиге:

```env
IP_BLOCKER_MOONSHINE_ENABLED=true
```

После этого в админ-панели MoonShine появится раздел "Заблокированные IP" с возможностью просмотра и разблокировки.

## Ежедневные отчёты

Настройте получателя:

```env
IP_BLOCKER_REPORT_EMAIL=admin@example.com
```

Отчёт отправляется ежедневно в 9:00 (настраивается через `report.schedule`). Содержит:

- Общую статистику (подозрительные запросы, блокировки)
- Топ-10 подозрительных IP
- Топ-10 атакуемых URL
- Распределение по источникам блокировок

## Настройка deny-конфигов

### nginx

```env
IP_BLOCKER_SERVER_TYPE=nginx
IP_BLOCKER_DENY_PATH=/etc/nginx/conf.d/blocked-ips.conf
IP_BLOCKER_RELOAD_CMD="nginx -s reload"
```

Убедитесь, что конфиг подключён в основном nginx-конфиге:

```nginx
include /etc/nginx/conf.d/*.conf;
```

### Apache

```env
IP_BLOCKER_SERVER_TYPE=apache
IP_BLOCKER_ALLOW_OVERRIDE_PATH=/var/www/html/.htaccess
IP_BLOCKER_RELOAD_CMD="systemctl reload apache2"
```

## Очистка данных

Старые записи удаляются автоматически при отправке ежедневного отчёта. Период хранения настраивается:

```env
IP_BLOCKER_RETENTION_DAYS=30
```
