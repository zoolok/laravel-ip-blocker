# Установка

## Требования

- PHP ^8.1
- Laravel ^10.0|^11.0|^12.0|^13.0
- nginx или Apache (для генерации deny-конфигов)
- Расширение PHP: `pcre`

## Установка через Composer

```bash
composer require zoolok/laravel-ip-blocker
```

Пакет использует Laravel auto-discovery. Сервис-провайдер `Zoolok\IpBlocker\IpBlockerServiceProvider` зарегистрируется автоматически.

Если auto-discovery отключён, добавьте в `config/app.php`:

```php
'providers' => [
    Zoolok\IpBlocker\IpBlockerServiceProvider::class,
],
```

## Публикация ассетов

### Конфиг

```bash
php artisan vendor:publish --tag=ip-blocker-config
```

Будет создан `config/ip-blocker.php`.

### Миграции

```bash
php artisan vendor:publish --tag=ip-blocker-migrations
```

После публикации выполните:

```bash
php artisan migrate
```

### Blade-шаблоны (для писем)

```bash
php artisan vendor:publish --tag=ip-blocker-views
```

## Переменные окружения

Минимальная настройка для `.env`:

```env
IP_BLOCKER_LOG_PATH=/var/log/nginx/access.log
IP_BLOCKER_REPORT_EMAIL=admin@example.com
IP_BLOCKER_DENY_PATH=/etc/nginx/conf.d/blocked-ips.conf
```

Полный список переменных — в `config/ip-blocker.php`.
