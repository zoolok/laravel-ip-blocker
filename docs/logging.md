# Логирование

Пакет использует стандартную систему логирования Laravel.

## Настройка

```env
IP_BLOCKER_LOG_CHANNEL=stack
IP_BLOCKER_LOG_LEVEL=debug
```

## Уровни логирования

| Уровень | Использование |
|---------|---------------|
| `ERROR` | Ошибки, требующие внимания (файл не найден, ошибка отправки письма, сбой перезагрузки сервера) |
| `WARNING` | Проблемы, не влияющие на работу (не удалось определить формат лога, не настроен email, ошибка парсинга строки) |
| `INFO` | Важные события (запуск/завершение команд, блокировка IP, генерация отчёта, перезагрузка сервера) |
| `DEBUG` | Подробная отладочная информация (каждый подозрительный запрос, метрики IP, позиция в логе) |

## Структура логов

Все логи содержат префикс компонента в квадратных скобках:

```
[IpBlockerServiceProvider.register] Package registered
[LogParser.parse] Starting log parsing
[IpAnalyzer.analyze] Suspicious IP detected
[TrackSuspiciousIps] BLOCKED
[BlockedIp.created] IP blocked
[DenyGenerator.generate] Generating deny config
[ReportService.sendDailyReport] Report sent
```

## Примеры

### Успешный парсинг лога

```
[2026-07-30 13:55:36] local.DEBUG: [LogParser.parse] Starting log parsing
  {"path":"/var/log/nginx/access.log","format":"nginx-combined","start_position":0}
[2026-07-30 13:55:36] local.DEBUG: [LogParser.parse] Found suspicious request
  {"ip":"192.168.1.1","url":"/admin","method":"GET","status":404}
[2026-07-30 13:55:36] local.INFO: [LogParser.parse] Parsing complete
  {"path":"/var/log/nginx/access.log","format":"nginx-combined","lines_processed":1500,"suspicious_found":12,"end_position":123456}
```

### Блокировка IP

```
[2026-07-30 13:56:00] local.INFO: [IpAnalyzer.analyze] Suspicious IP detected
  {"ip":"192.168.1.1","total_requests":45,"not_found":40,"unique_urls":15,"req_per_min":9,"reasons":["Too many 404 responses: 40 in 5 min (limit: 10)"]}
[2026-07-30 13:56:00] local.INFO: [BlockedIp.created] IP blocked
  {"ip":"192.168.1.1","reason":"Too many 404 responses: 40 in 5 min (limit: 10)","blocked_by":"auto","expires_at":"2026-07-30T14:56:00+00:00","duration_minutes":60}
[2026-07-30 13:56:01] local.INFO: [DenyGenerator.generate] Config file written
  {"path":"/etc/nginx/conf.d/blocked-ips.conf","bytes":45}
[2026-07-30 13:56:01] local.INFO: [DenyGenerator.reloadServer] Server reloaded successfully
```

### Middleware блокировка

```
[2026-07-30 13:57:00] local.DEBUG: [TrackSuspiciousIps] SAVED
  {"ip":"192.168.1.1","url":"http://example.com/admin","method":"GET","status":404}
[2026-07-30 13:57:01] local.INFO: [TrackSuspiciousIps] BLOCKED
  {"ip":"192.168.1.1","url":"http://example.com/admin","method":"GET","status":404}
```
