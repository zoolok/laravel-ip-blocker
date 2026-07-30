<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IP Blocker Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 700px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 { color: #dc3545; border-bottom: 2px solid #dc3545; padding-bottom: 10px; }
        h2 { color: #495057; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; font-weight: 600; }
        .summary { display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }
        .stat-card {
            flex: 1; min-width: 120px; padding: 15px; border-radius: 8px;
            background: #f8f9fa; text-align: center;
        }
        .stat-card .value { font-size: 28px; font-weight: bold; color: #dc3545; }
        .stat-card .label { font-size: 12px; color: #6c757d; text-transform: uppercase; }
        .footer { margin-top: 30px; font-size: 12px; color: #6c757d; border-top: 1px solid #dee2e6; padding-top: 10px; }
        .blocked { color: #dc3545; }
        .safe { color: #28a745; }
    </style>
</head>
<body>
    <h1>🚫 IP Blocker — Ежедневный отчёт</h1>
    <p>Период: <strong>{{ $data->periodLabel }}</strong></p>
    <p>Сгенерирован: {{ $generatedAt }}</p>

    <div class="summary">
        <div class="stat-card">
            <div class="value">{{ $data->totalSuspicious }}</div>
            <div class="label">Подозрительных запросов</div>
        </div>
        <div class="stat-card">
            <div class="value">{{ $data->totalBlocked }}</div>
            <div class="label">Заблокировано IP</div>
        </div>
        <div class="stat-card">
            <div class="value @if($data->activeBlocks > 0) blocked @else safe @endif">{{ $data->activeBlocks }}</div>
            <div class="label">Активных блокировок</div>
        </div>
        <div class="stat-card">
            <div class="value">{{ $data->expiredBlocks }}</div>
            <div class="label">Блокировок снято</div>
        </div>
    </div>

    @if($data->topIps->isNotEmpty())
    <h2>Топ-10 подозрительных IP</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>IP</th>
                <th>Запросов</th>
                <th>Причина</th>
            </tr>
        </thead>
        <tbody>
            @foreach($data->topIps as $i => $item)
            <tr>
                <td>{{ $i + 1 }}</td>
                <td><code>{{ $item['ip'] }}</code></td>
                <td>{{ $item['count'] }}</td>
                <td>{{ $item['reason'] }}</td>
            </tr>
            @endforeach
        </tbody>
    </table>
    @endif

    @if($data->topUrls->isNotEmpty())
    <h2>Топ-10 атакуемых URL</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>URL</th>
                <th>Запросов</th>
            </tr>
        </thead>
        <tbody>
            @foreach($data->topUrls as $i => $item)
            <tr>
                <td>{{ $i + 1 }}</td>
                <td><code>{{ $item['url'] }}</code></td>
                <td>{{ $item['count'] }}</td>
            </tr>
            @endforeach
        </tbody>
    </table>
    @endif

    <h2>Источники блокировок</h2>
    <table>
        <tr>
            <td>Через сервер (nginx/apache deny)</td>
            <td><strong>{{ $data->blockedByServer }}</strong></td>
        </tr>
        <tr>
            <td>Через middleware (403 ответ)</td>
            <td><strong>{{ $data->blockedByMiddleware }}</strong></td>
        </tr>
    </table>

    <div class="footer">
        <p>Сгенерировано laravel-ip-blocker. Настройки: IP_BLOCKER_REPORT_ENABLED={{ config('ip-blocker.report.enabled') ? 'true' : 'false' }}</p>
    </div>
</body>
</html>
