<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Log File Path
    |--------------------------------------------------------------------------
    |
    | Path to the web server access log file. Supports nginx and Apache formats.
    | Can be a single file or a glob pattern for rotated logs.
    |
    */
    'log_path' => env('IP_BLOCKER_LOG_PATH', '/var/log/nginx/access.log'),

    /*
    |--------------------------------------------------------------------------
    | Log Format
    |--------------------------------------------------------------------------
    |
    | The format of the access log file.
    | Supported: 'auto', 'nginx-combined', 'apache-common', 'apache-combined'
    |
    | 'auto' - tries to detect format from the first line of the file.
    |
    */
    'log_format' => env('IP_BLOCKER_LOG_FORMAT', 'auto'),

    /*
    |--------------------------------------------------------------------------
    | Analysis Window (minutes)
    |--------------------------------------------------------------------------
    |
    | Time window in minutes for analyzing suspicious requests.
    | The IpAnalyzer will look at requests within this window to determine
    | if an IP should be blocked.
    |
    */
    'analysis_window_minutes' => (int) env('IP_BLOCKER_ANALYSIS_WINDOW', 5),

    /*
    |--------------------------------------------------------------------------
    | Blocking Thresholds
    |--------------------------------------------------------------------------
    |
    | Thresholds that determine when an IP is considered suspicious.
    | If any threshold is exceeded within the analysis window, the IP
    | will be blocked.
    |
    */
    'thresholds' => [
        'max_404_per_window' => (int) env('IP_BLOCKER_MAX_404', 10),
        'max_requests_per_window' => (int) env('IP_BLOCKER_MAX_REQUESTS', 100),
        'max_unique_urls_per_window' => (int) env('IP_BLOCKER_MAX_UNIQUE_URLS', 20),
    ],

    /*
    |--------------------------------------------------------------------------
    | Suspicious Request Detection
    |--------------------------------------------------------------------------
    |
    | Besides HTTP status codes >= 400, requests are also considered
    | suspicious when their User-Agent or URL path matches one of these
    | patterns. This catches scanners that get 200 responses (e.g. SPA
    | apps returning index.html for unknown paths).
    |
    | User-Agent patterns are case-insensitive substring matches.
    | Path patterns support Str::is() wildcards (e.g. '/owa*').
    |
    */
    'suspicious' => [
        /*
         * Block an IP immediately when any of its requests matches a
         * suspicious user-agent or path pattern, even if the request counts
         * stay below the thresholds. User-agent matching is safe (scanner
         * UAs like zgrab/ExchangeScanner never come from real users) and is
         * enabled by default. Path matching is off by default because broad
         * patterns like '/vendor*' can match legitimate admin-panel assets.
         */
        'block_on_user_agent' => (bool) env('IP_BLOCKER_BLOCK_ON_UA', true),
        'block_on_path' => (bool) env('IP_BLOCKER_BLOCK_ON_PATH', false),

        'user_agents' => [
            '*exchangescanner*',
            '*zgrab*',
            '*internetmeasurement*',
            '*backupland*',
            '*visionheight*',
            '*sqlmap*',
            '*nikto*',
            '*nessus*',
            '*nuclei*',
            '*masscan*',
            '*wpscan*',
            '*acunetix*',
            '*dirbuster*',
            '*gobuster*',
            '*ffuf*',
            '*mglndd*',
            '*mirai*',
            '*openvas*',
        ],
        'paths' => [
            '/owa*',
            '/ews*',
            '/autodiscover*',
            '/microsoft-server-activesync*',
            '/ecp*',
            '/mapi*',
            '/rpc*',
            '/goform*',
            '/cgi-bin*',
            '/isapi*',
            '/sdk*',
            '/reports*',
            '/reportserver*',
            '/developmentserver*',
            '/owa/auth*',
            '/wp-admin*',
            '/wp-login*',
            '/wp-content*',
            '/phpmyadmin*',
            '/pma*',
            '/.env',
            '/config.php',
            '/shell.php',
            '/c99.php',
            '/.git*',
            '/actuator*',
            '/console*',
            '/solr*',
            '/jolokia*',
            '/shell*',
            '/xmpp*',
            '/vendor*',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Block Duration (minutes)
    |--------------------------------------------------------------------------
    |
    | How long an IP stays blocked. After this period, the block is lifted
    | automatically. Set to 0 for permanent block.
    |
    */
    'block_duration_minutes' => (int) env('IP_BLOCKER_BLOCK_DURATION', 60),

    /*
    |--------------------------------------------------------------------------
    | Web Server Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for the web server deny config generation.
    | Supports nginx and Apache.
    |
    */
    'server' => [
        'type' => env('IP_BLOCKER_SERVER_TYPE', 'nginx'),
        'deny_path' => env('IP_BLOCKER_DENY_PATH', '/etc/nginx/conf.d/blocked-ips.conf'),
        'reload_command' => env('IP_BLOCKER_RELOAD_CMD', 'nginx -s reload'),
        'allow_override_path' => env('IP_BLOCKER_ALLOW_OVERRIDE_PATH', '/var/www/html/.htaccess'),
    ],

    /*
    |--------------------------------------------------------------------------
    | MoonShine Admin Integration
    |--------------------------------------------------------------------------
    |
    | Enable or disable the optional MoonShine resource for viewing
    | and managing blocked IPs from the admin panel.
    |
    */
    'moonshine' => [
        'enabled' => env('IP_BLOCKER_MOONSHINE_ENABLED', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Daily Report
    |--------------------------------------------------------------------------
    |
    | Configuration for the daily email report about blocked IPs.
    | The report is sent via Laravel mail system.
    |
    */
    'report' => [
        'enabled' => env('IP_BLOCKER_REPORT_ENABLED', true),
        'email' => env('IP_BLOCKER_REPORT_EMAIL'),
        'schedule' => env('IP_BLOCKER_REPORT_SCHEDULE', '0 9 * * *'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Automatic Log Parsing Scheduler
    |--------------------------------------------------------------------------
    |
    | When enabled, the package registers a scheduled task that runs
    | `ip:parse-log --block` on the given cron expression. This parses new
    | lines from the access log (position is tracked automatically) and blocks
    | offending IPs without any manual cron setup.
    |
    | Requires Laravel's scheduler (`php artisan schedule:run`) to be running,
    | e.g. via `* * * * * php /path/to/artisan schedule:run`.
    |
    */
    'scheduler' => [
        'enabled' => env('IP_BLOCKER_SCHEDULER_ENABLED', false),
        'schedule' => env('IP_BLOCKER_SCHEDULER_SCHEDULE', '*/5 * * * *'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cleanup Settings
    |--------------------------------------------------------------------------
    |
    | Automatic cleanup of old suspicious request records.
    | Records older than retention_days will be deleted.
    |
    */
    'cleanup' => [
        'retention_days' => (int) env('IP_BLOCKER_RETENTION_DAYS', 30),
        'enabled' => env('IP_BLOCKER_CLEANUP_ENABLED', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Paths
    |--------------------------------------------------------------------------
    |
    | Paths that should NOT be tracked or blocked by the middleware.
    | Supports wildcard patterns via Str::is().
    |
    */
    'exclude_paths' => [
        '/healthcheck',
        '/api/documentation',
        '/favicon.ico',
        '/robots.txt',
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Log channel and level for the package.
    | Uses Laravel's built-in logging system.
    |
    */
    'log' => [
        'channel' => env('IP_BLOCKER_LOG_CHANNEL', 'stack'),
        'level' => env('IP_BLOCKER_LOG_LEVEL', 'debug'),
    ],

];
