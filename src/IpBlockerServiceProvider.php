<?php

namespace Zoolok\IpBlocker;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Commands\BlockCommand;
use Zoolok\IpBlocker\Commands\ParseLogCommand;
use Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps;
use Zoolok\IpBlocker\MoonShine\BlockedIpResource;
use Zoolok\IpBlocker\Services\LogParser;
use Zoolok\IpBlocker\Services\IpAnalyzer;
use Zoolok\IpBlocker\Services\DenyGenerator;
use Zoolok\IpBlocker\Services\ReportService;

class IpBlockerServiceProvider extends ServiceProvider
{
    private const string PACKAGE_VERSION = '1.0.0';

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ip-blocker.php', 'ip-blocker');

        $this->registerServices();

        Log::debug('[IpBlockerServiceProvider.register] Package registered', [
            'version' => self::PACKAGE_VERSION,
        ]);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishAssets();
            $this->registerCommands();
            $this->registerScheduler();
        }

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'ip-blocker');
        $this->registerMiddleware();
        $this->registerMoonShineResource();

        Log::debug('[IpBlockerServiceProvider.boot] Package booted', [
            'version' => self::PACKAGE_VERSION,
        ]);
    }

    private function registerServices(): void
    {
        $this->app->singleton(LogParser::class, fn ($app) => new LogParser(
            logFormat: $app['config']->get('ip-blocker.log_format', 'auto'),
        ));

        $this->app->singleton(IpAnalyzer::class, fn ($app) => new IpAnalyzer(
            analysisWindow: (int) $app['config']->get('ip-blocker.analysis_window_minutes', 5),
            max404: (int) $app['config']->get('ip-blocker.thresholds.max_404_per_window', 10),
            maxRequests: (int) $app['config']->get('ip-blocker.thresholds.max_requests_per_window', 100),
            maxUniqueUrls: (int) $app['config']->get('ip-blocker.thresholds.max_unique_urls_per_window', 20),
            blockDuration: (int) $app['config']->get('ip-blocker.block_duration_minutes', 60),
        ));

        $this->app->singleton(DenyGenerator::class, fn ($app) => new DenyGenerator(
            serverType: $app['config']->get('ip-blocker.server.type', 'nginx'),
            denyPath: $app['config']->get('ip-blocker.server.deny_path'),
            reloadCommand: $app['config']->get('ip-blocker.server.reload_command'),
            allowOverridePath: $app['config']->get('ip-blocker.server.allow_override_path'),
        ));

        $this->app->singleton(ReportService::class, fn ($app) => new ReportService(
            retentionDays: (int) $app['config']->get('ip-blocker.cleanup.retention_days', 30),
            cleanupEnabled: (bool) $app['config']->get('ip-blocker.cleanup.enabled', true),
        ));
    }

    private function registerCommands(): void
    {
        $this->commands([
            ParseLogCommand::class,
            BlockCommand::class,
        ]);

        Log::debug('[IpBlockerServiceProvider] Commands registered');
    }

    private function registerScheduler(): void
    {
        $this->callAfterResolving('Illuminate\Contracts\Console\Kernel', function ($kernel) {
            $schedule = $kernel->getSchedule();

            $reportEnabled = $this->app['config']->get('ip-blocker.report.enabled', true);
            $reportEmail = $this->app['config']->get('ip-blocker.report.email');
            $scheduleExpression = $this->app['config']->get('ip-blocker.report.schedule', '0 9 * * *');

            if ($reportEnabled && $reportEmail) {
                $schedule->call(function () {
                    $reportService = $this->app->make(ReportService::class);
                    $reportService->sendDailyReport();
                })->cron($scheduleExpression)->name('ip-blocker:daily-report');

                Log::debug('[IpBlockerServiceProvider] Daily report scheduled', [
                    'cron' => $scheduleExpression,
                    'email' => $reportEmail,
                ]);
            } elseif ($reportEnabled && ! $reportEmail) {
                Log::warning('[IpBlockerServiceProvider] Report enabled but no email configured. Set IP_BLOCKER_REPORT_EMAIL.');
            }
        });
    }

    private function registerMiddleware(): void
    {
        $this->app['router']->aliasMiddleware('suspicious-ip', TrackSuspiciousIps::class);

        Log::debug('[IpBlockerServiceProvider] Middleware alias registered: suspicious-ip');
    }

    private function registerMoonShineResource(): void
    {
        $moonshineEnabled = $this->app['config']->get('ip-blocker.moonshine.enabled', false);

        if (! $moonshineEnabled) {
            return;
        }

        if (! class_exists(\MoonShine\Laravel\DependencyInjection\MoonShineConfigurator::class)) {
            Log::warning('[IpBlockerServiceProvider] MoonShine not installed. Install moonshine/moonshine or disable moonshine in config.');

            return;
        }

        $this->callAfterResolving('MoonShine\Contracts\Core\DependencyInjection\CoreContract', function ($core) {
            $core->resources([
                BlockedIpResource::class,
            ]);

            Log::debug('[IpBlockerServiceProvider] MoonShine resource registered: BlockedIpResource');
        });
    }

    private function publishAssets(): void
    {
        $this->publishes([
            __DIR__.'/../config/ip-blocker.php' => config_path('ip-blocker.php'),
        ], 'ip-blocker-config');

        $this->publishes([
            __DIR__.'/../database/migrations/' => database_path('migrations'),
        ], 'ip-blocker-migrations');

        $this->publishes([
            __DIR__.'/../resources/views' => resource_path('views/vendor/ip-blocker'),
        ], 'ip-blocker-views');

        Log::debug('[IpBlockerServiceProvider] Publishable assets registered');
    }
}
