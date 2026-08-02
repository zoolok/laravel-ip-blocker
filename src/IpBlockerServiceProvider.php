<?php

namespace Zoolok\IpBlocker;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\ServiceProvider;
use Psr\Log\LoggerInterface;
use Zoolok\IpBlocker\Commands\BlockCommand;
use Zoolok\IpBlocker\Commands\InstallMoonShineCommand;
use Zoolok\IpBlocker\Commands\ParseLogCommand;
use Zoolok\IpBlocker\Commands\UnblockCommand;
use Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps;
use Zoolok\IpBlocker\MoonShine\BlockedIpResource;
use Zoolok\IpBlocker\Services\LogParser;
use Zoolok\IpBlocker\Services\IpAnalyzer;
use Zoolok\IpBlocker\Services\DenyGenerator;
use Zoolok\IpBlocker\Services\ReportService;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

class IpBlockerServiceProvider extends ServiceProvider
{
    private const PACKAGE_VERSION = '1.0.0';

    /**
     * Register package services and merge its configuration.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/ip-blocker.php', 'ip-blocker');

        $this->registerServices();
    }

    /**
     * Bootstrap the package.
     *
     * Loads migrations and views, registers the middleware alias and the
     * MoonShine resource, and (in console) publishes assets, registers
     * commands and the scheduler.
     *
     * @return void
     */
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
    }

    /**
     * Register the package services as singletons.
     *
     * @return void
     */
    private function registerServices(): void
    {
        $this->app->singleton(SuspiciousDetector::class, fn ($app) => new SuspiciousDetector(
            suspiciousUserAgents: $app['config']->get('ip-blocker.suspicious.user_agents', []),
            suspiciousPaths: $app['config']->get('ip-blocker.suspicious.paths', []),
            excludedPaths: $app['config']->get('ip-blocker.exclude_paths', []),
        ));

        $this->app->singleton(LogParser::class, fn ($app) => new LogParser(
            logFormat: $app['config']->get('ip-blocker.log_format', 'auto'),
            logger: $app->make(LoggerInterface::class),
            detector: $app->make(SuspiciousDetector::class),
        ));

        $this->app->singleton(IpAnalyzer::class, fn ($app) => new IpAnalyzer(
            analysisWindow: (int) $app['config']->get('ip-blocker.analysis_window_minutes', 5),
            max404: (int) $app['config']->get('ip-blocker.thresholds.max_404_per_window', 10),
            maxRequests: (int) $app['config']->get('ip-blocker.thresholds.max_requests_per_window', 100),
            maxUniqueUrls: (int) $app['config']->get('ip-blocker.thresholds.max_unique_urls_per_window', 20),
            blockDuration: (int) $app['config']->get('ip-blocker.block_duration_minutes', 60),
            detector: $app->make(SuspiciousDetector::class),
            blockOnUserAgent: (bool) $app['config']->get('ip-blocker.suspicious.block_on_user_agent', true),
            blockOnPath: (bool) $app['config']->get('ip-blocker.suspicious.block_on_path', false),
        ));

        $this->app->singleton(DenyGenerator::class, fn ($app) => new DenyGenerator(
            serverType: $app['config']->get('ip-blocker.server.type', 'nginx'),
            denyPath: $app['config']->get('ip-blocker.server.deny_path'),
            reloadCommand: $app['config']->get('ip-blocker.server.reload_command'),
            allowOverridePath: $app['config']->get('ip-blocker.server.allow_override_path'),
            logger: $app->make(LoggerInterface::class),
        ));

        $this->app->singleton(ReportService::class, fn ($app) => new ReportService(
            retentionDays: (int) $app['config']->get('ip-blocker.cleanup.retention_days', 30),
            cleanupEnabled: (bool) $app['config']->get('ip-blocker.cleanup.enabled', true),
        ));
    }

    /**
     * Register the package console commands.
     *
     * @return void
     */
    private function registerCommands(): void
    {
        $this->commands([
            ParseLogCommand::class,
            BlockCommand::class,
            UnblockCommand::class,
            InstallMoonShineCommand::class,
        ]);
    }

    /**
     * Register the package scheduled tasks.
     *
     * Registers the daily report and, when enabled, the automatic
     * `ip:parse-log --block` task. Uses the schedule resolver so the tasks
     * work in Laravel 10+.
     *
     * @return void
     */
    private function registerScheduler(): void
    {
        $this->callAfterResolving(Schedule::class, function (Schedule $schedule) {
            $this->registerDailyReport($schedule);
            $this->registerLogParsing($schedule);
        });
    }

    /**
     * Register the daily report scheduled task.
     *
     * @param Schedule $schedule Scheduler instance.
     * @return void
     */
    private function registerDailyReport(Schedule $schedule): void
    {
        $reportEnabled = $this->app['config']->get('ip-blocker.report.enabled', true);
        $reportEmail = $this->app['config']->get('ip-blocker.report.email');
        $scheduleExpression = $this->app['config']->get('ip-blocker.report.schedule', '0 9 * * *');

        if ($reportEnabled && $reportEmail) {
            $schedule->call(function () {
                $reportService = $this->app->make(ReportService::class);
                $reportService->sendDailyReport();
            })->cron($scheduleExpression)->name('ip-blocker:daily-report');
        }
    }

    /**
     * Register the automatic log parsing scheduled task.
     *
     * @param Schedule $schedule Scheduler instance.
     * @return void
     */
    private function registerLogParsing(Schedule $schedule): void
    {
        $schedulerEnabled = $this->app['config']->get('ip-blocker.scheduler.enabled', false);
        $scheduleExpression = $this->app['config']->get('ip-blocker.scheduler.schedule', '*/5 * * * *');

        if (! $schedulerEnabled) {
            return;
        }

        $schedule->command('ip:parse-log --block')
            ->cron($scheduleExpression)
            ->name('ip-blocker:parse-log')
            ->withoutOverlapping();
    }

    /**
     * Register the suspicious-ip middleware alias.
     *
     * @return void
     */
    private function registerMiddleware(): void
    {
        $this->app['router']->aliasMiddleware('suspicious-ip', TrackSuspiciousIps::class);
    }

    /**
     * Register the MoonShine resource when enabled and installed.
     *
     * @return void
     */
    private function registerMoonShineResource(): void
    {
        $moonshineEnabled = $this->app['config']->get('ip-blocker.moonshine.enabled', false);

        if (! $moonshineEnabled) {
            return;
        }

        if (! class_exists(\MoonShine\Laravel\DependencyInjection\MoonShineConfigurator::class)) {
            return;
        }

        $this->callAfterResolving('MoonShine\Contracts\Core\DependencyInjection\CoreContract', function ($core) {
            $core->resources([
                BlockedIpResource::class,
            ]);
        });
    }

    /**
     * Register publishable package assets.
     *
     * @return void
     */
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
    }
}
