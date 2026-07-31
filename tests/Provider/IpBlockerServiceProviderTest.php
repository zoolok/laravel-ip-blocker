<?php

namespace Zoolok\IpBlocker\Tests\Provider;

use Illuminate\Console\Scheduling\Schedule;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

/**
 * php artisan test --filter=IpBlockerServiceProviderTest tests/Provider/IpBlockerServiceProviderTest.php
 */
class IpBlockerServiceProviderTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IpBlockerServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('ip-blocker.report.enabled', true);
        $app['config']->set('ip-blocker.report.email', 'admin@example.com');
    }

    /**
     * php artisan test --filter=test_registers_daily_report_schedule
     *
     * Проверяет, что задача ежедневного отчёта зарегистрирована в планировщике
     */
    public function test_registers_daily_report_schedule(): void
    {
        $schedule = $this->app->make(Schedule::class);

        $events = $schedule->events();

        $matches = array_values(array_filter(
            $events,
            fn ($event) => $event->description === 'ip-blocker:daily-report',
        ));

        $this->assertCount(1, $matches);
    }

    /**
     * php artisan test --filter=test_does_not_register_schedule_without_email
     *
     * Проверяет, что задача не регистрируется, если email не настроен
     */
    public function test_does_not_register_schedule_without_email(): void
    {
        config(['ip-blocker.report.email' => null]);

        $schedule = $this->app->make(Schedule::class);

        $matches = array_values(array_filter(
            $schedule->events(),
            fn ($event) => $event->description === 'ip-blocker:daily-report',
        ));

        $this->assertCount(0, $matches);
    }
}
