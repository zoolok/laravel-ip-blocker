<?php

namespace Zoolok\IpBlocker\Tests;

use Orchestra\Testbench\TestCase as OrchestraTestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

class TestCase extends OrchestraTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            IpBlockerServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'test');
        $app['config']->set('database.connections.test', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('ip-blocker.log_path', '/var/log/nginx/access.log');
        $app['config']->set('ip-blocker.log_format', 'auto');
        $app['config']->set('ip-blocker.report.enabled', false);
        $app['config']->set('ip-blocker.moonshine.enabled', false);
        $app['config']->set('ip-blocker.server.sync_on_change', false);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../database/migrations'));
    }
}
