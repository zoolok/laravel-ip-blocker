<?php

namespace Zoolok\IpBlocker\Tests\Middleware;

use Illuminate\Support\Facades\DB;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class TrackSuspiciousIpsIntegrationTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IpBlockerServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'test');
        $app['config']->set('database.connections.test', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('ip-blocker.exclude_paths', ['/healthcheck']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../../database/migrations'));
    }

    public function test_404_request_logs_suspicious_request(): void
    {
        $this->app['router']->get('/test-404', function () {
            return response('Not Found', 404);
        })->middleware('suspicious-ip');

        $this->get('/test-404', ['REMOTE_ADDR' => '10.0.0.1']);

        $count = SuspiciousRequest::where('ip', '10.0.0.1')->count();

        $this->assertEquals(1, $count);
    }

    public function test_multiple_404_creates_multiple_records(): void
    {
        $this->app['router']->get('/test-404', function () {
            return response('Not Found', 404);
        })->middleware('suspicious-ip');

        $this->get('/test-404', ['REMOTE_ADDR' => '10.0.0.1']);
        $this->get('/test-404', ['REMOTE_ADDR' => '10.0.0.1']);

        $count = SuspiciousRequest::where('ip', '10.0.0.1')->count();

        $this->assertEquals(2, $count);
    }
}
