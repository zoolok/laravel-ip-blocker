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

    public function test_blocked_ip_gets_403_before_processing(): void
    {
        $processed = false;

        $this->app['router']->get('/protected', function () use (&$processed) {
            $processed = true;

            return response('OK', 200);
        })->middleware('suspicious-ip');

        \Zoolok\IpBlocker\Models\BlockedIp::query()->create([
            'ip' => '10.0.0.1',
            'reason' => 'Test block',
            'blocked_by' => 'test',
            'blocked_at' => now(),
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);

        $response = $this->get('/protected', ['REMOTE_ADDR' => '10.0.0.1']);

        $response->assertStatus(403);
        $this->assertFalse($processed, 'Route handler must not run for a blocked IP');
    }

    public function test_200_response_with_suspicious_user_agent_logs_suspicious_request(): void
    {
        config()->set('ip-blocker.suspicious.user_agents', ['*exchangescanner*']);

        $this->app['router']->get('/test-ok', function () {
            return response('OK', 200);
        })->middleware('suspicious-ip');

        $this->get('/test-ok', [
            'REMOTE_ADDR' => '10.0.0.5',
            'HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; ExchangeScanner/2.1)',
        ]);

        $count = SuspiciousRequest::where('ip', '10.0.0.5')->count();

        $this->assertEquals(1, $count);
    }

    public function test_200_response_with_suspicious_path_logs_suspicious_request(): void
    {
        config()->set('ip-blocker.suspicious.paths', ['/owa*']);

        $this->app['router']->get('/owa/', function () {
            return response('OK', 200);
        })->middleware('suspicious-ip');

        $this->get('/owa/', ['REMOTE_ADDR' => '10.0.0.6']);

        $count = SuspiciousRequest::where('ip', '10.0.0.6')->count();

        $this->assertEquals(1, $count);
    }

    public function test_200_response_without_suspicious_signals_not_logged(): void
    {
        config()->set('ip-blocker.suspicious.user_agents', ['*exchangescanner*']);
        config()->set('ip-blocker.suspicious.paths', ['/owa*']);

        $this->app['router']->get('/normal', function () {
            return response('OK', 200);
        })->middleware('suspicious-ip');

        $this->get('/normal', ['REMOTE_ADDR' => '10.0.0.7']);

        $count = SuspiciousRequest::where('ip', '10.0.0.7')->count();

        $this->assertEquals(0, $count);
    }
}
