<?php

namespace Zoolok\IpBlocker\Tests\Middleware;

use Illuminate\Http\Request;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

class TrackSuspiciousIpsTest extends TestCase
{
    private TrackSuspiciousIps $middleware;

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
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../../database/migrations'));

        $this->middleware = new TrackSuspiciousIps();
    }

    public function test_passes_through_for_healthy_response(): void
    {
        $request = Request::create('/health', 'GET');

        $response = $this->middleware->handle($request, function ($req) {
            return response('OK', 200);
        });

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    public function test_passes_through_for_excluded_path(): void
    {
        config(['ip-blocker.exclude_paths' => ['/healthcheck']]);

        $request = Request::create('/healthcheck', 'GET');

        $response = $this->middleware->handle($request, function ($req) {
            return response('OK', 200);
        });

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_does_not_block_excluded_paths_even_with_404(): void
    {
        config(['ip-blocker.exclude_paths' => ['/robots.txt']]);

        $request = Request::create('/robots.txt', 'GET');

        $response = $this->middleware->handle($request, function ($req) {
            return response('Not Found', 404);
        });

        $this->assertEquals(404, $response->getStatusCode());
    }
}
