<?php

namespace Zoolok\IpBlocker\Tests\Commands;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class BlockCommandTest extends TestCase
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

        $app['config']->set('ip-blocker.thresholds.max_404_per_window', 1);
        $app['config']->set('ip-blocker.analysis_window_minutes', 60);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../../database/migrations'));
    }

    public function test_dry_run_shows_output_without_blocking(): void
    {
        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/admin',
            'method' => 'GET',
            'status_code' => 404,
        ]);

        $exitCode = Artisan::call('ip:block', [
            '--dry-run' => true,
            '--force' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertStringContainsString('10.0.0.1', Artisan::output());
        $this->assertEquals(0, BlockedIp::count());
    }

    public function test_blocks_specific_ip_with_reason(): void
    {
        $exitCode = Artisan::call('ip:block', [
            '--ip' => '10.0.0.1',
            '--reason' => 'Manual block test',
            '--force' => true,
        ]);

        $this->assertEquals(0, $exitCode);

        $blocked = BlockedIp::where('ip', '10.0.0.1')->first();

        $this->assertNotNull($blocked);
        $this->assertSame('Manual block test', $blocked->reason);
    }
}
