<?php

namespace Zoolok\IpBlocker\Tests\Commands;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class UnblockCommandTest extends TestCase
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
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../../database/migrations'));
    }

    public function test_unblocks_specific_ip_and_clears_its_requests(): void
    {
        BlockedIp::query()->create([
            'ip' => '89.207.69.111',
            'reason' => 'Too many requests',
            'blocked_by' => 'auto',
            'blocked_at' => now(),
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);

        SuspiciousRequest::query()->create([
            'ip' => '89.207.69.111',
            'url' => '/lk/settings',
            'method' => 'GET',
            'status_code' => 403,
        ]);

        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/owa/',
            'method' => 'GET',
            'status_code' => 200,
        ]);

        $exitCode = Artisan::call('ip:unblock', [
            '--ip' => '89.207.69.111',
            '--force' => true,
            '--no-nginx' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertStringContainsString('89.207.69.111', Artisan::output());
        $this->assertEquals(0, BlockedIp::count());
        $this->assertEquals(0, SuspiciousRequest::where('ip', '89.207.69.111')->count());
        $this->assertEquals(1, SuspiciousRequest::where('ip', '10.0.0.1')->count());
    }

    public function test_invalid_ip_returns_failure(): void
    {
        $exitCode = Artisan::call('ip:unblock', [
            '--ip' => 'not-an-ip',
            '--force' => true,
        ]);

        $this->assertEquals(1, $exitCode);
        $this->assertStringContainsString('Invalid IP', Artisan::output());
    }

    public function test_missing_ip_returns_failure(): void
    {
        $exitCode = Artisan::call('ip:unblock', [
            '--force' => true,
        ]);

        $this->assertEquals(1, $exitCode);
        $this->assertStringContainsString('--ip', Artisan::output());
    }

    public function test_unblock_all_clears_everything(): void
    {
        BlockedIp::query()->create([
            'ip' => '89.207.69.111',
            'reason' => 'r1',
            'blocked_by' => 'auto',
            'blocked_at' => now(),
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);

        BlockedIp::query()->create([
            'ip' => '10.0.0.1',
            'reason' => 'r2',
            'blocked_by' => 'auto',
            'blocked_at' => now(),
            'expires_at' => now()->addHour(),
            'is_active' => true,
        ]);

        SuspiciousRequest::query()->create([
            'ip' => '89.207.69.111',
            'url' => '/owa/',
            'method' => 'GET',
            'status_code' => 200,
        ]);

        $exitCode = Artisan::call('ip:unblock', [
            '--all' => true,
            '--force' => true,
            '--no-nginx' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertEquals(0, BlockedIp::count());
        $this->assertEquals(0, SuspiciousRequest::count());
    }

    public function test_nothing_to_unblock_reports_success(): void
    {
        $exitCode = Artisan::call('ip:unblock', [
            '--ip' => '89.207.69.111',
            '--force' => true,
            '--no-nginx' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertStringContainsString('Nothing to unblock', Artisan::output());
    }
}
