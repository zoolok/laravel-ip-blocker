<?php

namespace Zoolok\IpBlocker\Tests\Models;

use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Services\DenyGenerator;

/**
 * php artisan test --filter=BlockedIpSyncTest tests/Models/BlockedIpSyncTest.php
 */
class BlockedIpSyncTest extends TestCase
{
    private string $tempDir;
    private string $denyPath;

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

        $app['config']->set('ip-blocker.server.sync_on_change', true);
        $app['config']->set('ip-blocker.server.reload_command', 'echo reloaded');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->loadMigrationsFrom(realpath(__DIR__.'/../../database/migrations'));

        $this->tempDir = sys_get_temp_dir().'/ip-blocker-sync-test-'.uniqid();
        mkdir($this->tempDir, 0777, true);

        $this->denyPath = $this->tempDir.'/blocked-ips.conf';

        $this->app->instance(DenyGenerator::class, new DenyGenerator(
            serverType: 'nginx',
            denyPath: $this->denyPath,
            reloadCommand: 'echo reloaded',
        ));
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tempDir);

        parent::tearDown();
    }

    public function test_sync_from_database_contains_only_active_blocks(): void
    {
        $this->makeBlock('1.1.1.1', null);                // permanent
        $this->makeBlock('2.2.2.2', '+1 hour');           // active
        $this->makeBlock('3.3.3.3', '-1 hour');           // expired

        $generator = app(DenyGenerator::class);
        $this->assertTrue($generator->syncFromDatabase());

        $content = file_get_contents($this->denyPath);

        $this->assertStringContainsString('deny 1.1.1.1;', $content);
        $this->assertStringContainsString('deny 2.2.2.2;', $content);
        $this->assertStringNotContainsString('3.3.3.3', $content);
    }

    public function test_model_events_regenerate_config_on_save(): void
    {
        $this->makeBlock('10.0.0.1', '+1 hour');

        $content = file_get_contents($this->denyPath);
        $this->assertStringContainsString('deny 10.0.0.1;', $content);

        $block = BlockedIp::where('ip', '10.0.0.1')->firstOrFail();
        $block->expires_at = now()->subMinute();
        $block->save();

        $content = file_get_contents($this->denyPath);
        $this->assertStringNotContainsString('10.0.0.1', $content);
    }

    public function test_model_events_regenerate_config_on_delete(): void
    {
        $this->makeBlock('10.0.0.2', '+1 hour');
        $this->makeBlock('10.0.0.3', null);

        BlockedIp::where('ip', '10.0.0.2')->firstOrFail()->delete();

        $content = file_get_contents($this->denyPath);

        $this->assertStringNotContainsString('10.0.0.2', $content);
        $this->assertStringContainsString('deny 10.0.0.3;', $content);
    }

    private function makeBlock(string $ip, ?string $expiresAt): void
    {
        BlockedIp::query()->create([
            'ip' => $ip,
            'reason' => 'test',
            'blocked_by' => 'command',
            'blocked_at' => now(),
            'expires_at' => $expiresAt !== null ? now()->parse($expiresAt) : null,
            'is_active' => true,
        ]);
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir) ?: [], ['.', '..']);

        foreach ($files as $file) {
            $filePath = $dir.'/'.$file;

            if (is_file($filePath)) {
                unlink($filePath);
            } else {
                $this->removeDirectory($filePath);
            }
        }

        rmdir($dir);
    }
}
