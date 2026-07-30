<?php

namespace Zoolok\IpBlocker\Tests\Commands;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

class ParseLogCommandTest extends TestCase
{
    private string $tempDir;

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

        $this->tempDir = sys_get_temp_dir().'/ip-blocker-test-'.uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tempDir);

        parent::tearDown();
    }

    public function test_exits_with_error_for_missing_file(): void
    {
        $exitCode = Artisan::call('ip:parse-log', [
            '--path' => '/nonexistent/access.log',
        ]);

        $this->assertEquals(1, $exitCode);
        $this->assertStringContainsString('not found', Artisan::output());
    }

    public function test_parses_valid_nginx_log(): void
    {
        $logFile = $this->tempDir.'/access.log';
        file_put_contents($logFile, "192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] \"GET /admin HTTP/1.1\" 404 123 \"-\" \"curl/7.68.0\"\n");

        $exitCode = Artisan::call('ip:parse-log', [
            '--path' => $logFile,
            '--from-beginning' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertStringContainsString('suspicious', Artisan::output());
    }

    public function test_dry_run_does_not_save_records(): void
    {
        $logFile = $this->tempDir.'/access.log';
        file_put_contents($logFile, "192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] \"GET /admin HTTP/1.1\" 404 123 \"-\" \"curl/7.68.0\"\n");

        $exitCode = Artisan::call('ip:parse-log', [
            '--path' => $logFile,
            '--from-beginning' => true,
            '--dry-run' => true,
        ]);

        $this->assertEquals(0, $exitCode);
        $this->assertStringContainsString('Dry run', Artisan::output());
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir) ?: [], ['.', '..']);

        foreach ($files as $file) {
            unlink($dir.'/'.$file);
        }

        rmdir($dir);
    }
}
