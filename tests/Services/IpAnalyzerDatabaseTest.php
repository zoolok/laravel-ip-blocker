<?php

namespace Zoolok\IpBlocker\Tests\Services;

use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\SuspiciousRequest;
use Zoolok\IpBlocker\Services\IpAnalyzer;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

/**
 * php artisan test --filter=IpAnalyzerDatabaseTest tests/Services/IpAnalyzerDatabaseTest.php
 */
class IpAnalyzerDatabaseTest extends TestCase
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

    /**
     * php artisan test --filter=test_blocks_single_request_with_suspicious_user_agent
     *
     * Проверяет, что один запрос с подозрительным UA блокирует IP даже без превышения порогов
     */
    public function test_blocks_single_request_with_suspicious_user_agent(): void
    {
        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/',
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0 (compatible; ExchangeScanner/2.1)',
            'status_code' => 200,
        ]);

        $analyzer = new IpAnalyzer(
            analysisWindow: 60,
            max404: 100,
            maxRequests: 100,
            maxUniqueUrls: 100,
            detector: new SuspiciousDetector(
                suspiciousUserAgents: ['*exchangescanner*', '*zgrab*'],
            ),
            blockOnUserAgent: true,
        );

        $results = $analyzer->analyze();

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isSuspicious);
        $this->assertStringContainsString('exchangescanner', implode('; ', $results[0]->reasons));
    }

    /**
     * php artisan test --filter=test_does_not_block_single_healthy_request
     *
     * Проверяет, что один обычный запрос не блокирует IP, когда пороги не превышены
     */
    public function test_does_not_block_single_healthy_request(): void
    {
        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/',
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0 (Windows NT 10.0)',
            'status_code' => 200,
        ]);

        $analyzer = new IpAnalyzer(
            analysisWindow: 60,
            max404: 100,
            maxRequests: 100,
            maxUniqueUrls: 100,
            detector: new SuspiciousDetector(
                suspiciousUserAgents: ['*exchangescanner*', '*zgrab*'],
            ),
            blockOnUserAgent: true,
        );

        $results = $analyzer->analyze();

        $this->assertCount(1, $results);
        $this->assertFalse($results[0]->isSuspicious);
    }

    /**
     * php artisan test --filter=test_path_blocking_off_by_default
     *
     * Проверяет, что блокировка по пути выключена по умолчанию
     */
    public function test_path_blocking_off_by_default(): void
    {
        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/owa/auth/x.js',
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0',
            'status_code' => 200,
        ]);

        $analyzer = new IpAnalyzer(
            analysisWindow: 60,
            max404: 100,
            maxRequests: 100,
            maxUniqueUrls: 100,
            detector: new SuspiciousDetector(
                suspiciousPaths: ['/owa*'],
            ),
            blockOnUserAgent: true,
            blockOnPath: false,
        );

        $results = $analyzer->analyze();

        $this->assertCount(1, $results);
        $this->assertFalse($results[0]->isSuspicious);
    }

    /**
     * php artisan test --filter=test_path_blocking_when_enabled
     *
     * Проверяет, что при включении блокировка по пути срабатывает
     */
    public function test_path_blocking_when_enabled(): void
    {
        SuspiciousRequest::query()->create([
            'ip' => '10.0.0.1',
            'url' => '/owa/auth/x.js',
            'method' => 'GET',
            'user_agent' => 'Mozilla/5.0',
            'status_code' => 200,
        ]);

        $analyzer = new IpAnalyzer(
            analysisWindow: 60,
            max404: 100,
            maxRequests: 100,
            maxUniqueUrls: 100,
            detector: new SuspiciousDetector(
                suspiciousPaths: ['/owa*'],
            ),
            blockOnUserAgent: true,
            blockOnPath: true,
        );

        $results = $analyzer->analyze();

        $this->assertCount(1, $results);
        $this->assertTrue($results[0]->isSuspicious);
        $this->assertStringContainsString('path', implode('; ', $results[0]->reasons));
    }
}
