<?php

namespace Zoolok\IpBlocker\Tests\Models;

use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\Models\BlockedIp;

/**
 * php artisan test --filter=BlockedIpScopeTest tests/Models/BlockedIpScopeTest.php
 */
class BlockedIpScopeTest extends TestCase
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

    private function makeBlock(string $ip, bool $isActive = true, ?string $expiresAt = null): void
    {
        BlockedIp::query()->create([
            'ip' => $ip,
            'reason' => 'test',
            'blocked_by' => 'command',
            'blocked_at' => now()->subHour(),
            'expires_at' => $expiresAt !== null ? now()->parse($expiresAt) : null,
            'is_active' => $isActive,
        ]);
    }

    /**
     * php artisan test --filter=test_active_scope_excludes_expired
     *
     * Тест: активный scope возвращает только действующие блокировки
     */
    public function test_active_scope_excludes_expired(): void
    {
        $this->makeBlock('1.1.1.1', true, '+1 hour');  // активная
        $this->makeBlock('2.2.2.2', true, '-1 hour');  // срок истёк, но is_active = true
        $this->makeBlock('3.3.3.3', false);            // is_active = false
        $this->makeBlock('4.4.4.4', true);             // вечная

        $activeIps = BlockedIp::active()->orderBy("id")->pluck('ip')->all();

        $this->assertSame(['1.1.1.1', '4.4.4.4'], $activeIps);
    }

    /**
     * php artisan test --filter=test_expired_scope_returns_expired
     *
     * Тест: expired scope возвращает истёкшие по сроку и по флагу
     */
    public function test_expired_scope_returns_expired(): void
    {
        $this->makeBlock('1.1.1.1', true, '+1 hour');  // активная
        $this->makeBlock('2.2.2.2', true, '-1 hour');  // срок истёк, но is_active = true
        $this->makeBlock('3.3.3.3', false);            // is_active = false
        $this->makeBlock('4.4.4.4', true);             // вечная

        $expiredIps = BlockedIp::expired()->orderBy("id")->pluck('ip')->all();

        $this->assertSame(['2.2.2.2', '3.3.3.3'], $expiredIps);
    }
}
