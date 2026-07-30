<?php

namespace Zoolok\IpBlocker\Tests\Services;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Services\IpAnalyzer;

class IpAnalyzerTest extends TestCase
{
    public function test_get_block_expiration_returns_carbon(): void
    {
        $analyzer = new IpAnalyzer(blockDuration: 60);

        $expiration = $analyzer->getBlockExpiration();

        $this->assertNotNull($expiration);
        $this->assertInstanceOf(\Illuminate\Support\Carbon::class, $expiration);
    }

    public function test_get_block_expiration_returns_null_for_permanent(): void
    {
        $analyzer = new IpAnalyzer(blockDuration: 0);

        $this->assertNull($analyzer->getBlockExpiration());
    }

    public function test_get_block_expiration_returns_null_for_negative(): void
    {
        $analyzer = new IpAnalyzer(blockDuration: -1);

        $this->assertNull($analyzer->getBlockExpiration());
    }

    public function test_constructor_sets_default_values(): void
    {
        $analyzer = new IpAnalyzer();

        $expiration = $analyzer->getBlockExpiration();

        $this->assertNotNull($expiration);
    }

    public function test_constructor_with_custom_values(): void
    {
        $analyzer = new IpAnalyzer(
            analysisWindow: 10,
            max404: 20,
            maxRequests: 200,
            maxUniqueUrls: 50,
            blockDuration: 120,
        );

        $start = now();
        $expiration = $analyzer->getBlockExpiration();

        $this->assertNotNull($expiration);
        $this->assertTrue($expiration->isFuture(), 'Expiration should be in the future');
        $this->assertTrue($expiration->greaterThan($start), 'Expiration should be after start');
        $this->assertEqualsWithDelta(120, $start->diffInMinutes($expiration, absolute: true), 0.1);
    }
}
