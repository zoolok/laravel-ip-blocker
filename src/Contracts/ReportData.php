<?php

namespace Zoolok\IpBlocker\Contracts;

use Illuminate\Support\Collection;

class ReportData
{
    /**
     * @param int $totalSuspicious Total suspicious requests in the last 24h.
     * @param int $totalBlocked Total IPs blocked in the last 24h.
     * @param int $activeBlocks Currently active blocks.
     * @param int $expiredBlocks Blocks that expired in the last 24h.
     * @param Collection<int, array{ip: string, count: int, reason: string}> $topIps Top 10 most active suspicious IPs.
     * @param Collection<int, array{url: string, count: int}> $topUrls Top 10 most targeted URLs.
     * @param int $blockedByMiddleware Count of requests blocked by middleware.
     * @param int $blockedByServer Count of IPs blocked in server config.
     * @param string $periodLabel Human-readable period description.
     */
    public function __construct(
        public readonly int $totalSuspicious = 0,
        public readonly int $totalBlocked = 0,
        public readonly int $activeBlocks = 0,
        public readonly int $expiredBlocks = 0,
        public readonly Collection $topIps = new Collection(),
        public readonly Collection $topUrls = new Collection(),
        public readonly int $blockedByMiddleware = 0,
        public readonly int $blockedByServer = 0,
        public readonly string $periodLabel = 'last 24 hours',
    ) {}
}
