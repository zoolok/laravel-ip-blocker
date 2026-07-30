<?php

namespace Zoolok\IpBlocker\Contracts;

class SuspiciousIpData
{
    /**
     * @param string $ip The suspicious IP address.
     * @param int $totalRequests Total requests in the analysis window.
     * @param int $notFoundCount Number of 404 responses.
     * @param int $uniqueUrls Number of unique URLs requested.
     * @param float $requestsPerMinute Request frequency.
     * @param bool $isSuspicious Whether the IP exceeds thresholds.
     * @param array<int, string> $reasons Reasons for being flagged as suspicious.
     */
    public function __construct(
        public readonly string $ip,
        public readonly int $totalRequests = 0,
        public readonly int $notFoundCount = 0,
        public readonly int $uniqueUrls = 0,
        public readonly float $requestsPerMinute = 0.0,
        public readonly bool $isSuspicious = false,
        public readonly array $reasons = [],
    ) {}
}
