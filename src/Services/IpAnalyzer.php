<?php

namespace Zoolok\IpBlocker\Services;

use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Contracts\SuspiciousIpData;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class IpAnalyzer
{
    public function __construct(
        private readonly int $analysisWindow = 5,
        private readonly int $max404 = 10,
        private readonly int $maxRequests = 100,
        private readonly int $maxUniqueUrls = 20,
        private readonly int $blockDuration = 60,
    ) {}

    /**
     * Analyze suspicious requests and return IPs that exceed thresholds.
     *
     * @return array<int, SuspiciousIpData>
     */
    public function analyze(): array
    {
        $windowStart = now()->subMinutes($this->analysisWindow);
        $windowEnd = now();

        Log::info('[IpAnalyzer.analyze] Starting analysis', [
            'window_from' => $windowStart->toIso8601String(),
            'window_to' => $windowEnd->toIso8601String(),
            'thresholds' => [
                'max_404' => $this->max404,
                'max_requests' => $this->maxRequests,
                'max_unique_urls' => $this->maxUniqueUrls,
            ],
        ]);

        $requests = SuspiciousRequest::forPeriod($windowStart, $windowEnd)
            ->get();

        $grouped = $requests->groupBy('ip');

        $alreadyBlockedIps = BlockedIp::active()->pluck('ip')->toArray();

        $results = [];

        foreach ($grouped as $ip => $ipRequests) {
            if (in_array($ip, $alreadyBlockedIps, true)) {
                Log::debug('[IpAnalyzer.analyze] Skipping already blocked IP', [
                    'ip' => $ip,
                ]);

                continue;
            }

            $totalRequests = $ipRequests->count();
            $notFoundCount = $ipRequests->where('status_code', 404)->count();
            $uniqueUrls = $ipRequests->pluck('url')->unique()->count();

            $windowMinutes = max(1, $this->analysisWindow);
            $requestsPerMinute = round($totalRequests / $windowMinutes, 2);

            $reasons = [];

            if ($notFoundCount >= $this->max404) {
                $reasons[] = "Too many 404 responses: {$notFoundCount} in {$this->analysisWindow} min (limit: {$this->max404})";
            }

            if ($totalRequests >= $this->maxRequests) {
                $reasons[] = "Too many requests: {$totalRequests} in {$this->analysisWindow} min (limit: {$this->maxRequests})";
            }

            if ($uniqueUrls >= $this->maxUniqueUrls) {
                $reasons[] = "Too many unique URLs: {$uniqueUrls} (limit: {$this->maxUniqueUrls})";
            }

            $isSuspicious = count($reasons) > 0;

            if ($isSuspicious) {
                Log::info('[IpAnalyzer.analyze] Suspicious IP detected', [
                    'ip' => $ip,
                    'total_requests' => $totalRequests,
                    'not_found' => $notFoundCount,
                    'unique_urls' => $uniqueUrls,
                    'req_per_min' => $requestsPerMinute,
                    'reasons' => $reasons,
                ]);
            } else {
                Log::debug('[IpAnalyzer.analyze] IP within limits', [
                    'ip' => $ip,
                    'total_requests' => $totalRequests,
                    'not_found' => $notFoundCount,
                    'unique_urls' => $uniqueUrls,
                    'req_per_min' => $requestsPerMinute,
                ]);
            }

            $results[] = new SuspiciousIpData(
                ip: $ip,
                totalRequests: $totalRequests,
                notFoundCount: $notFoundCount,
                uniqueUrls: $uniqueUrls,
                requestsPerMinute: $requestsPerMinute,
                isSuspicious: $isSuspicious,
                reasons: $reasons,
            );
        }

        $suspiciousCount = count(array_filter($results, fn (SuspiciousIpData $d) => $d->isSuspicious));

        Log::info('[IpAnalyzer.analyze] Analysis complete', [
            'total_ips_analyzed' => count($results),
            'suspicious_ips_found' => $suspiciousCount,
            'already_blocked_skipped' => count($alreadyBlockedIps),
        ]);

        return $results;
    }

    /**
     * Analyze a single IP address.
     */
    public function analyzeIp(string $ip): ?SuspiciousIpData
    {
        if (BlockedIp::active()->where('ip', $ip)->exists()) {
            Log::debug('[IpAnalyzer.analyzeIp] IP is already blocked', [
                'ip' => $ip,
            ]);

            return null;
        }

        $windowStart = now()->subMinutes($this->analysisWindow);

        $ipRequests = SuspiciousRequest::forPeriod($windowStart, now())
            ->forIp($ip)
            ->get();

        if ($ipRequests->isEmpty()) {
            Log::debug('[IpAnalyzer.analyzeIp] No recent requests for IP', [
                'ip' => $ip,
            ]);

            return new SuspiciousIpData(
                ip: $ip,
                totalRequests: 0,
                notFoundCount: 0,
                uniqueUrls: 0,
                requestsPerMinute: 0.0,
                isSuspicious: false,
                reasons: [],
            );
        }

        $totalRequests = $ipRequests->count();
        $notFoundCount = $ipRequests->where('status_code', 404)->count();
        $uniqueUrls = $ipRequests->pluck('url')->unique()->count();
        $requestsPerMinute = round($totalRequests / max(1, $this->analysisWindow), 2);

        $reasons = [];

        if ($notFoundCount >= $this->max404) {
            $reasons[] = "Too many 404 responses: {$notFoundCount} in {$this->analysisWindow} min (limit: {$this->max404})";
        }

        if ($totalRequests >= $this->maxRequests) {
            $reasons[] = "Too many requests: {$totalRequests} in {$this->analysisWindow} min (limit: {$this->maxRequests})";
        }

        if ($uniqueUrls >= $this->maxUniqueUrls) {
            $reasons[] = "Too many unique URLs: {$uniqueUrls} (limit: {$this->maxUniqueUrls})";
        }

        return new SuspiciousIpData(
            ip: $ip,
            totalRequests: $totalRequests,
            notFoundCount: $notFoundCount,
            uniqueUrls: $uniqueUrls,
            requestsPerMinute: $requestsPerMinute,
            isSuspicious: count($reasons) > 0,
            reasons: $reasons,
        );
    }

    /**
     * Calculate the blocking expiration time.
     */
    public function getBlockExpiration(): ?\Illuminate\Support\Carbon
    {
        if ($this->blockDuration <= 0) {
            return null;
        }

        return now()->addMinutes($this->blockDuration);
    }
}
