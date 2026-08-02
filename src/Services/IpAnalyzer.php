<?php

namespace Zoolok\IpBlocker\Services;

use Illuminate\Support\Carbon;
use Zoolok\IpBlocker\Contracts\SuspiciousIpData;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class IpAnalyzer
{
    /**
     * @param int $analysisWindow Analysis window length in minutes.
     * @param int $max404 Maximum allowed 404 responses within the window.
     * @param int $maxRequests Maximum allowed total requests within the window.
     * @param int $maxUniqueUrls Maximum allowed unique URLs requested.
     * @param int $blockDuration Default block duration in minutes (0 = permanent).
     * @param SuspiciousDetector|null $detector Detector used to flag IPs matching
     *                                         suspicious user-agent or path patterns.
     * @param bool $blockOnUserAgent Block an IP immediately when any of its requests
     *                                matches a suspicious user-agent pattern.
     * @param bool $blockOnPath Block an IP immediately when any of its requests
     *                          matches a suspicious path pattern.
     */
    public function __construct(
        private readonly int $analysisWindow = 5,
        private readonly int $max404 = 10,
        private readonly int $maxRequests = 100,
        private readonly int $maxUniqueUrls = 20,
        private readonly int $blockDuration = 60,
        private readonly ?SuspiciousDetector $detector = null,
        private readonly bool $blockOnUserAgent = false,
        private readonly bool $blockOnPath = false,
    ) {}

    /**
     * Analyze all suspicious requests and return per-IP statistics.
     *
     * Groups recent suspicious requests by IP, skips IPs that are already
     * actively blocked, and produces a {@see SuspiciousIpData} entry for
     * every remaining IP with its counters and blocking reasons.
     *
     * @return array<int, SuspiciousIpData> Statistics for every analyzed IP.
     */
    public function analyze(): array
    {
        $windowStart = now()->subMinutes($this->analysisWindow);
        $windowEnd = now();

        $requests = SuspiciousRequest::forPeriod($windowStart, $windowEnd)
            ->get();

        $grouped = $requests->groupBy('ip');

        $alreadyBlockedIps = BlockedIp::active()->pluck('ip')->toArray();

        $results = [];

        foreach ($grouped as $ip => $ipRequests) {
            if (in_array($ip, $alreadyBlockedIps, true)) {
                continue;
            }

            $totalRequests = $ipRequests->count();
            $notFoundCount = $ipRequests->where('status_code', 404)->count();
            $uniqueUrls = $ipRequests->pluck('url')->unique()->count();

            $windowMinutes = max(1, $this->analysisWindow);
            $requestsPerMinute = round($totalRequests / $windowMinutes, 2);

            $reasons = $this->patternMatchReasons($ipRequests);

            if ($notFoundCount >= $this->max404) {
                $reasons[] = "Too many 404 responses: {$notFoundCount} in {$this->analysisWindow} min (limit: {$this->max404})";
            }

            if ($totalRequests >= $this->maxRequests) {
                $reasons[] = "Too many requests: {$totalRequests} in {$this->analysisWindow} min (limit: {$this->maxRequests})";
            }

            if ($uniqueUrls >= $this->maxUniqueUrls) {
                $reasons[] = "Too many unique URLs: {$uniqueUrls} (limit: {$this->maxUniqueUrls})";
            }

            $results[] = new SuspiciousIpData(
                ip: $ip,
                totalRequests: $totalRequests,
                notFoundCount: $notFoundCount,
                uniqueUrls: $uniqueUrls,
                requestsPerMinute: $requestsPerMinute,
                isSuspicious: count($reasons) > 0,
                reasons: $reasons,
            );
        }

        return $results;
    }

    /**
     * Analyze a single IP address.
     *
     * Evaluates the IP against the configured thresholds using its recent
     * suspicious requests. Returns null when the IP is already actively
     * blocked.
     *
     * @param string $ip The IP address to analyze.
     * @return SuspiciousIpData|null Statistics for the IP, or null when it is already blocked.
     */
    public function analyzeIp(string $ip): ?SuspiciousIpData
    {
        if (BlockedIp::active()->where('ip', $ip)->exists()) {
            return null;
        }

        $windowStart = now()->subMinutes($this->analysisWindow);

        $ipRequests = SuspiciousRequest::forPeriod($windowStart, now())
            ->forIp($ip)
            ->get();

        if ($ipRequests->isEmpty()) {
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

        $reasons = $this->patternMatchReasons($ipRequests);

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
     *
     * @return Carbon|null Expiration timestamp, or null when the block is permanent or the duration is not positive.
     */
    public function getBlockExpiration(): ?Carbon
    {
        if ($this->blockDuration <= 0) {
            return null;
        }

        return now()->addMinutes($this->blockDuration);
    }

    /**
     * Collect blocking reasons based on suspicious user-agent/path patterns.
     *
     * When enabled, a single request matching a suspicious user-agent or
     * path pattern is enough to flag the IP, regardless of request counts.
     *
     * @param \Illuminate\Support\Collection<int, SuspiciousRequest> $ipRequests Requests of a single IP.
     * @return array<int, string> List of pattern-based blocking reasons.
     */
    private function patternMatchReasons($ipRequests): array
    {
        $reasons = [];

        if ($this->detector === null || (! $this->blockOnUserAgent && ! $this->blockOnPath)) {
            return $reasons;
        }

        foreach ($ipRequests as $request) {
            $userAgent = $request->user_agent;
            $path = $this->extractPath($request->url);

            if ($this->blockOnUserAgent && $userAgent !== null && $userAgent !== '') {
                $matched = $this->detector->findMatchingUserAgent($userAgent);

                if ($matched !== null) {
                    $reasons[] = "Suspicious user-agent match: {$matched}";
                    break;
                }
            }

            if ($this->blockOnPath) {
                $matched = $this->detector->findMatchingPath($path);

                if ($matched !== null) {
                    $reasons[] = "Suspicious path match: {$matched}";
                    break;
                }
            }
        }

        return $reasons;
    }

    /**
     * Extract the path component from a URL or path string.
     *
     * @param string $url Full URL or path (e.g. 'https://example.com/owa' or '/owa').
     * @return string Path with a leading slash.
     */
    private function extractPath(string $url): string
    {
        $path = $url;

        if (preg_match('#^https?://#i', $url)) {
            $parsed = parse_url($url);

            $path = $parsed['path'] ?? '/';
        }

        if (! str_starts_with($path, '/')) {
            $path = '/'.$path;
        }

        return $path;
    }
}
