<?php

namespace Zoolok\IpBlocker\Services;

use Illuminate\Support\Str;

/**
 * Decides whether a request is suspicious.
 *
 * A request is suspicious when its HTTP status is >= 400, its User-Agent
 * matches a configured pattern, or its URL path matches a configured
 * pattern. The latter two catch scanners that receive 200 responses
 * (e.g. SPA apps returning index.html for unknown paths).
 */
class SuspiciousDetector
{
    /**
     * @param array<int, string> $suspiciousUserAgents Case-insensitive Str::is() patterns.
     * @param array<int, string> $suspiciousPaths Str::is() patterns.
     */
    public function __construct(
        private readonly array $suspiciousUserAgents = [],
        private readonly array $suspiciousPaths = [],
    ) {}

    /**
     * Check whether a request is suspicious.
     *
     * @param string $url URL path (with leading slash).
     * @param string|null $userAgent User-Agent header, or null.
     * @param int $statusCode HTTP response status code.
     * @return bool True when the request is considered suspicious.
     */
    public function isSuspicious(string $url, ?string $userAgent, int $statusCode): bool
    {
        if ($statusCode >= 400) {
            return true;
        }

        if ($userAgent !== null && $this->matchesAny($this->suspiciousUserAgents, mb_strtolower($userAgent), caseInsensitive: true)) {
            return true;
        }

        return $this->matchesAny($this->suspiciousPaths, mb_strtolower($url), caseInsensitive: true);
    }

    /**
     * Check whether the subject matches any of the patterns.
     *
     * @param array<int, string> $patterns Str::is() patterns.
     * @param string $subject Value to match against.
     * @param bool $caseInsensitive Lowercase both patterns and subject first.
     * @return bool True when any pattern matches.
     */
    private function matchesAny(array $patterns, string $subject, bool $caseInsensitive): bool
    {
        foreach ($patterns as $pattern) {
            if ($pattern === '' || $pattern === '*') {
                continue;
            }

            $normalized = $caseInsensitive ? mb_strtolower($pattern) : $pattern;

            if (Str::is($normalized, $subject)) {
                return true;
            }
        }

        return false;
    }
}
