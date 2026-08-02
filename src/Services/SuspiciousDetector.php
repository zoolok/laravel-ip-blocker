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
     * @param array<int, string> $excludedPaths Str::is() patterns that never match as suspicious.
     */
    public function __construct(
        private readonly array $suspiciousUserAgents = [],
        private readonly array $suspiciousPaths = [],
        private readonly array $excludedPaths = [],
    ) {}

    /**
     * Check whether a request is suspicious.
     *
     * A request on an excluded path is never considered suspicious, even
     * when it has a bad status code or matches a suspicious UA/path pattern.
     *
     * @param string $url URL path (with leading slash).
     * @param string|null $userAgent User-Agent header, or null.
     * @param int $statusCode HTTP response status code.
     * @return bool True when the request is considered suspicious.
     */
    public function isSuspicious(string $url, ?string $userAgent, int $statusCode): bool
    {
        if ($this->isExcluded($url)) {
            return false;
        }

        if ($statusCode >= 400) {
            return true;
        }

        if ($this->findMatchingUserAgent($userAgent) !== null) {
            return true;
        }

        return $this->findMatchingPath($url) !== null;
    }

    /**
     * Find the first user-agent pattern that matches the given header.
     *
     * @param string|null $userAgent User-Agent header, or null.
     * @return string|null The matching pattern, or null when nothing matched.
     */
    public function findMatchingUserAgent(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $subject = mb_strtolower($userAgent);

        return $this->findMatch($this->suspiciousUserAgents, $subject, caseInsensitive: true);
    }

    /**
     * Find the first path pattern that matches the given URL.
     *
     * @param string $url URL path (with leading slash).
     * @return string|null The matching pattern, or null when nothing matched.
     */
    public function findMatchingPath(string $url): ?string
    {
        return $this->findMatch($this->suspiciousPaths, mb_strtolower($url), caseInsensitive: true);
    }

    /**
     * Find the first pattern matching the subject.
     *
     * @param array<int, string> $patterns Str::is() patterns.
     * @param string $subject Value to match against.
     * @param bool $caseInsensitive Lowercase both patterns and subject first.
     * @return string|null The matching pattern, or null when nothing matched.
     */
    private function findMatch(array $patterns, string $subject, bool $caseInsensitive): ?string
    {
        foreach ($patterns as $pattern) {
            if ($pattern === '' || $pattern === '*') {
                continue;
            }

            $normalized = $caseInsensitive ? mb_strtolower($pattern) : $pattern;

            if (Str::is($normalized, $subject)) {
                return $pattern;
            }
        }

        return null;
    }

    /**
     * Check whether a URL path matches an excluded pattern.
     *
     * @param string $url URL path (with leading slash).
     * @return bool True when the path matches an excluded pattern.
     */
    public function isExcluded(string $url): bool
    {
        foreach ($this->excludedPaths as $pattern) {
            if ($pattern === '' || $pattern === '*') {
                continue;
            }

            if (Str::is(mb_strtolower($pattern), mb_strtolower($url))) {
                return true;
            }
        }

        return false;
    }
}
