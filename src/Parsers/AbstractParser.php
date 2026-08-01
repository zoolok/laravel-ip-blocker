<?php

namespace Zoolok\IpBlocker\Parsers;

use Zoolok\IpBlocker\Contracts\LogParserStrategy;
use Zoolok\IpBlocker\Contracts\ParsedRequest;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

abstract class AbstractParser implements LogParserStrategy
{
    protected const MIN_SUSPICIOUS_STATUS = 400;

    protected SuspiciousDetector $detector;

    /**
     * @param SuspiciousDetector|null $detector Detector for UA/path-based detection.
     */
    public function __construct(?SuspiciousDetector $detector = null)
    {
        $this->detector = $detector ?? new SuspiciousDetector();
    }

    /**
     * Normalize a URL by removing query string and fragment.
     *
     * @param string $url Raw URL from the log line.
     * @return string URL without query string and fragment.
     */
    protected function normalizeUrl(string $url): string
    {
        $withoutFragment = explode('#', $url, 2)[0];

        $withoutQuery = explode('?', $withoutFragment, 2)[0];

        return $withoutQuery;
    }

    /**
     * Check if the status code indicates a suspicious request.
     *
     * @param int $statusCode HTTP response status code.
     * @return bool True when the status code is >= 400.
     */
    protected function isSuspiciousStatus(int $statusCode): bool
    {
        return $statusCode >= self::MIN_SUSPICIOUS_STATUS;
    }

    /**
     * Parse a timestamp string from a log line into a Carbon instance.
     *
     * @param string|null $dateString Raw timestamp from the log line.
     * @return \Illuminate\Support\Carbon|null Parsed timestamp, or null when unparseable.
     */
    protected function parseTimestamp(?string $dateString): ?\Illuminate\Support\Carbon
    {
        if ($dateString === null || $dateString === '') {
            return null;
        }

        try {
            return \Illuminate\Support\Carbon::createFromFormat('d/M/Y:H:i:s O', $dateString);
        } catch (\Exception) {
            try {
                return \Illuminate\Support\Carbon::parse($dateString);
            } catch (\Exception) {
                return null;
            }
        }
    }

    /**
     * Validate that a string looks like a valid IPv4 or IPv6 address.
     *
     * @param string $ip Candidate IP address.
     * @return bool True when the string is a valid IP address.
     */
    protected function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Build a ParsedRequest from matched regex groups.
     *
     * Returns null when the IP is invalid or the status code is not
     * suspicious.
     *
     * @param array<string, string> $matches Named regex matches.
     * @return ParsedRequest|null Parsed request data, or null when not applicable.
     */
    protected function makeRequest(array $matches): ?ParsedRequest
    {
        $ip = $matches['ip'] ?? '';
        $statusCode = (int) ($matches['status'] ?? 0);

        if (! $this->isValidIp($ip)) {
            return null;
        }

        $url = $this->normalizeUrl($matches['url'] ?? '/');
        $method = strtoupper($matches['method'] ?? 'GET');
        $timestamp = $this->parseTimestamp($matches['date'] ?? null);
        $userAgent = $matches['ua'] ?? null;
        $referer = $matches['referer'] ?? null;

        if ($userAgent === '-' || $userAgent === '') {
            $userAgent = null;
        }

        if ($referer === '-' || $referer === '') {
            $referer = null;
        }

        if (! $this->detector->isSuspicious($url, $userAgent, $statusCode)) {
            return null;
        }

        return new ParsedRequest(
            ip: $ip,
            url: $url,
            method: $method,
            statusCode: $statusCode,
            userAgent: $userAgent,
            referer: $referer,
            timestamp: $timestamp,
        );
    }
}
