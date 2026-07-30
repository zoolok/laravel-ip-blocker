<?php

namespace Zoolok\IpBlocker\Contracts;

class ParsedRequest
{
    /**
     * @param string $ip Client IP address.
     * @param string $url Request URL path.
     * @param string $method HTTP method (GET, POST, etc.).
     * @param int $statusCode HTTP response status code.
     * @param string|null $userAgent User-Agent header value.
     * @param string|null $referer Referer header value.
     * @param \Illuminate\Support\Carbon|null $timestamp Request timestamp.
     */
    public function __construct(
        public readonly string $ip,
        public readonly string $url,
        public readonly string $method,
        public readonly int $statusCode,
        public readonly ?string $userAgent = null,
        public readonly ?string $referer = null,
        public readonly ?\Illuminate\Support\Carbon $timestamp = null,
    ) {}
}
