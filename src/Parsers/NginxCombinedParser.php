<?php

namespace Zoolok\IpBlocker\Parsers;

use Zoolok\IpBlocker\Contracts\ParsedRequest;

/**
 * Parser for nginx combined log format.
 *
 * Format:
 *   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
 *
 * Example:
 *   192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"
 */
class NginxCombinedParser extends AbstractParser
{
    private const NGINX_COMBINED_REGEX = '/^(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+\d+\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"/';

    /**
     * Parse a single nginx combined log line.
     *
     * @param string $line A single line from the log file.
     * @return ParsedRequest|null Parsed request data, or null when the line does not match or is not suspicious.
     */
    public function parseLine(string $line): ?ParsedRequest
    {
        if (trim($line) === '') {
            return null;
        }

        if (preg_match(self::NGINX_COMBINED_REGEX, $line, $matches) !== 1) {
            return null;
        }

        return $this->makeRequest($matches);
    }
}
