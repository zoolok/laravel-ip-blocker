<?php

namespace Zoolok\IpBlocker\Parsers;

use Zoolok\IpBlocker\Contracts\ParsedRequest;

/**
 * Parser for Apache common log format (CLF).
 *
 * Format:
 *   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
 *
 * Example:
 *   192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123
 */
class ApacheCommonParser extends AbstractParser
{
    private const string APACHE_COMMON_REGEX = '/^(?P<ip>\S+)\s+-\s+\S+\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d{3})\s+\d+/';

    public function parseLine(string $line): ?ParsedRequest
    {
        if (trim($line) === '') {
            return null;
        }

        if (preg_match(self::APACHE_COMMON_REGEX, $line, $matches) !== 1) {
            return null;
        }

        return $this->makeRequest($matches);
    }
}
