<?php

namespace Zoolok\IpBlocker\Tests\Parsers;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Parsers\ApacheCombinedParser;

class ApacheCombinedParserTest extends TestCase
{
    private ApacheCombinedParser $parser;

    protected function setUp(): void
    {
        $this->parser = new ApacheCombinedParser();
    }

    public function test_parses_valid_combined_line(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->ip);
        $this->assertSame('/admin', $result->url);
        $this->assertSame(404, $result->statusCode);
        $this->assertSame('curl/7.68.0', $result->userAgent);
    }

    public function test_parses_with_referer(): void
    {
        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "POST /login HTTP/1.1" 403 456 "https://evil.com" "Mozilla/5.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('https://evil.com', $result->referer);
        $this->assertSame('Mozilla/5.0', $result->userAgent);
    }

    public function test_skips_healthy_status_codes(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /index HTTP/1.1" 200 123 "-" "curl/7.68.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNull($result);
    }

    public function test_parses_ipv6(): void
    {
        $line = '::1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 500 123 "-" "curl"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('::1', $result->ip);
        $this->assertSame(500, $result->statusCode);
    }
}
