<?php

namespace Zoolok\IpBlocker\Tests\Parsers;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Parsers\ApacheCommonParser;

class ApacheCommonParserTest extends TestCase
{
    private ApacheCommonParser $parser;

    protected function setUp(): void
    {
        $this->parser = new ApacheCommonParser();
    }

    public function test_parses_valid_common_line(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->ip);
        $this->assertSame('/admin', $result->url);
        $this->assertSame('GET', $result->method);
        $this->assertSame(404, $result->statusCode);
        $this->assertNull($result->userAgent);
        $this->assertNull($result->referer);
    }

    public function test_skips_healthy_status_codes(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /index HTTP/1.1" 200 123';

        $result = $this->parser->parseLine($line);

        $this->assertNull($result);
    }

    public function test_parses_ipv6(): void
    {
        $line = '::1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('::1', $result->ip);
    }

    public function test_returns_null_for_empty_line(): void
    {
        $this->assertNull($this->parser->parseLine(''));
    }
}
