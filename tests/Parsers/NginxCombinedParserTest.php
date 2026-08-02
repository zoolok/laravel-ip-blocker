<?php

namespace Zoolok\IpBlocker\Tests\Parsers;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Parsers\NginxCombinedParser;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

class NginxCombinedParserTest extends TestCase
{
    private NginxCombinedParser $parser;

    protected function setUp(): void
    {
        $this->parser = new NginxCombinedParser();
    }

    public function test_parses_valid_combined_line(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->ip);
        $this->assertSame('/admin', $result->url);
        $this->assertSame('GET', $result->method);
        $this->assertSame(404, $result->statusCode);
        $this->assertSame('curl/7.68.0', $result->userAgent);
        $this->assertNull($result->referer);
    }

    public function test_skips_healthy_status_codes(): void
    {
        $line = '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /index HTTP/1.1" 200 123 "-" "curl/7.68.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNull($result);
    }

    public function test_parses_ipv6(): void
    {
        $line = '::1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('::1', $result->ip);
    }

    public function test_parses_with_referer(): void
    {
        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "POST /login HTTP/1.1" 403 456 "https://example.com" "Mozilla/5.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('10.0.0.1', $result->ip);
        $this->assertSame('/login', $result->url);
        $this->assertSame('POST', $result->method);
        $this->assertSame(403, $result->statusCode);
        $this->assertSame('Mozilla/5.0', $result->userAgent);
        $this->assertSame('https://example.com', $result->referer);
    }

    public function test_parses_with_special_chars_in_user_agent(): void
    {
        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "GET /wp-admin HTTP/1.1" 404 123 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertStringContainsString('Googlebot', $result->userAgent ?? '');
    }

    public function test_returns_null_for_empty_line(): void
    {
        $this->assertNull($this->parser->parseLine(''));
        $this->assertNull($this->parser->parseLine('   '));
    }

    public function test_returns_null_for_malformed_line(): void
    {
        $this->assertNull($this->parser->parseLine('this is not a log line'));
    }

    public function test_parses_500_status(): void
    {
        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "GET /broken HTTP/1.1" 500 123 "-" "curl/8.0"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame(500, $result->statusCode);
    }

    public function test_strips_query_string_from_url(): void
    {
        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin?page=1&test=2 HTTP/1.1" 404 123 "-" "curl"';

        $result = $this->parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('/admin', $result->url);
    }

    public function test_parses_200_response_with_suspicious_user_agent(): void
    {
        $detector = new SuspiciousDetector(suspiciousUserAgents: ['*exchangescanner*']);
        $parser = new NginxCombinedParser($detector);

        $line = '179.43.186.241 - - [01/Aug/2026:02:19:02 +0300] "GET /owa/ HTTP/1.1" 200 613 "-" "Mozilla/5.0 (compatible; ExchangeScanner/2.1)"';

        $result = $parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame('179.43.186.241', $result->ip);
        $this->assertSame(200, $result->statusCode);
    }

    public function test_parses_200_response_with_suspicious_path(): void
    {
        $detector = new SuspiciousDetector(suspiciousPaths: ['/owa*']);
        $parser = new NginxCombinedParser($detector);

        $line = '179.43.186.241 - - [01/Aug/2026:02:19:02 +0300] "GET /owa/ HTTP/1.1" 200 613 "-" "Mozilla/5.0"';

        $result = $parser->parseLine($line);

        $this->assertNotNull($result);
        $this->assertSame(200, $result->statusCode);
        $this->assertSame('/owa/', $result->url);
    }

    public function test_skips_200_response_without_suspicious_signals(): void
    {
        $detector = new SuspiciousDetector(suspiciousUserAgents: ['*exchangescanner*'], suspiciousPaths: ['/owa*']);
        $parser = new NginxCombinedParser($detector);

        $line = '10.0.0.1 - - [10/Jul/2026:13:55:36 +0000] "GET /index HTTP/1.1" 200 123 "-" "Mozilla/5.0"';

        $this->assertNull($parser->parseLine($line));
    }

    public function test_skips_excluded_path_even_with_bad_status(): void
    {
        $detector = new SuspiciousDetector(suspiciousPaths: ['/vendor*'], excludedPaths: ['/vendor/moonshine*']);
        $parser = new NginxCombinedParser($detector);

        $line = '89.207.69.111 - - [02/Aug/2026:08:43:49 +0300] "GET /vendor/moonshine/assets/app.js HTTP/1.1" 200 14628 "-" "Mozilla/5.0"';

        $this->assertNull($parser->parseLine($line));
    }

    public function test_excluded_admin_path_not_tracked_even_with_503(): void
    {
        $detector = new SuspiciousDetector(excludedPaths: ['/admin*']);
        $parser = new NginxCombinedParser($detector);

        $line = '89.207.69.111 - - [02/Aug/2026:08:43:28 +0300] "GET /admin/resource/blocked-ip-resource/blocked-ip-index-page HTTP/1.1" 503 6692 "-" "Mozilla/5.0"';

        $this->assertNull($parser->parseLine($line));
    }
}
