<?php

namespace Zoolok\IpBlocker\Tests\Services;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Services\LogParser;

class LogParserTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir().'/ip-blocker-test-'.uniqid();
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->tempDir);
    }

    public function test_parses_nginx_log_file(): void
    {
        $logFile = $this->createLogFile([
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/7.68.0"',
            '192.168.1.1 - - [10/Jul/2026:13:55:37 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"',
            '10.0.0.1 - - [10/Jul/2026:13:55:38 +0000] "POST /login HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
            '10.0.0.1 - - [10/Jul/2026:13:55:39 +0000] "GET /index HTTP/1.1" 200 456 "-" "Mozilla/5.0"',
        ]);

        $parser = new LogParser('nginx-combined');

        $results = iterator_to_array($parser->parse($logFile, fromBeginning: true));

        $this->assertCount(2, $results);
        $this->assertSame('192.168.1.1', $results[0]->ip);
        $this->assertSame('/admin', $results[0]->url);
        $this->assertSame(404, $results[0]->statusCode);
        $this->assertSame('10.0.0.1', $results[1]->ip);
        $this->assertSame('/login', $results[1]->url);
        $this->assertSame(403, $results[1]->statusCode);
    }

    public function test_auto_detects_nginx_format(): void
    {
        $logFile = $this->createLogFile([
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"',
        ]);

        $parser = new LogParser('auto');

        $results = iterator_to_array($parser->parse($logFile, fromBeginning: true));

        $this->assertCount(1, $results);
        $this->assertSame('nginx-combined', $parser->getDetectedFormat());
    }

    public function test_throws_exception_for_missing_file(): void
    {
        $parser = new LogParser('nginx-combined');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Log file not found');

        iterator_to_array($parser->parse('/nonexistent/path.log'));
    }

    public function test_incremental_parsing_saves_position(): void
    {
        $logFile = $this->createLogFile([
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"',
            '10.0.0.1 - - [10/Jul/2026:13:55:37 +0000] "POST /login HTTP/1.1" 403 456 "-" "Mozilla/5.0"',
        ]);

        $parser = new LogParser('nginx-combined');

        $firstRun = iterator_to_array($parser->parse($logFile, fromBeginning: true));
        $this->assertCount(2, $firstRun);

        $this->assertGreaterThan(0, $parser->getCurrentPosition());
        $posFile = $logFile.'.ip-blocker-pos';
        $this->assertFileExists($posFile);
        $this->assertSame((string) $parser->getCurrentPosition(), file_get_contents($posFile));
    }

    public function test_from_beginning_resets_position(): void
    {
        $logFile = $this->createLogFile([
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"',
        ]);

        $parser = new LogParser('nginx-combined');

        iterator_to_array($parser->parse($logFile, fromBeginning: true));
        $firstPosition = $parser->getCurrentPosition();

        iterator_to_array($parser->parse($logFile, fromBeginning: true));
        $secondPosition = $parser->getCurrentPosition();

        $this->assertGreaterThan(0, $secondPosition);
    }

    public function test_returns_empty_for_file_with_only_healthy_requests(): void
    {
        $logFile = $this->createLogFile([
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 123 "-" "curl/7.68.0"',
            '10.0.0.1 - - [10/Jul/2026:13:55:37 +0000] "GET /about HTTP/1.1" 301 456 "-" "Mozilla/5.0"',
        ]);

        $parser = new LogParser('nginx-combined');

        $results = iterator_to_array($parser->parse($logFile, fromBeginning: true));

        $this->assertCount(0, $results);
    }

    private function createLogFile(array $lines): string
    {
        $path = $this->tempDir.'/access.log';
        file_put_contents($path, implode("\n", $lines)."\n");

        return $path;
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir) ?: [], ['.', '..']);

        foreach ($files as $file) {
            $filePath = $dir.'/'.$file;

            if (is_file($filePath)) {
                unlink($filePath);
            }
        }

        rmdir($dir);
    }
}
