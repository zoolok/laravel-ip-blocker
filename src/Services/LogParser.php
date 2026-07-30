<?php

namespace Zoolok\IpBlocker\Services;

use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Contracts\LogParserInterface;
use Zoolok\IpBlocker\Contracts\LogParserStrategy;
use Zoolok\IpBlocker\Contracts\ParsedRequest;
use Zoolok\IpBlocker\Parsers\ApacheCombinedParser;
use Zoolok\IpBlocker\Parsers\ApacheCommonParser;
use Zoolok\IpBlocker\Parsers\NginxCombinedParser;

class LogParser implements LogParserInterface
{
    private const array FORMAT_MAP = [
        'nginx-combined' => NginxCombinedParser::class,
        'apache-common' => ApacheCommonParser::class,
        'apache-combined' => ApacheCombinedParser::class,
    ];

    private const string POSITION_FILE_SUFFIX = '.ip-blocker-pos';

    private LogParserStrategy $strategy;

    private string $detectedFormat = 'auto';

    private int $currentPosition = 0;

    public function __construct(
        private readonly string $logFormat = 'auto',
    ) {
        $this->strategy = $this->resolveStrategy($logFormat);
    }

    public function parse(string $filePath, bool $fromBeginning = false): \Generator
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            Log::error('[LogParser.parse] Log file not found or not readable', [
                'path' => $filePath,
            ]);

            throw new \RuntimeException("Log file not found or not readable: {$filePath}");
        }

        $handle = fopen($filePath, 'r');
        if ($handle === false) {
            Log::error('[LogParser.parse] Cannot open log file', [
                'path' => $filePath,
            ]);

            throw new \RuntimeException("Cannot open log file: {$filePath}");
        }

        $startPosition = $fromBeginning ? 0 : $this->loadPosition($filePath);
        $this->currentPosition = $startPosition;

        if ($startPosition > 0) {
            fseek($handle, $startPosition);
        }

        if ($this->detectedFormat === 'auto') {
            $this->autoDetectFormat($handle);
            fseek($handle, $startPosition);
        }

        Log::info('[LogParser.parse] Starting log parsing', [
            'path' => $filePath,
            'format' => $this->detectedFormat,
            'start_position' => $startPosition,
        ]);

        $lineNumber = 0;
        $suspiciousCount = 0;

        while (($line = fgets($handle)) !== false) {
            $lineNumber++;
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            try {
                $parsed = $this->strategy->parseLine($line);

                if ($parsed !== null) {
                    $suspiciousCount++;
                    Log::debug('[LogParser.parse] Found suspicious request', [
                        'ip' => $parsed->ip,
                        'url' => $parsed->url,
                        'method' => $parsed->method,
                        'status' => $parsed->statusCode,
                    ]);

                    yield $parsed;
                }
            } catch (\Throwable $e) {
                Log::warning('[LogParser.parse] Failed to parse line', [
                    'line' => $lineNumber,
                    'error' => $e->getMessage(),
                ]);
            }
        }

        $this->currentPosition = ftell($handle);
        fclose($handle);

        $this->savePosition($filePath, $this->currentPosition);

        Log::info('[LogParser.parse] Parsing complete', [
            'path' => $filePath,
            'format' => $this->detectedFormat,
            'lines_processed' => $lineNumber,
            'suspicious_found' => $suspiciousCount,
            'end_position' => $this->currentPosition,
        ]);
    }

    public function getDetectedFormat(): string
    {
        return $this->detectedFormat;
    }

    public function getCurrentPosition(): int
    {
        return $this->currentPosition;
    }

    private function resolveStrategy(string $format): LogParserStrategy
    {
        if ($format === 'auto') {
            $this->detectedFormat = 'auto';

            return new NginxCombinedParser();
        }

        $class = self::FORMAT_MAP[$format] ?? null;

        if ($class === null) {
            Log::warning('[LogParser] Unknown log format, falling back to nginx-combined', [
                'requested_format' => $format,
            ]);
            $this->detectedFormat = 'nginx-combined';

            return new NginxCombinedParser();
        }

        $this->detectedFormat = $format;

        return new $class();
    }

    private function autoDetectFormat($handle): void
    {
        $firstLine = fgets($handle);

        if ($firstLine === false) {
            Log::warning('[LogParser.autoDetect] Empty log file, defaulting to nginx-combined');
            $this->detectedFormat = 'nginx-combined';
            $this->strategy = new NginxCombinedParser();

            return;
        }

        $firstLine = trim($firstLine);

        $parsers = [
            'nginx-combined' => new NginxCombinedParser(),
            'apache-combined' => new ApacheCombinedParser(),
            'apache-common' => new ApacheCommonParser(),
        ];

        foreach ($parsers as $name => $parser) {
            $result = $parser->parseLine($firstLine);

            if ($result !== null) {
                $this->detectedFormat = $name;
                $this->strategy = $parser;

                Log::debug('[LogParser.autoDetect] Detected log format', [
                    'format' => $name,
                    'sample_ip' => $result->ip,
                    'sample_url' => $result->url,
                ]);

                return;
            }
        }

        Log::warning('[LogParser.autoDetect] Could not detect format, defaulting to nginx-combined', [
            'first_line' => substr($firstLine, 0, 200),
        ]);
        $this->detectedFormat = 'nginx-combined';
        $this->strategy = new NginxCombinedParser();
    }

    private function loadPosition(string $filePath): int
    {
        $posFile = $filePath.self::POSITION_FILE_SUFFIX;

        if (file_exists($posFile)) {
            $position = (int) file_get_contents($posFile);

            Log::debug('[LogParser] Loaded position', [
                'path' => $posFile,
                'position' => $position,
            ]);

            return $position;
        }

        return 0;
    }

    private function savePosition(string $filePath, int $position): void
    {
        $posFile = $filePath.self::POSITION_FILE_SUFFIX;

        $written = file_put_contents($posFile, (string) $position);

        if ($written === false) {
            Log::warning('[LogParser] Could not save position file', [
                'path' => $posFile,
            ]);
        } else {
            Log::debug('[LogParser] Saved position', [
                'path' => $posFile,
                'position' => $position,
            ]);
        }
    }
}
