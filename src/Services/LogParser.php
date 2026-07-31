<?php

namespace Zoolok\IpBlocker\Services;

use Generator;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Zoolok\IpBlocker\Contracts\LogParserInterface;
use Zoolok\IpBlocker\Contracts\LogParserStrategy;
use Zoolok\IpBlocker\Contracts\ParsedRequest;
use Zoolok\IpBlocker\Parsers\ApacheCombinedParser;
use Zoolok\IpBlocker\Parsers\ApacheCommonParser;
use Zoolok\IpBlocker\Parsers\NginxCombinedParser;

class LogParser implements LogParserInterface
{
    private const FORMAT_MAP = [
        'nginx-combined' => NginxCombinedParser::class,
        'apache-common' => ApacheCommonParser::class,
        'apache-combined' => ApacheCombinedParser::class,
    ];

    private const POSITION_FILE_SUFFIX = '.ip-blocker-pos';

    private LogParserStrategy $strategy;

    private string $detectedFormat = 'auto';

    private int $currentPosition = 0;

    /**
     * @param string $logFormat Log format name ('auto', 'nginx-combined', 'apache-common', 'apache-combined').
     * @param LoggerInterface $logger PSR-3 logger; used only for error reporting.
     */
    public function __construct(
        private readonly string $logFormat = 'auto',
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        $this->strategy = $this->resolveStrategy($logFormat);
    }

    /**
     * Parse a log file and yield suspicious requests.
     *
     * Incrementally reads the file starting from the saved byte position
     * (or from the beginning when $fromBeginning is true) and yields one
     * {@see ParsedRequest} per suspicious line. The final byte position is
     * persisted to a sidecar file for subsequent incremental runs.
     *
     * @param string $filePath Absolute path to the log file.
     * @param bool $fromBeginning If true, ignore the saved position and parse from the start.
     * @return Generator<int, ParsedRequest>
     *
     * @throws \RuntimeException When the log file does not exist, is not readable, or cannot be opened.
     */
    public function parse(string $filePath, bool $fromBeginning = false): Generator
    {
        if (! file_exists($filePath) || ! is_readable($filePath)) {
            $this->logger->error('[LogParser.parse] Log file not found or not readable', [
                'path' => $filePath,
            ]);

            throw new \RuntimeException("Log file not found or not readable: {$filePath}");
        }

        $handle = @fopen($filePath, 'r');
        if ($handle === false) {
            $this->logger->error('[LogParser.parse] Cannot open log file', [
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

        while (($line = fgets($handle)) !== false) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            try {
                $parsed = $this->strategy->parseLine($line);

                if ($parsed !== null) {
                    yield $parsed;
                }
            } catch (\Throwable) {
                continue;
            }
        }

        $this->currentPosition = ftell($handle);
        fclose($handle);

        $this->savePosition($filePath, $this->currentPosition);
    }

    /**
     * Get the name of the detected or configured log format.
     *
     * @return string One of 'auto', 'nginx-combined', 'apache-common', 'apache-combined'.
     */
    public function getDetectedFormat(): string
    {
        return $this->detectedFormat;
    }

    /**
     * Get the current byte position in the parsed file.
     *
     * @return int Absolute byte offset in the log file.
     */
    public function getCurrentPosition(): int
    {
        return $this->currentPosition;
    }

    /**
     * Resolve the parser strategy for a given format name.
     *
     * Falls back to the nginx-combined parser when the format is unknown.
     *
     * @param string $format Log format name or 'auto'.
     * @return LogParserStrategy Concrete parser strategy instance.
     */
    private function resolveStrategy(string $format): LogParserStrategy
    {
        if ($format === 'auto') {
            $this->detectedFormat = 'auto';

            return new NginxCombinedParser();
        }

        $class = self::FORMAT_MAP[$format] ?? null;

        if ($class === null) {
            $this->detectedFormat = 'nginx-combined';

            return new NginxCombinedParser();
        }

        $this->detectedFormat = $format;

        return new $class();
    }

    /**
     * Detect the log format by inspecting the first non-empty line.
     *
     * Tries every known parser against the first line and keeps the first
     * one that produces a match. Defaults to nginx-combined otherwise.
     *
     * @param resource $handle Open file handle positioned at the start of the file.
     * @return void
     */
    private function autoDetectFormat($handle): void
    {
        $firstLine = fgets($handle);

        if ($firstLine === false) {
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

                return;
            }
        }

        $this->detectedFormat = 'nginx-combined';
        $this->strategy = new NginxCombinedParser();
    }

    /**
     * Load the saved byte position for a log file.
     *
     * Reads the sidecar position file and returns its value, or 0 when no
     * position file exists.
     *
     * @param string $filePath Absolute path to the log file.
     * @return int Last parsed byte position, 0 when none was saved.
     */
    private function loadPosition(string $filePath): int
    {
        $posFile = $filePath.self::POSITION_FILE_SUFFIX;

        if (file_exists($posFile)) {
            return (int) file_get_contents($posFile);
        }

        return 0;
    }

    /**
     * Persist the current byte position for a log file.
     *
     * Writes the position into a sidecar file so that the next run can
     * continue from where the previous one stopped.
     *
     * @param string $filePath Absolute path to the log file.
     * @param int $position Byte position to persist.
     * @return void
     */
    private function savePosition(string $filePath, int $position): void
    {
        $posFile = $filePath.self::POSITION_FILE_SUFFIX;

        @file_put_contents($posFile, (string) $position);
    }
}
