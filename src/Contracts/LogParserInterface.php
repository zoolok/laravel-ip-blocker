<?php

namespace Zoolok\IpBlocker\Contracts;

use Generator;

interface LogParserInterface
{
    /**
     * Parse a log file and return suspicious requests.
     *
     * @param string $filePath Absolute path to the log file.
     * @param bool $fromBeginning If true, ignore saved position and parse from start.
     * @return Generator<int, ParsedRequest>
     */
    public function parse(string $filePath, bool $fromBeginning = false): Generator;

    /**
     * Get the name of the detected/configured format.
     */
    public function getDetectedFormat(): string;

    /**
     * Get the current byte position in the parsed file.
     */
    public function getCurrentPosition(): int;
}
