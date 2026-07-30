<?php

namespace Zoolok\IpBlocker\Contracts;

interface LogParserStrategy
{
    /**
     * Parse a single line from an access log.
     *
     * @param string $line A single line from the log file.
     * @return ParsedRequest|null Parsed request data, or null if the line doesn't match the format or is not suspicious.
     */
    public function parseLine(string $line): ?ParsedRequest;
}
