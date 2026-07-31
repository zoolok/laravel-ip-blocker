<?php

namespace Zoolok\IpBlocker\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Models\SuspiciousRequest;
use Zoolok\IpBlocker\Services\LogParser;

class ParseLogCommand extends Command
{
    protected $signature = 'ip:parse-log
        {--path= : Path to the access log file (overrides config)}
        {--format=auto : Log format: auto, nginx-combined, apache-common, apache-combined}
        {--dry-run : Parse but do not save to database}
        {--from-beginning : Ignore saved position and parse from the start of the file}';

    protected $description = 'Parse web server access log and detect suspicious requests';

    private int $foundCount = 0;

    private int $savedCount = 0;

    private int $skippedCount = 0;

    /**
     * Execute the console command.
     *
     * Parses the access log, shows a progress bar, saves detected suspicious
     * requests to the database in batches of 100 (unless --dry-run), and
     * prints a summary.
     *
     * @param LogParser $logParser Log parser service.
     * @return int Command exit code (SUCCESS or FAILURE).
     */
    public function handle(LogParser $logParser): int
    {
        $filePath = $this->option('path') ?? config('ip-blocker.log_path');
        $format = $this->option('format') ?? 'auto';
        $dryRun = (bool) $this->option('dry-run');
        $fromBeginning = (bool) $this->option('from-beginning');

        if ($filePath === null) {
            $this->error('No log file path specified. Set IP_BLOCKER_LOG_PATH env or use --path option.');

            return self::FAILURE;
        }

        if (! file_exists($filePath)) {
            $this->error("Log file not found: {$filePath}");

            return self::FAILURE;
        }

        $this->components->info("Parsing log file: {$filePath}");

        $parser = new LogParser(logFormat: $format);

        $bar = $this->output->createProgressBar();
        $bar->setFormat(' %current% suspicious requests found [%bar%] %elapsed:6s%');
        $bar->start();

        try {
            $chunk = [];

            foreach ($parser->parse($filePath, $fromBeginning) as $parsed) {
                $this->foundCount++;
                $bar->setProgress($this->foundCount);

                if ($dryRun) {
                    continue;
                }

                $chunk[] = [
                    'ip' => $parsed->ip,
                    'url' => $parsed->url,
                    'method' => $parsed->method,
                    'user_agent' => $parsed->userAgent,
                    'referer' => $parsed->referer,
                    'status_code' => $parsed->statusCode,
                    'created_at' => now(),
                    'updated_at' => now(),
                ];

                if (count($chunk) >= 100) {
                    $this->saveChunk($chunk);
                    $chunk = [];
                }
            }

            if (! $dryRun && count($chunk) > 0) {
                $this->saveChunk($chunk);
            }

            $bar->finish();
            $this->newLine(2);

            $detectedFormat = $parser->getDetectedFormat();
            $this->components->twoColumnDetail('Detected format', $detectedFormat);
            $this->components->twoColumnDetail('Suspicious requests found', (string) $this->foundCount);

            if (! $dryRun) {
                $this->components->twoColumnDetail('Saved to database', (string) $this->savedCount);
                if ($this->skippedCount > 0) {
                    $this->components->twoColumnDetail('Skipped (duplicates)', (string) $this->skippedCount);
                }
            } else {
                $this->components->twoColumnDetail('Dry run', 'No records saved');
            }
        } catch (\Throwable $e) {
            $bar->finish();
            $this->newLine();
            $this->error("Error parsing log: {$e->getMessage()}");

            Log::error('[ParseLogCommand.handle] Error', [
                'path' => $filePath,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Save a chunk of parsed records to the database.
     *
     * Inserts each record individually and counts skipped duplicates.
     *
     * @param array<int, array<string, mixed>> $chunk Batch of records to insert.
     * @return void
     */
    private function saveChunk(array $chunk): void
    {
        $inserted = 0;

        foreach ($chunk as $record) {
            try {
                SuspiciousRequest::query()->create($record);
                $inserted++;
            } catch (\Throwable) {
                $this->skippedCount++;
            }
        }

        $this->savedCount += $inserted;
    }
}
