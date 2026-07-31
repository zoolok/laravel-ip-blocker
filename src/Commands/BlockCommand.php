<?php

namespace Zoolok\IpBlocker\Commands;

use Illuminate\Console\Command;
use Zoolok\IpBlocker\Contracts\SuspiciousIpData;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Services\DenyGenerator;
use Zoolok\IpBlocker\Services\IpAnalyzer;

class BlockCommand extends Command
{
    protected $signature = 'ip:block
        {--ip= : Block a specific IP address instead of analyzing logs}
        {--reason= : Reason for blocking (used with --ip)}
        {--duration= : Block duration in minutes (overrides config)}
        {--dry-run : Show which IPs would be blocked without actually blocking}
        {--force : Skip confirmation prompt}
        {--no-nginx : Skip nginx deny config generation}';

    protected $description = 'Analyze suspicious requests and block malicious IPs';

    /**
     * Execute the console command.
     *
     * Blocks a specific IP when --ip is given, otherwise analyzes all
     * suspicious requests and blocks the offending IPs.
     *
     * @param IpAnalyzer $analyzer IP analysis service.
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @return int Command exit code (SUCCESS or FAILURE).
     */
    public function handle(IpAnalyzer $analyzer, DenyGenerator $denyGenerator): int
    {
        $specificIp = $this->option('ip');
        $dryRun = (bool) $this->option('dry-run');
        $force = (bool) $this->option('force');
        $noNginx = (bool) $this->option('no-nginx');
        $customReason = $this->option('reason');
        $customDuration = $this->option('duration');

        if ($specificIp !== null) {
            return $this->blockSpecificIp($analyzer, $specificIp, $customReason, $customDuration, $dryRun, $force);
        }

        return $this->analyzeAndBlock($analyzer, $denyGenerator, $dryRun, $force, $noNginx, $customDuration);
    }

    /**
     * Block a specific IP address.
     *
     * Checks whether the IP is already blocked, analyzes it, displays the
     * results, and creates a block record (unless running in dry-run mode
     * or the user cancels the confirmation prompt).
     *
     * @param IpAnalyzer $analyzer IP analysis service.
     * @param string $ip IP address to block.
     * @param string|null $customReason Optional custom blocking reason.
     * @param string|null $customDuration Optional block duration in minutes.
     * @param bool $dryRun If true, do not create the block record.
     * @param bool $force If true, skip the confirmation prompt.
     * @return int Command exit code.
     */
    private function blockSpecificIp(
        IpAnalyzer $analyzer,
        string $ip,
        ?string $customReason,
        ?string $customDuration,
        bool $dryRun,
        bool $force = false,
    ): int {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->error("Invalid IP address: {$ip}");

            return self::FAILURE;
        }

        $this->components->info("Checking IP: {$ip}");

        $existing = BlockedIp::active()->where('ip', $ip)->first();

        if ($existing !== null) {
            $this->warn("IP {$ip} is already blocked until {$existing->expires_at}");

            return self::SUCCESS;
        }

        $data = $analyzer->analyzeIp($ip);

        if ($data === null) {
            $this->warn("IP {$ip} is already blocked.");

            return self::SUCCESS;
        }

        $reason = $customReason ?? 'Manually blocked by administrator';

        if ($data->isSuspicious && ! $customReason) {
            $reason = implode('; ', $data->reasons);
        }

        $this->displayIpInfo($data);

        if ($dryRun) {
            $this->components->info("Dry run: IP {$ip} would be blocked");
            $this->components->twoColumnDetail('Reason', $reason);

            return self::SUCCESS;
        }

        if (! $this->confirmBlock($ip, $dryRun, $force)) {
            $this->components->info('Block cancelled.');

            return self::SUCCESS;
        }

        $this->createBlock($ip, $reason, 'command', $customDuration);

        return self::SUCCESS;
    }

    /**
     * Analyze all IPs and block suspicious ones.
     *
     * Runs a full analysis, presents the results, prompts for confirmation,
     * blocks the confirmed IPs, and optionally regenerates the web server
     * deny configuration.
     *
     * @param IpAnalyzer $analyzer IP analysis service.
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @param bool $dryRun If true, do not create any block records.
     * @param bool $force If true, skip confirmation prompts.
     * @param bool $noNginx If true, skip web server deny config regeneration.
     * @param string|null $customDuration Optional block duration in minutes.
     * @return int Command exit code.
     */
    private function analyzeAndBlock(
        IpAnalyzer $analyzer,
        DenyGenerator $denyGenerator,
        bool $dryRun,
        bool $force,
        bool $noNginx,
        ?string $customDuration,
    ): int {
        $this->components->info('Analyzing suspicious requests...');

        $results = $analyzer->analyze();

        $suspiciousIps = array_filter($results, fn ($data) => $data->isSuspicious);

        if (count($suspiciousIps) === 0) {
            $this->components->info('No suspicious IPs found.');

            return self::SUCCESS;
        }

        $this->components->info("Found ".count($suspiciousIps)." suspicious IP(s).");
        $this->newLine();

        $blockedIps = [];

        foreach ($suspiciousIps as $data) {
            $this->displayIpInfo($data);

            if ($dryRun) {
                $this->components->info("  → Would be blocked");
            } else {
                if (! $this->confirmBlock($data->ip, $dryRun, $force)) {
                    $this->components->info("  → Skipped");
                    continue;
                }

                $reason = implode('; ', $data->reasons);
                $this->createBlock($data->ip, $reason, 'auto', $customDuration);
                $blockedIps[] = $data->ip;
            }

            $this->newLine();
        }

        if (! $dryRun && count($blockedIps) > 0 && ! $noNginx) {
            $this->components->info('Updating web server deny configuration...');
            $denyGenerator->generate($blockedIps);
        }

        $this->table(
            ['IP', 'Reason', 'Status'],
            array_map(fn ($data) => [
                $data->ip,
                implode('; ', $data->reasons),
                $dryRun ? 'Would block' : 'Blocked',
            ], $suspiciousIps),
        );

        return self::SUCCESS;
    }

    /**
     * Display IP analysis information.
     *
     * @param SuspiciousIpData $data Statistics of the IP being analyzed.
     * @return void
     */
    private function displayIpInfo(SuspiciousIpData $data): void
    {
        $this->components->twoColumnDetail('IP', $data->ip);
        $this->components->twoColumnDetail('Total requests', (string) $data->totalRequests);
        $this->components->twoColumnDetail('404 responses', (string) $data->notFoundCount);
        $this->components->twoColumnDetail('Unique URLs', (string) $data->uniqueUrls);
        $this->components->twoColumnDetail('Requests/min', (string) $data->requestsPerMinute);

        if (count($data->reasons) > 0) {
            foreach ($data->reasons as $reason) {
                $this->components->twoColumnDetail('Reason', $reason);
            }
        }
    }

    /**
     * Confirm blocking an IP address.
     *
     * Returns true without prompting when running in dry-run mode, with
     * --force, or when the input is not interactive.
     *
     * @param string $ip IP address to confirm blocking.
     * @param bool $dryRun Whether dry-run mode is active.
     * @param bool $force Whether the confirmation should be skipped.
     * @return bool True when the block is confirmed.
     */
    private function confirmBlock(string $ip, bool $dryRun, bool $force): bool
    {
        if ($dryRun || $force || ! $this->input->isInteractive()) {
            return true;
        }

        return $this->components->confirm("Block IP {$ip}?");
    }

    /**
     * Create a blocked IP record.
     *
     * @param string $ip IP address to block.
     * @param string $reason Blocking reason.
     * @param string $blockedBy Source of the block ('command' or 'auto').
     * @param string|null $customDuration Optional block duration in minutes.
     * @return void
     */
    private function createBlock(string $ip, string $reason, string $blockedBy, ?string $customDuration): void
    {
        $duration = $customDuration !== null
            ? (int) $customDuration
            : config('ip-blocker.block_duration_minutes', 60);

        $expiresAt = $duration > 0 ? now()->addMinutes($duration) : null;

        BlockedIp::query()->create([
            'ip' => $ip,
            'reason' => $reason,
            'blocked_by' => $blockedBy,
            'blocked_at' => now(),
            'expires_at' => $expiresAt,
            'is_active' => true,
        ]);

        $durationLabel = $duration > 0 ? "{$duration} min" : 'permanent';

        $this->components->info("IP {$ip} blocked ({$durationLabel}). Reason: {$reason}");
    }
}
