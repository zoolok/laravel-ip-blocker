<?php

namespace Zoolok\IpBlocker\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
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
     */
    private function blockSpecificIp(
        IpAnalyzer $analyzer,
        string $ip,
        ?string $customReason,
        ?string $customDuration,
        bool $dryRun,
        bool $force = false,
    ): int {
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

            Log::info('[BlockCommand] No suspicious IPs found during analysis');

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

        Log::info('[BlockCommand] Analysis and blocking complete', [
            'suspicious_found' => count($suspiciousIps),
            'blocked' => count($blockedIps),
            'dry_run' => $dryRun,
        ]);

        return self::SUCCESS;
    }

    /**
     * Display IP analysis information.
     */
    private function displayIpInfo(\Zoolok\IpBlocker\Contracts\SuspiciousIpData $data): void
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
     * Confirm blocking an IP.
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
