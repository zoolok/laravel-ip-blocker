<?php

namespace Zoolok\IpBlocker\Commands;

use Illuminate\Console\Command;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;
use Zoolok\IpBlocker\Services\DenyGenerator;

class UnblockCommand extends Command
{
    protected $signature = 'ip:unblock
        {--ip= : IP address to unblock}
        {--all : Unblock all IPs and clear all suspicious requests}
        {--force : Skip confirmation prompt}
        {--no-nginx : Skip web server deny config regeneration}';

    protected $description = 'Unblock IP address(es), clear their suspicious requests and update the web server deny config';

    /**
     * Execute the console command.
     *
     * Removes the given IP (or all IPs with --all) from blocked_ips, deletes
     * their suspicious requests, and regenerates the web server deny config
     * so the unblocked IPs are no longer rejected by nginx/Apache.
     *
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @return int Command exit code (SUCCESS or FAILURE).
     */
    public function handle(DenyGenerator $denyGenerator): int
    {
        $specificIp = $this->option('ip');
        $all = (bool) $this->option('all');
        $force = (bool) $this->option('force');
        $noNginx = (bool) $this->option('no-nginx');

        if ($all) {
            return $this->unblockAll($denyGenerator, $force, $noNginx);
        }

        if ($specificIp === null || $specificIp === '') {
            $this->error('Specify --ip=ADDRESS or use --all to unblock every IP.');

            return self::FAILURE;
        }

        return $this->unblockIp($specificIp, $denyGenerator, $force, $noNginx);
    }

    /**
     * Unblock a single IP address.
     *
     * @param string $ip IP address to unblock.
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @param bool $force If true, skip the confirmation prompt.
     * @param bool $noNginx If true, skip web server deny config regeneration.
     * @return int Command exit code.
     */
    private function unblockIp(string $ip, DenyGenerator $denyGenerator, bool $force, bool $noNginx): int
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $this->error("Invalid IP address: {$ip}");

            return self::FAILURE;
        }

        $blockedCount = BlockedIp::where('ip', $ip)->count();
        $suspiciousCount = SuspiciousRequest::where('ip', $ip)->count();

        if ($blockedCount === 0 && $suspiciousCount === 0) {
            $this->components->info("Nothing to unblock: IP {$ip} has no active block or suspicious requests.");

            return self::SUCCESS;
        }

        $this->components->twoColumnDetail('IP', $ip);
        $this->components->twoColumnDetail('Block records', (string) $blockedCount);
        $this->components->twoColumnDetail('Suspicious requests', (string) $suspiciousCount);

        if (! $this->confirmUnblock($force)) {
            $this->components->info('Unblock cancelled.');

            return self::SUCCESS;
        }

        $deletedBlocks = BlockedIp::where('ip', $ip)->delete();
        $deletedSuspicious = SuspiciousRequest::where('ip', $ip)->delete();

        $this->components->info("Unblocked {$ip}: {$deletedBlocks} block record(s), {$deletedSuspicious} suspicious request(s) removed.");

        return $this->regenerateDenyConfig($denyGenerator, $noNginx);
    }

    /**
     * Unblock all IPs and clear all suspicious requests.
     *
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @param bool $force If true, skip the confirmation prompt.
     * @param bool $noNginx If true, skip web server deny config regeneration.
     * @return int Command exit code.
     */
    private function unblockAll(DenyGenerator $denyGenerator, bool $force, bool $noNginx): int
    {
        $blockedCount = BlockedIp::count();
        $suspiciousCount = SuspiciousRequest::count();

        if ($blockedCount === 0 && $suspiciousCount === 0) {
            $this->components->info('Nothing to unblock: no blocked IPs or suspicious requests.');

            return self::SUCCESS;
        }

        $this->components->twoColumnDetail('Block records', (string) $blockedCount);
        $this->components->twoColumnDetail('Suspicious requests', (string) $suspiciousCount);

        if (! $this->confirmUnblock($force)) {
            $this->components->info('Unblock cancelled.');

            return self::SUCCESS;
        }

        BlockedIp::query()->delete();
        SuspiciousRequest::query()->delete();

        $this->components->info("Unblocked all IPs: {$blockedCount} block record(s), {$suspiciousCount} suspicious request(s) removed.");

        return $this->regenerateDenyConfig($denyGenerator, $noNginx);
    }

    /**
     * Regenerate the web server deny config from remaining blocked IPs.
     *
     * @param DenyGenerator $denyGenerator Web server deny config generator.
     * @param bool $noNginx If true, skip regeneration.
     * @return int Command exit code.
     */
    private function regenerateDenyConfig(DenyGenerator $denyGenerator, bool $noNginx): int
    {
        if ($noNginx) {
            $this->components->warn('Skipped web server deny config regeneration (--no-nginx).');

            return self::SUCCESS;
        }

        $this->components->info('Regenerating web server deny configuration...');

        $remaining = BlockedIp::active()->pluck('ip')->all();

        if ($denyGenerator->generate($remaining)) {
            $this->components->info('Web server deny configuration updated.');
        } else {
            $this->components->warn('Failed to regenerate web server deny configuration. Update it manually.');
        }

        return self::SUCCESS;
    }

    /**
     * Confirm the unblock action.
     *
     * Returns true without prompting when --force is given or the input is
     * not interactive.
     *
     * @param bool $force If true, skip the confirmation prompt.
     * @return bool True when the unblock is confirmed.
     */
    private function confirmUnblock(bool $force): bool
    {
        if ($force || ! $this->input->isInteractive()) {
            return true;
        }

        return $this->components->confirm('Proceed with unblock?');
    }
}
