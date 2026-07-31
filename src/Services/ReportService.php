<?php

namespace Zoolok\IpBlocker\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Zoolok\IpBlocker\Contracts\ReportData;
use Zoolok\IpBlocker\Mail\DailyReportMail;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class ReportService
{
    /**
     * @param int $retentionDays Number of days to keep records before cleanup.
     * @param bool $cleanupEnabled Whether old records should be deleted after sending the report.
     */
    public function __construct(
        private readonly int $retentionDays = 30,
        private readonly bool $cleanupEnabled = true,
    ) {}

    /**
     * Generate a daily report and send it via email.
     *
     * Builds the report data, optionally cleans up old records, and sends
     * the report to the configured email address. Errors are logged.
     *
     * @return void
     */
    public function sendDailyReport(): void
    {
        try {
            $reportData = $this->generateReportData();

            if ($this->cleanupEnabled) {
                $this->cleanupOldRecords();
            }

            $email = config('ip-blocker.report.email');

            if ($email === null || $email === '') {
                return;
            }

            Mail::to($email)->send(new DailyReportMail($reportData));
        } catch (\Throwable $e) {
            Log::error('[ReportService.sendDailyReport] Failed to send report', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }
    }

    /**
     * Generate report data for the last 24 hours.
     *
     * Aggregates suspicious request and blocking statistics, including top
     * IPs and targeted URLs, into a single {@see ReportData} object.
     *
     * @return ReportData Aggregated report statistics.
     */
    public function generateReportData(): ReportData
    {
        $since = now()->subDay();

        $totalSuspicious = SuspiciousRequest::where('created_at', '>=', $since)->count();

        $totalBlocked = BlockedIp::where('blocked_at', '>=', $since)->count();

        $activeBlocks = BlockedIp::active()->count();

        $expiredBlocks = BlockedIp::where('is_active', false)
            ->where('updated_at', '>=', $since)
            ->count();

        $topIps = SuspiciousRequest::where('created_at', '>=', $since)
            ->selectRaw('ip, COUNT(*) as count')
            ->groupBy('ip')
            ->orderByDesc('count')
            ->limit(10)
            ->get()
            ->map(function ($item) {
                $blocked = BlockedIp::where('ip', $item->ip)->first();

                return [
                    'ip' => $item->ip,
                    'count' => $item->count,
                    'reason' => $blocked?->reason ?? 'Not blocked',
                ];
            });

        $topUrls = SuspiciousRequest::where('created_at', '>=', $since)
            ->selectRaw('url, COUNT(*) as count')
            ->groupBy('url')
            ->orderByDesc('count')
            ->limit(10)
            ->get()
            ->map(fn ($item) => [
                'url' => $item->url,
                'count' => $item->count,
            ]);

        $blockedByServer = BlockedIp::where('blocked_by', 'auto')
            ->where('blocked_at', '>=', $since)
            ->count();

        $blockedByMiddleware = BlockedIp::where('blocked_by', 'middleware')
            ->where('blocked_at', '>=', $since)
            ->count();

        return new ReportData(
            totalSuspicious: $totalSuspicious,
            totalBlocked: $totalBlocked,
            activeBlocks: $activeBlocks,
            expiredBlocks: $expiredBlocks,
            topIps: $topIps,
            topUrls: $topUrls,
            blockedByMiddleware: $blockedByMiddleware,
            blockedByServer: $blockedByServer,
            periodLabel: now()->subDay()->format('Y-m-d H:i').' — '.now()->format('Y-m-d H:i'),
        );
    }

    /**
     * Delete records older than the retention period.
     *
     * @return void
     */
    private function cleanupOldRecords(): void
    {
        $cutoff = now()->subDays($this->retentionDays);

        SuspiciousRequest::where('created_at', '<', $cutoff)->delete();
        BlockedIp::where('created_at', '<', $cutoff)->delete();
    }
}
