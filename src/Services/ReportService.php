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
    public function __construct(
        private readonly int $retentionDays = 30,
        private readonly bool $cleanupEnabled = true,
    ) {}

    /**
     * Generate a daily report and send it via email.
     */
    public function sendDailyReport(): void
    {
        Log::info('[ReportService.sendDailyReport] Generating daily report');

        try {
            $reportData = $this->generateReportData();

            $this->logReportData($reportData);

            if ($this->cleanupEnabled) {
                $this->cleanupOldRecords();
            }

            $email = config('ip-blocker.report.email');

            if ($email === null || $email === '') {
                Log::warning('[ReportService.sendDailyReport] Report email not configured');

                return;
            }

            Mail::to($email)->send(new DailyReportMail($reportData));

            Log::info('[ReportService.sendDailyReport] Report sent', [
                'email' => $email,
            ]);
        } catch (\Throwable $e) {
            Log::error('[ReportService.sendDailyReport] Failed to send report', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
        }
    }

    /**
     * Generate report data for the last 24 hours.
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
     * Delete records older than retention days.
     */
    private function cleanupOldRecords(): void
    {
        $cutoff = now()->subDays($this->retentionDays);

        $deletedSuspicious = SuspiciousRequest::where('created_at', '<', $cutoff)->delete();
        $deletedBlocked = BlockedIp::where('created_at', '<', $cutoff)->delete();

        Log::info('[ReportService.cleanupOldRecords] Cleanup complete', [
            'cutoff' => $cutoff->toIso8601String(),
            'deleted_suspicious' => $deletedSuspicious,
            'deleted_blocked' => $deletedBlocked,
        ]);
    }

    /**
     * Log report data for debugging.
     */
    private function logReportData(ReportData $data): void
    {
        Log::info('[ReportService] Report data generated', [
            'total_suspicious' => $data->totalSuspicious,
            'total_blocked' => $data->totalBlocked,
            'active_blocks' => $data->activeBlocks,
            'expired_blocks' => $data->expiredBlocks,
            'blocked_by_server' => $data->blockedByServer,
            'blocked_by_middleware' => $data->blockedByMiddleware,
            'top_ips_count' => $data->topIps->count(),
            'top_urls_count' => $data->topUrls->count(),
            'period' => $data->periodLabel,
        ]);
    }
}
