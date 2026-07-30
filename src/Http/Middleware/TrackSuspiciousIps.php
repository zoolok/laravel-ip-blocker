<?php

namespace Zoolok\IpBlocker\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;

class TrackSuspiciousIps
{
    public function handle(Request $request, Closure $next): mixed
    {
        $response = $next($request);

        $ip = $request->ip();
        $path = $request->path();

        if ($ip === null || $this->isExcludedPath($path)) {
            return $response;
        }

        $statusCode = $response->getStatusCode();

        if ($statusCode >= 400) {
            $this->logSuspiciousRequest($request, $statusCode);
        }

        if ($this->isIpBlocked($ip)) {
            Log::info('[TrackSuspiciousIps] BLOCKED', [
                'ip' => $ip,
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'status' => $statusCode,
            ]);

            return new JsonResponse(
                data: [
                    'error' => 'Your IP has been blocked',
                    'code' => 'IP_BLOCKED',
                ],
                status: 403,
                headers: ['X-IP-Blocked' => 'true'],
            );
        }

        return $response;
    }

    private function isExcludedPath(string $path): bool
    {
        $excludedPaths = config('ip-blocker.exclude_paths', []);

        foreach ($excludedPaths as $excluded) {
            if (Str::is($excluded, $path)) {
                return true;
            }
        }

        return false;
    }

    private function logSuspiciousRequest(Request $request, int $statusCode): void
    {
        try {
            SuspiciousRequest::query()->create([
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'user_agent' => $request->userAgent(),
                'referer' => $request->header('referer'),
                'status_code' => $statusCode,
            ]);

            Log::debug('[TrackSuspiciousIps] SAVED', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'method' => $request->method(),
                'status' => $statusCode,
            ]);
        } catch (\Throwable $e) {
            Log::error('[TrackSuspiciousIps] Failed to log suspicious request', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'error' => $e->getMessage(),
            ]);
        }
    }

    private function isIpBlocked(string $ip): bool
    {
        return BlockedIp::active()->where('ip', $ip)->exists();
    }
}
