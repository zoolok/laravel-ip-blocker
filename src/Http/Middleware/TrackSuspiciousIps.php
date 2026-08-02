<?php

namespace Zoolok\IpBlocker\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\Models\SuspiciousRequest;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

class TrackSuspiciousIps
{
    /**
     * @param SuspiciousDetector $detector Detector for status/UA/path-based suspicion.
     */
    public function __construct(
        private readonly SuspiciousDetector $detector = new SuspiciousDetector(),
    ) {}

    /**
     * Handle an incoming request.
     *
     * Returns a 403 JSON response for already-blocked IPs before the request
     * is processed. Otherwise passes the request through and records
     * suspicious responses (status >= 400, suspicious UA, or suspicious path).
     *
     * @param Request $request Incoming HTTP request.
     * @param Closure(Request): mixed $next Next middleware in the pipeline.
     * @return mixed The response returned by the next middleware or a 403 JSON response.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $ip = $request->ip();
        $path = $request->path();

        if ($ip === null || $this->detector->isExcluded('/'.$path)) {
            return $next($request);
        }

        if ($this->isIpBlocked($ip)) {
            return new JsonResponse(
                data: [
                    'error' => 'Your IP has been blocked',
                    'code' => 'IP_BLOCKED',
                ],
                status: 403,
                headers: ['X-IP-Blocked' => 'true'],
            );
        }

        $response = $next($request);

        $statusCode = $response->getStatusCode();

        if ($this->detector->isSuspicious('/'.$path, $request->userAgent(), $statusCode)) {
            $this->logSuspiciousRequest($request, $statusCode);
        }

        return $response;
    }

    /**
     * Record a suspicious request into the database.
     *
     * @param Request $request Incoming HTTP request.
     * @param int $statusCode HTTP response status code.
     * @return void
     */
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
        } catch (\Throwable $e) {
            Log::error('[TrackSuspiciousIps] Failed to log suspicious request', [
                'ip' => $request->ip(),
                'url' => $request->fullUrl(),
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Check whether the IP address is actively blocked.
     *
     * @param string $ip IP address to check.
     * @return bool True when the IP has an active block record.
     */
    private function isIpBlocked(string $ip): bool
    {
        return BlockedIp::active()->where('ip', $ip)->exists();
    }
}
