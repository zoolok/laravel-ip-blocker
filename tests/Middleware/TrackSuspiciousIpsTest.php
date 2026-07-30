<?php

namespace Zoolok\IpBlocker\Tests\Middleware;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Http\Middleware\TrackSuspiciousIps;

class TrackSuspiciousIpsTest extends TestCase
{
    private TrackSuspiciousIps $middleware;

    protected function setUp(): void
    {
        $this->middleware = new TrackSuspiciousIps();
    }

    public function test_passes_through_for_healthy_response(): void
    {
        $request = Request::create('/health', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $response = $this->middleware->handle($request, function ($req) {
            return response('OK', 200);
        });

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('OK', $response->getContent());
    }

    public function test_passes_through_for_excluded_path(): void
    {
        config(['ip-blocker.exclude_paths' => ['/healthcheck']]);

        $request = Request::create('/healthcheck', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $response = $this->middleware->handle($request, function ($req) {
            return response('OK', 200);
        });

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function test_returns_json_response_for_blocked_ip(): void
    {
        $request = Request::create('/admin', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $response = $this->middleware->handle($request, function ($req) {
            return response('Not Found', 404);
        });

        if ($response instanceof JsonResponse) {
            $this->assertEquals(403, $response->getStatusCode());
            $this->assertJson($response->getContent() ?: '{}');

            $data = json_decode($response->getContent() ?: '{}', true);

            $this->assertArrayHasKey('error', $data);
            $this->assertArrayHasKey('code', $data);
            $this->assertEquals('IP_BLOCKED', $data['code']);
        }
    }

    public function test_sets_x_ip_blocked_header(): void
    {
        $request = Request::create('/admin', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $response = $this->middleware->handle($request, function ($req) {
            return response('Not Found', 404);
        });

        if ($response instanceof JsonResponse) {
            $this->assertEquals('true', $response->headers->get('X-IP-Blocked'));
        }
    }

    public function test_does_not_block_excluded_paths_even_with_404(): void
    {
        config(['ip-blocker.exclude_paths' => ['/robots.txt']]);

        $request = Request::create('/robots.txt', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);

        $response = $this->middleware->handle($request, function ($req) {
            return response('Not Found', 404);
        });

        $this->assertEquals(404, $response->getStatusCode());
    }
}
