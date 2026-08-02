<?php

namespace Zoolok\IpBlocker\Tests\Services;

use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Services\SuspiciousDetector;

class SuspiciousDetectorTest extends TestCase
{
    public function test_detects_suspicious_status_codes(): void
    {
        $detector = new SuspiciousDetector();

        $this->assertTrue($detector->isSuspicious('/', 'Mozilla/5.0', 404));
        $this->assertTrue($detector->isSuspicious('/', 'Mozilla/5.0', 500));
        $this->assertFalse($detector->isSuspicious('/', 'Mozilla/5.0', 200));
    }

    public function test_detects_suspicious_user_agent_case_insensitive(): void
    {
        $detector = new SuspiciousDetector(
            suspiciousUserAgents: ['*exchangescanner*', '*zgrab*'],
        );

        $this->assertTrue($detector->isSuspicious('/', 'Mozilla/5.0 (compatible; ExchangeScanner/2.1)', 200));
        $this->assertTrue($detector->isSuspicious('/', 'Mozilla/5.0 zgrab/0.x', 200));
        $this->assertFalse($detector->isSuspicious('/', 'Mozilla/5.0 (Windows NT 10.0)', 200));
    }

    public function test_detects_suspicious_path(): void
    {
        $detector = new SuspiciousDetector(
            suspiciousPaths: ['/owa*', '/cgi-bin*'],
        );

        $this->assertTrue($detector->isSuspicious('/owa/', 'Mozilla/5.0', 200));
        $this->assertTrue($detector->isSuspicious('/cgi-bin/magicBox.cgi', 'Mozilla/5.0', 200));
        $this->assertFalse($detector->isSuspicious('/home', 'Mozilla/5.0', 200));
    }

    public function test_status_code_short_circuits_when_healthy(): void
    {
        $detector = new SuspiciousDetector();

        $this->assertFalse($detector->isSuspicious('/owa/', null, 200));
        $this->assertTrue($detector->isSuspicious('/owa/', null, 404));
    }

    public function test_find_matching_user_agent_returns_pattern(): void
    {
        $detector = new SuspiciousDetector(
            suspiciousUserAgents: ['*exchangescanner*', '*zgrab*'],
        );

        $this->assertSame('*exchangescanner*', $detector->findMatchingUserAgent('Mozilla/5.0 (compatible; ExchangeScanner/2.1)'));
        $this->assertNull($detector->findMatchingUserAgent('Mozilla/5.0 (Windows NT 10.0)'));
        $this->assertNull($detector->findMatchingUserAgent(null));
        $this->assertNull($detector->findMatchingUserAgent(''));
    }

    public function test_find_matching_path_returns_pattern(): void
    {
        $detector = new SuspiciousDetector(
            suspiciousPaths: ['/owa*', '/cgi-bin*'],
        );

        $this->assertSame('/owa*', $detector->findMatchingPath('/owa/'));
        $this->assertNull($detector->findMatchingPath('/home'));
    }
}
