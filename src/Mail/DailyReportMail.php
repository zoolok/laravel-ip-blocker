<?php

namespace Zoolok\IpBlocker\Mail;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Zoolok\IpBlocker\Contracts\ReportData;

class DailyReportMail extends Mailable
{
    public function __construct(
        public readonly ReportData $reportData,
    ) {}

    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Отчёт о блокировке подозрительных IP за '.now()->format('Y-m-d'),
        );
    }

    public function content(): Content
    {
        return new Content(
            view: 'ip-blocker::daily-report',
            with: [
                'data' => $this->reportData,
                'generatedAt' => now()->format('Y-m-d H:i:s'),
            ],
        );
    }
}
