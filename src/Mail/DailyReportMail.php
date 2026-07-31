<?php

namespace Zoolok\IpBlocker\Mail;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Zoolok\IpBlocker\Contracts\ReportData;

class DailyReportMail extends Mailable
{
    /**
     * @param ReportData $reportData Aggregated report statistics.
     */
    public function __construct(
        public readonly ReportData $reportData,
    ) {}

    /**
     * Get the message envelope.
     *
     * @return Envelope Envelope with the report subject.
     */
    public function envelope(): Envelope
    {
        return new Envelope(
            subject: 'Отчёт о блокировке подозрительных IP за '.now()->format('Y-m-d'),
        );
    }

    /**
     * Get the message content definition.
     *
     * @return Content Content definition referencing the report view.
     */
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
