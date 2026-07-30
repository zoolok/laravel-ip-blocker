<?php

namespace Zoolok\IpBlocker\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property string $ip
 * @property string $url
 * @property string $method
 * @property string|null $user_agent
 * @property string|null $referer
 * @property int $status_code
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @method static Builder|static forIp(string $ip)
 * @method static Builder|static forPeriod(\Illuminate\Support\Carbon $from, \Illuminate\Support\Carbon $to)
 * @method static Builder|static statusCode(int $code)
 */
class SuspiciousRequest extends Model
{
    protected $guarded = ['id'];

    protected function casts(): array
    {
        return [
            'status_code' => 'integer',
        ];
    }

    public function blockedIp()
    {
        return $this->belongsTo(BlockedIp::class, 'ip', 'ip');
    }

    /**
     * Scope: запросы с указанного IP.
     */
    public function scopeForIp(Builder $query, string $ip): void
    {
        $query->where('ip', $ip);
    }

    /**
     * Scope: запросы за указанный период.
     */
    public function scopeForPeriod(Builder $query, \Illuminate\Support\Carbon $from, \Illuminate\Support\Carbon $to): void
    {
        $query->whereBetween('created_at', [$from, $to]);
    }

    /**
     * Scope: запросы с указанным статус-кодом.
     */
    public function scopeStatusCode(Builder $query, int $code): void
    {
        $query->where('status_code', $code);
    }
}
