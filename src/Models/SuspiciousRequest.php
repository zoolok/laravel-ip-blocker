<?php

namespace Zoolok\IpBlocker\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

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

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status_code' => 'integer',
        ];
    }

    /**
     * Get the block record associated with the same IP.
     *
     * @return BelongsTo<BlockedIp, $this>
     */
    public function blockedIp(): BelongsTo
    {
        return $this->belongsTo(BlockedIp::class, 'ip', 'ip');
    }

    /**
     * Scope: запросы с указанного IP.
     *
     * @param Builder<SuspiciousRequest> $query
     * @param string $ip
     * @return void
     */
    public function scopeForIp(Builder $query, string $ip): void
    {
        $query->where('ip', $ip);
    }

    /**
     * Scope: запросы за указанный период.
     *
     * @param Builder<SuspiciousRequest> $query
     * @param Carbon $from
     * @param Carbon $to
     * @return void
     */
    public function scopeForPeriod(Builder $query, Carbon $from, Carbon $to): void
    {
        $query->whereBetween('created_at', [$from, $to]);
    }

    /**
     * Scope: запросы с указанным статус-кодом.
     *
     * @param Builder<SuspiciousRequest> $query
     * @param int $code
     * @return void
     */
    public function scopeStatusCode(Builder $query, int $code): void
    {
        $query->where('status_code', $code);
    }
}
