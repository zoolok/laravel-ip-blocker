<?php

namespace Zoolok\IpBlocker\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $ip
 * @property string $reason
 * @property string|null $blocked_by
 * @property \Illuminate\Support\Carbon $blocked_at
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property bool $is_active
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @method static Builder|static active()
 * @method static Builder|static forIp(string $ip)
 */
class BlockedIp extends Model
{
    protected $guarded = ['id'];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'blocked_at' => 'datetime',
            'expires_at' => 'datetime',
            'is_active' => 'boolean',
        ];
    }

    /**
     * Get the suspicious requests recorded for the same IP.
     *
     * @return HasMany<SuspiciousRequest, $this>
     */
    public function suspiciousRequests(): HasMany
    {
        return $this->hasMany(SuspiciousRequest::class, 'ip', 'ip');
    }

    /**
     * Scope: только активные блокировки (is_active = true и срок не истёк).
     *
     * @param Builder<BlockedIp> $query
     * @return void
     */
    public function scopeActive(Builder $query): void
    {
        $query->where('is_active', true)
            ->where(function (Builder $q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    /**
     * Scope: блокировки для указанного IP.
     *
     * @param Builder<BlockedIp> $query
     * @param string $ip
     * @return void
     */
    public function scopeForIp(Builder $query, string $ip): void
    {
        $query->where('ip', $ip);
    }
}
