<?php

namespace Zoolok\IpBlocker\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;

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

    protected function casts(): array
    {
        return [
            'blocked_at' => 'datetime',
            'expires_at' => 'datetime',
            'is_active' => 'boolean',
        ];
    }

    public function suspiciousRequests()
    {
        return $this->hasMany(SuspiciousRequest::class, 'ip', 'ip');
    }

    /**
     * Scope: только активные блокировки (is_active = true и срок не истёк).
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
     */
    public function scopeForIp(Builder $query, string $ip): void
    {
        $query->where('ip', $ip);
    }

    protected static function booted(): void
    {
        static::created(function (BlockedIp $blocked) {
            Log::info('[BlockedIp.created] IP blocked', [
                'ip' => $blocked->ip,
                'reason' => $blocked->reason,
                'blocked_by' => $blocked->blocked_by,
                'expires_at' => $blocked->expires_at?->toIso8601String(),
                'duration_minutes' => $blocked->expires_at
                    ? now()->diffInMinutes($blocked->expires_at)
                    : null,
            ]);
        });

        static::updated(function (BlockedIp $blocked) {
            if ($blocked->isDirty('is_active') && $blocked->is_active === false) {
                Log::info('[BlockedIp.updated] IP unblocked', [
                    'ip' => $blocked->ip,
                    'reason' => $blocked->reason,
                ]);
            }
        });
    }
}
