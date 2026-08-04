<?php

namespace Zoolok\IpBlocker\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Facades\Log;
use Zoolok\IpBlocker\Services\DenyGenerator;

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
 * @method static Builder|static expired()
 * @method static Builder|static forIp(string $ip)
 */
class BlockedIp extends Model
{
    protected $guarded = ['id'];

    /**
     * Register model event listeners to keep the web server deny config in
     * sync with the blocked_ips table.
     *
     * When a record is created, updated or deleted (e.g. from the MoonShine
     * admin panel), the deny config is regenerated from all currently active
     * blocks. Controlled by the "ip-blocker.server.sync_on_change" config so
     * it can be disabled when undesired.
     *
     * @return void
     */
    protected static function booted(): void
    {
        if (! static::shouldSyncDenyConfig()) {
            return;
        }

        static::saved(function () {
            self::syncDenyConfigFromDatabase();
        });

        static::deleted(function () {
            self::syncDenyConfigFromDatabase();
        });
    }

    /**
     * Whether the deny config should be regenerated on model changes.
     *
     * @return bool
     */
    private static function shouldSyncDenyConfig(): bool
    {
        return (bool) config('ip-blocker.server.sync_on_change', true);
    }

    /**
     * Regenerate the web server deny config from all active blocked IPs.
     *
     * Failures are caught and logged so a broken config path never breaks the
     * application flow.
     *
     * @return void
     */
    private static function syncDenyConfigFromDatabase(): void
    {
        try {
            app(DenyGenerator::class)->syncFromDatabase();
        } catch (\Throwable $e) {
            Log::error('[BlockedIp] Failed to sync deny config after model change', [
                'error' => $e->getMessage(),
            ]);
        }
    }

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
     * Scope: только истёкшие блокировки (is_active = false или срок истёк).
     *
     * @param Builder<BlockedIp> $query
     * @return void
     */
    public function scopeExpired(Builder $query): void
    {
        $query->where(function (Builder $q) {
            $q->where('is_active', false)
                ->orWhere(function (Builder $qq) {
                    $qq->whereNotNull('expires_at')
                        ->where('expires_at', '<=', now());
                });
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
