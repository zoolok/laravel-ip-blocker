<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine;

use MoonShine\Laravel\Resources\ModelResource;
use MoonShine\Support\ListOf;
use Zoolok\IpBlocker\Models\BlockedIp;
use Zoolok\IpBlocker\MoonShine\Pages\BlockedIpDetailPage;
use Zoolok\IpBlocker\MoonShine\Pages\BlockedIpIndexPage;

/**
 * @extends ModelResource<BlockedIp, BlockedIpIndexPage, null, BlockedIpDetailPage>
 */
class BlockedIpResource extends ModelResource
{
    protected string $model = BlockedIp::class;

    protected string $title = 'Заблокированные IP';

    protected string $column = 'ip';

    /**
     * Get the list of pages for the resource.
     *
     * @return array<int, class-string>
     */
    protected function pages(): array
    {
        return [
            BlockedIpIndexPage::class,
            BlockedIpDetailPage::class,
        ];
    }

    /**
     * Get the allowed actions.
     *
     * Uses the installed version's Action enum. Actions CREATE and UPDATE
     * are removed so the resource is read-only.
     *
     * @return ListOf<\MoonShine\Support\Enums\Action|\MoonShine\Laravel\Enums\Action>
     */
    protected function activeActions(): ListOf
    {
        return parent::activeActions()->except(
            MoonShineVersion::action('CREATE'),
            MoonShineVersion::action('UPDATE'),
        );
    }

    /**
     * Get the query tags for quick filtering.
     *
     * «Активные» и «Истекшие» вычисляются по сроку истечения, а не только по
     * флагу is_active (пакет никогда не выставляет is_active = false).
     *
     * Works in both MoonShine 3.x (resource-level tags) and 4.x
     * (resource tags are delegated by the CrudResource).
     *
     * @return list<\MoonShine\Crud\QueryTags\QueryTag|\MoonShine\Laravel\QueryTags\QueryTag>
     */
    protected function queryTags(): array
    {
        return [
            MoonShineVersion::queryTag('Активные', fn ($query) => $query->active()),
            MoonShineVersion::queryTag('Истекшие', fn ($query) => $query->expired()),
        ];
    }
}
