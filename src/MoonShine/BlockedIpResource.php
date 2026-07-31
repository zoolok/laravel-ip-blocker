<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine;

use MoonShine\Laravel\Resources\ModelResource;
use MoonShine\Support\Enums\Action;
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
     * @return ListOf<int, Action> Actions with create and update removed.
     */
    protected function activeActions(): ListOf
    {
        return parent::activeActions()->except(Action::CREATE, Action::UPDATE);
    }
}
