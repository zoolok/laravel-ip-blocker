<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine\Pages;

use MoonShine\Contracts\UI\ComponentContract;
use MoonShine\Laravel\Pages\Crud\DetailPage;
use MoonShine\UI\Fields\Checkbox;
use MoonShine\UI\Fields\Date;
use MoonShine\UI\Fields\ID;
use MoonShine\UI\Fields\Text;
use MoonShine\UI\Fields\Textarea;
use Zoolok\IpBlocker\Models\BlockedIp;

/**
 * @extends DetailPage<\Zoolok\IpBlocker\MoonShine\BlockedIpResource>
 */
class BlockedIpDetailPage extends DetailPage
{
    /**
     * Get the detail page fields.
     *
     * @return iterable<int, FieldContract>
     */
    protected function fields(): iterable
    {
        return [
            ID::make(),
            Text::make('IP', 'ip'),
            Textarea::make('Причина', 'reason'),
            Text::make('Кем заблокирован', 'blocked_by'),
            Date::make('Заблокирован', 'blocked_at'),
            Date::make('Истекает', 'expires_at'),
            Checkbox::make('Активно', 'is_active'),
        ];
    }

    /**
     * Modify the detail component before rendering.
     *
     * @param ComponentContract $component Component to modify.
     * @return ComponentContract Modified component.
     */
    protected function modifyDetailComponent(ComponentContract $component): ComponentContract
    {
        return $component;
    }
}
