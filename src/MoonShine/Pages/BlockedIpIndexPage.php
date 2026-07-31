<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine\Pages;

use MoonShine\Contracts\UI\ComponentContract;
use MoonShine\Laravel\Pages\Crud\IndexPage;
use MoonShine\UI\Fields\Checkbox;
use MoonShine\UI\Fields\Date;
use MoonShine\UI\Fields\ID;
use MoonShine\UI\Fields\Text;
use Zoolok\IpBlocker\Models\BlockedIp;

/**
 * @extends IndexPage<\Zoolok\IpBlocker\MoonShine\BlockedIpResource>
 */
class BlockedIpIndexPage extends IndexPage
{
    /**
     * Get the index page table fields.
     *
     * @return iterable<int, FieldContract>
     */
    protected function fields(): iterable
    {
        return [
            ID::make()->sortable(),
            Text::make('IP', 'ip')->sortable(),
            Text::make('Причина', 'reason'),
            Text::make('Кем заблокирован', 'blocked_by'),
            Date::make('Заблокирован', 'blocked_at')->sortable(),
            Date::make('Истекает', 'expires_at')->sortable(),
            Checkbox::make('Активно', 'is_active')->sortable(),
        ];
    }

    /**
     * Get the filter fields.
     *
     * @return iterable<int, FieldContract>
     */
    protected function filters(): iterable
    {
        return [
            Text::make('IP', 'ip'),
            Checkbox::make('Активно', 'is_active'),
            Date::make('Заблокирован с', 'blocked_at_from'),
            Date::make('Заблокирован до', 'blocked_at_to'),
        ];
    }

    /**
     * Modify the list component before rendering.
     *
     * @param ComponentContract $component Component to modify.
     * @return ComponentContract Modified component.
     */
    protected function modifyListComponent(ComponentContract $component): ComponentContract
    {
        return $component;
    }
}
