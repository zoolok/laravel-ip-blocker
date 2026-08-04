<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine\Pages;

use MoonShine\Laravel\Pages\Crud\FormPage;
use MoonShine\UI\Fields\Checkbox;
use MoonShine\UI\Fields\Date;
use MoonShine\UI\Fields\ID;
use MoonShine\UI\Fields\Text;
use MoonShine\UI\Fields\Textarea;

/**
 * @extends FormPage<\Zoolok\IpBlocker\MoonShine\BlockedIpResource>
 */
class BlockedIpFormPage extends FormPage
{
    /**
     * Get the form page fields.
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
}