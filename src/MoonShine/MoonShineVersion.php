<?php

declare(strict_types=1);

namespace Zoolok\IpBlocker\MoonShine;

use Closure;

/**
 * Detects the installed MoonShine major version and provides
 * version-agnostic access to version-specific classes.
 */
final class MoonShineVersion
{
    /**
     * Whether MoonShine 4.x (or higher) is installed.
     *
     * @return bool True when the 4.x class layout is present.
     */
    public static function isV4(): bool
    {
        return class_exists(\MoonShine\Support\Enums\Action::class)
            && class_exists(\MoonShine\Crud\QueryTags\QueryTag::class);
    }

    /**
     * Get the Action enum class for the installed version.
     *
     * @return class-string<\MoonShine\Support\Enums\Action|\MoonShine\Laravel\Enums\Action> Backed enum class with Action cases.
     */
    public static function actionEnum(): string
    {
        return self::isV4()
            ? \MoonShine\Support\Enums\Action::class
            : \MoonShine\Laravel\Enums\Action::class;
    }

    /**
     * Get an Action enum case by name.
     *
     * @param string $case Case name, e.g. "CREATE".
     * @return \BackedEnum The Action enum case.
     */
    public static function action(string $case): \BackedEnum
    {
        $enum = self::actionEnum();

        return $enum::{$case};
    }

    /**
     * Create a query tag for the installed version.
     *
     * @param Closure|string $label Tag label.
     * @param Closure $builder Query builder callback.
     * @return \MoonShine\Crud\QueryTags\QueryTag|\MoonShine\Laravel\QueryTags\QueryTag QueryTag instance.
     */
    public static function queryTag(Closure|string $label, Closure $builder): object
    {
        $class = self::isV4()
            ? \MoonShine\Crud\QueryTags\QueryTag::class
            : \MoonShine\Laravel\QueryTags\QueryTag::class;

        return $class::make($label, $builder);
    }
}
