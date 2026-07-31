<?php

namespace Zoolok\IpBlocker\Tests\MoonShine3;

use MoonShine\Laravel\DependencyInjection\MoonShine;
use MoonShine\Laravel\DependencyInjection\MoonShineConfigurator;
use MoonShine\Laravel\Providers\MoonShineServiceProvider;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;
use Zoolok\IpBlocker\MoonShine\BlockedIpResource;
use Zoolok\IpBlocker\MoonShine\MoonShineVersion;

class MoonShine3CompatibilityTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        $providers = [
            IpBlockerServiceProvider::class,
        ];

        if (class_exists(MoonShineServiceProvider::class)) {
            $providers[] = MoonShineServiceProvider::class;
        }

        return $providers;
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (! class_exists(\MoonShine\Laravel\Enums\Action::class)) {
            $this->markTestSkipped('MoonShine 3.x is not installed in this environment.');
        }
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('ip-blocker.moonshine.enabled', true);
        $app['config']->set('moonshine.identity', 'test');
    }

    /**
     * php artisan test --filter=test_detects_moonshine_3 tests/MoonShine3/MoonShine3CompatibilityTest.php
     *
     * Тест: определение третьей версии MoonShine через хелпер.
     */
    public function test_detects_moonshine_3(): void
    {
        $this->assertFalse(MoonShineVersion::isV4());

        $this->assertSame(
            \MoonShine\Laravel\Enums\Action::class,
            MoonShineVersion::actionEnum()
        );
    }

    /**
     * php artisan test --filter=test_creates_query_tags tests/MoonShine3/MoonShine3CompatibilityTest.php
     *
     * Тест: создание QueryTag совместимо с MoonShine 3.x.
     */
    public function test_creates_query_tags(): void
    {
        $tag = MoonShineVersion::queryTag(
            'Активные',
            fn ($query) => $query->where('is_active', true)
        );

        $this->assertInstanceOf(\MoonShine\Laravel\QueryTags\QueryTag::class, $tag);
    }

    /**
     * php artisan test --filter=test_resource_registers tests/MoonShine3/MoonShine3CompatibilityTest.php
     *
     * Тест: ресурс регистрируется в MoonShine 3.x и его queryTags не пустые.
     */
    public function test_resource_registers(): void
    {
        $core = app(MoonShine::class);

        $core->resources([
            BlockedIpResource::class,
        ]);

        $resources = $core->getResources();

        $this->assertTrue($resources->contains(
            static fn (BlockedIpResource $r): bool => $r instanceof BlockedIpResource
        ));

        $resource = $resources->first(
            static fn (BlockedIpResource $r): bool => $r instanceof BlockedIpResource
        );

        $this->assertNotNull($resource);
        $this->assertTrue($resource->hasQueryTags());
        $this->assertNotEmpty($resource->getQueryTags());

        foreach ($resource->getQueryTags() as $tag) {
            $this->assertInstanceOf(\MoonShine\Laravel\QueryTags\QueryTag::class, $tag);
        }
    }

    /**
     * php artisan test --filter=test_active_actions_exclude_create_update tests/MoonShine3/MoonShine3CompatibilityTest.php
     *
     * Тест: из activeActions исключены create и update.
     */
    public function test_active_actions_exclude_create_update(): void
    {
        $core = app(MoonShine::class);

        $core->resources([
            BlockedIpResource::class,
        ]);

        $resource = $core->getResources()->first();

        $this->assertInstanceOf(BlockedIpResource::class, $resource);

        $this->assertFalse($resource->hasAction(\MoonShine\Laravel\Enums\Action::CREATE));
        $this->assertFalse($resource->hasAction(\MoonShine\Laravel\Enums\Action::UPDATE));
        $this->assertTrue($resource->hasAction(\MoonShine\Laravel\Enums\Action::VIEW));
        $this->assertTrue($resource->hasAction(\MoonShine\Laravel\Enums\Action::DELETE));
    }
}
