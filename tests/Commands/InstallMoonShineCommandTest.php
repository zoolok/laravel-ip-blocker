<?php

namespace Zoolok\IpBlocker\Tests\Commands;

use Illuminate\Support\Facades\Artisan;
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

class InstallMoonShineCommandTest extends TestCase
{
    private string $layoutDir;

    private string $fixtureNamespace;

    protected function getPackageProviders($app): array
    {
        return [IpBlockerServiceProvider::class];
    }

    protected function setUp(): void
    {
        parent::setUp();

        if (! class_exists(\MoonShine\Laravel\DependencyInjection\MoonShineConfigurator::class)) {
            eval('namespace MoonShine\Laravel\DependencyInjection; class MoonShineConfigurator {}');
        }

        $this->layoutDir = sys_get_temp_dir().'/ip-blocker-moonshine-'.uniqid();
        $this->fixtureNamespace = 'Zoolok\IpBlocker\Tests\Fixtures\Ns'.uniqid();
        mkdir($this->layoutDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->layoutDir.'/*') as $file) {
            unlink($file);
        }
        rmdir($this->layoutDir);

        parent::tearDown();
    }

    /**
     * php artisan test --filter=test_installs_import_and_menu_entry tests/Commands/InstallMoonShineCommandTest.php
     *
     * Тест: команда добавляет use-импорт и пункт меню в layout-файл MoonShine.
     */
    public function test_installs_import_and_menu_entry(): void
    {
        $layoutFile = $this->writeLayout();

        $this->app['config']->set('moonshine.layout', $this->fixtureNamespace.'\MoonShineLayout');

        require_once $layoutFile;

        $exitCode = Artisan::call('ip:install-moonshine');

        $this->assertSame(0, $exitCode);

        $code = file_get_contents($layoutFile);

        $this->assertStringContainsString('use Zoolok\IpBlocker\MoonShine\BlockedIpResource;', $code);
        $this->assertStringContainsString("MenuItem::make(BlockedIpResource::class, 'Заблокированные IP'),", $code);
    }

    /**
     * php artisan test --filter=test_is_idempotent tests/Commands/InstallMoonShineCommandTest.php
     *
     * Тест: повторный запуск команды не дублирует импорт и пункт меню.
     */
    public function test_is_idempotent(): void
    {
        $layoutFile = $this->writeLayout();

        $this->app['config']->set('moonshine.layout', $this->fixtureNamespace.'\MoonShineLayout');

        require_once $layoutFile;

        Artisan::call('ip:install-moonshine');
        Artisan::call('ip:install-moonshine');

        $code = file_get_contents($layoutFile);

        $this->assertSame(1, substr_count($code, 'use Zoolok\IpBlocker\MoonShine\BlockedIpResource;'));
        $this->assertSame(1, substr_count($code, "MenuItem::make(BlockedIpResource::class, 'Заблокированные IP'),"));
    }

    /**
     * php artisan test --filter=test_fails_when_layout_missing tests/Commands/InstallMoonShineCommandTest.php
     *
     * Тест: если layout-класс не существует, команда завершается с ошибкой.
     */
    public function test_fails_when_layout_missing(): void
    {
        $this->app['config']->set('moonshine.layout', $this->fixtureNamespace.'\DoesNotExistLayout');

        $exitCode = Artisan::call('ip:install-moonshine');

        $this->assertSame(1, $exitCode);
        $this->assertStringContainsString('MoonShine layout file not found', Artisan::output());
    }

    /**
     * Write a fake MoonShine layout file to the temp directory.
     *
     * @return string Absolute path to the created layout file.
     */
    private function writeLayout(): string
    {
        $layoutFile = $this->layoutDir.'/MoonShineLayout.php';

        $code = <<<'PHP'
<?php

namespace %s;

use MoonShine\MenuManager\MenuItem;

class BaseLayout
{
    protected function menu(): array
    {
        return [];
    }
}

final class MoonShineLayout extends BaseLayout
{
    protected function menu(): array
    {
        return [
            ...parent::menu(),

            MenuItem::make(SomeResource::class, 'Some resource'),
        ];
    }
}
PHP;

        file_put_contents($layoutFile, sprintf($code, $this->fixtureNamespace));

        return $layoutFile;
    }
}
