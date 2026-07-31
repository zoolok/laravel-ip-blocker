<?php

namespace Zoolok\IpBlocker\Commands;

use Illuminate\Console\Command;
use MoonShine\Laravel\DependencyInjection\MoonShineConfigurator;
use Zoolok\IpBlocker\MoonShine\BlockedIpResource;

class InstallMoonShineCommand extends Command
{
    protected $signature = 'ip:install-moonshine
        {--force : Re-insert the menu entry even if it already exists}';

    protected $description = 'Add the blocked-IP resource to the MoonShine admin panel menu';

    /**
     * Execute the console command.
     *
     * Locates the active MoonShine layout file (from the "moonshine.layout"
     * config) and inserts the resource import and a menu item pointing to the
     * package BlockedIpResource. Idempotent: existing entries are not
     * duplicated unless --force is passed.
     *
     * @return int Command exit code (SUCCESS or FAILURE).
     */
    public function handle(): int
    {
        if (! class_exists(MoonShineConfigurator::class)) {
            $this->error('MoonShine is not installed. Run: composer require moonshine/moonshine');

            return self::FAILURE;
        }

        if (! (bool) config('ip-blocker.moonshine.enabled')) {
            $this->warn('ip-blocker.moonshine.enabled is false. Set IP_BLOCKER_MOONSHINE_ENABLED=true in .env to register the resource.');
        }

        $layoutFile = $this->resolveLayoutFile();

        if ($layoutFile === null) {
            $this->error('MoonShine layout file not found. Check the "moonshine.layout" config value.');

            return self::FAILURE;
        }

        $this->components->info("Editing MoonShine layout: {$layoutFile}");

        $original = file_get_contents($layoutFile);

        if ($original === false) {
            $this->error("Unable to read layout file: {$layoutFile}");

            return self::FAILURE;
        }

        $code = $original;
        $changed = false;

        [$code, $importChanged] = $this->ensureImport($code);
        [$code, $menuChanged] = $this->ensureMenuEntry($code, $this->option('force'));

        $changed = $importChanged || $menuChanged;

        if (! $changed) {
            $this->components->info('MoonShine resource is already installed. Nothing to do.');

            return self::SUCCESS;
        }

        $bytes = file_put_contents($layoutFile, $code);

        if ($bytes === false) {
            $this->error("Unable to write layout file: {$layoutFile}");

            return self::FAILURE;
        }

        if ($importChanged) {
            $this->components->twoColumnDetail('Import', 'added');
        }

        if ($menuChanged) {
            $this->components->twoColumnDetail('Menu entry', 'added');
        }

        $this->components->twoColumnDetail('Resource', BlockedIpResource::class);
        $this->components->twoColumnDetail('Layout', $layoutFile);

        $this->components->info('Done. Open the MoonShine admin panel to see the "Заблокированные IP" item.');

        return self::SUCCESS;
    }

    /**
     * Resolve the active MoonShine layout file path.
     *
     * @return string|null Absolute path to the layout file, or null when the
     *                     configured layout class cannot be resolved.
     */
    private function resolveLayoutFile(): ?string
    {
        $layoutClass = config('moonshine.layout');

        if (! is_string($layoutClass) || $layoutClass === '') {
            return null;
        }

        if (! class_exists($layoutClass)) {
            return null;
        }

        $reflection = new \ReflectionClass($layoutClass);

        $file = $reflection->getFileName();

        return $file === false ? null : $file;
    }

    /**
     * Ensure the package resource import is present in the layout file.
     *
     * @param string $code Current layout source code.
     * @return array{0: string, 1: bool} Updated code and whether a change was made.
     */
    private function ensureImport(string $code): array
    {
        $import = 'use Zoolok\IpBlocker\MoonShine\BlockedIpResource;';

        if (str_contains($code, $import)) {
            return [$code, false];
        }

        $lastUsePosition = mb_strrpos($code, 'use MoonShine');

        if ($lastUsePosition === false) {
            $lastUsePosition = mb_strrpos($code, 'use App\\');

            if ($lastUsePosition === false) {
                return [$code, false];
            }
        }

        $lineEnd = mb_strpos($code, "\n", $lastUsePosition);

        if ($lineEnd === false) {
            $lineEnd = mb_strlen($code);
        }

        $updated = mb_substr($code, 0, $lineEnd + 1)
            .$import."\n"
            .mb_substr($code, $lineEnd + 1);

        return [$updated, true];
    }

    /**
     * Ensure a menu item for the package resource exists in the layout menu.
     *
     * @param string $code Current layout source code.
     * @param bool $force Re-insert even if the entry already exists.
     * @return array{0: string, 1: bool} Updated code and whether a change was made.
     */
    private function ensureMenuEntry(string $code, bool $force = false): array
    {
        $entry = "MenuItem::make(BlockedIpResource::class, 'Заблокированные IP'),";

        if (! $force && str_contains($code, 'BlockedIpResource::class')) {
            return [$code, false];
        }

        $anchor = '...parent::menu(),';

        $anchorPosition = mb_strpos($code, $anchor);

        if ($anchorPosition !== false) {
            $insertAt = $anchorPosition + mb_strlen($anchor);

            $updated = mb_substr($code, 0, $insertAt)
                ."\n            ".$entry
                .mb_substr($code, $insertAt);

            return [$updated, true];
        }

        $menuMethod = 'protected function menu(): array';

        $methodPosition = mb_strpos($code, $menuMethod);

        if ($methodPosition === false) {
            return [$code, false];
        }

        $returnPosition = mb_strpos($code, 'return [', $methodPosition);

        if ($returnPosition === false) {
            return [$code, false];
        }

        $insertAt = $returnPosition + mb_strlen('return [');

        $updated = mb_substr($code, 0, $insertAt)
            ."\n            ".$entry
            .mb_substr($code, $insertAt);

        return [$updated, true];
    }
}
