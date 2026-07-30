# Тестирование

## Запуск тестов

```bash
composer install
composer test
```

Или напрямую:

```bash
./vendor/bin/phpunit
```

## Структура тестов

```
tests/
├── Parsers/
│   ├── NginxCombinedParserTest.php      # Unit-тесты nginx парсера
│   ├── ApacheCommonParserTest.php       # Unit-тесты Apache common парсера
│   └── ApacheCombinedParserTest.php     # Unit-тесты Apache combined парсера
├── Services/
│   ├── LogParserTest.php                # Unit-тесты фасада LogParser
│   ├── IpAnalyzerTest.php               # Unit-тесты анализатора
│   └── DenyGeneratorTest.php            # Unit-тесты генератора deny-конфигов
├── Middleware/
│   ├── TrackSuspiciousIpsTest.php       # Unit-тесты middleware
│   └── TrackSuspiciousIpsIntegrationTest.php  # Integration-тесты middleware
├── Commands/
│   ├── ParseLogCommandTest.php          # Integration-тесты команды ip:parse-log
│   └── BlockCommandTest.php             # Integration-тесты команды ip:block
└── TestCase.php                         # Базовый TestCase для Orchestra
```

## Написание тестов

Тесты используют PHPUnit. Integration-тесты наследуют `Orchestra\Testbench\TestCase` для изолированного окружения Laravel.

### Пример unit-теста

```php
use PHPUnit\Framework\TestCase;
use Zoolok\IpBlocker\Parsers\NginxCombinedParser;

class NginxCombinedParserTest extends TestCase
{
    public function test_parses_valid_log_line(): void
    {
        $parser = new NginxCombinedParser();
        $result = $parser->parseLine(
            '192.168.1.1 - - [10/Jul/2026:13:55:36 +0000] "GET /admin HTTP/1.1" 404 123 "-" "curl/7.68.0"'
        );

        $this->assertNotNull($result);
        $this->assertSame('192.168.1.1', $result->ip);
    }
}
```

### Пример integration-теста

```php
use Orchestra\Testbench\TestCase;
use Zoolok\IpBlocker\IpBlockerServiceProvider;

class MyIntegrationTest extends TestCase
{
    protected function getPackageProviders($app): array
    {
        return [IpBlockerServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'test');
        $app['config']->set('database.connections.test', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
    }

    protected function setUp(): void
    {
        parent::setUp();
        $this->loadMigrationsFrom(realpath(__DIR__.'/../database/migrations'));
    }
}
```

## CI/CD

Пример для GitHub Actions:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        php: [8.1, 8.2, 8.3]
        laravel: [10, 11, 12]

    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
      - run: composer require "laravel/framework:^${{ matrix.laravel }}" --no-interaction --no-update
      - run: composer install
      - run: ./vendor/bin/phpunit
```
