<?php

declare(strict_types=1);

/**
 * Derafu: Csrf - CSRF tokens for the forms, over the session of Mezzio.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsCsrf;

use ArrayObject;
use Derafu\Csrf\Contract\SessionCsrfTokenManagerInterface;
use Derafu\Csrf\CsrfSessionMiddleware;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\Csrf\Translation\CsrfTranslationResourceProvider;
use Derafu\Form\Contract\Csrf\CsrfTokenManagerInterface;
use Derafu\Translation\Exception\Core\TranslatableLogicException;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Session\Session;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\DependencyInjection\Dumper\PhpDumper;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * An application that imports the services of the package gets, for the
 * interface that derafu/form asks for, the manager over the session, and the
 * middleware that gives the session to that same manager.
 */
#[CoversNothing]
final class ServicesTest extends TestCase
{
    private function container(bool $compile = true, string $configuration = 'csrf-services.yaml'): ContainerBuilder
    {
        $container = new ContainerBuilder();
        (new YamlFileLoader($container, new FileLocator([
            dirname(__DIR__, 2) . '/resources/config',
            dirname(__DIR__) . '/fixtures/config',
        ])))
            ->load($configuration);

        $container->getAlias(CsrfTokenManagerInterface::class)->setPublic(true);
        $container->getDefinition(SessionCsrfTokenManagerInterface::class)->setPublic(true);
        $container->getDefinition(CsrfSessionMiddleware::class)->setPublic(true);
        if ($compile) {
            $container->compile(true);
        }

        return $container;
    }

    #[Test]
    public function theInterfaceOfTheFormsIsTheManagerOverTheSession(): void
    {
        $manager = $this->container()->get(CsrfTokenManagerInterface::class);

        $this->assertInstanceOf(SessionCsrfTokenManager::class, $manager);
    }

    #[Test]
    public function theMiddlewareGivesTheSessionToTheManagerThatTheFormsUse(): void
    {
        $container = $this->container();
        $manager = $container->get(CsrfTokenManagerInterface::class);
        $this->assertInstanceOf(CsrfTokenManagerInterface::class, $manager);
        $middleware = $container->get(CsrfSessionMiddleware::class);
        $this->assertInstanceOf(CsrfSessionMiddleware::class, $middleware);

        /** @var ArrayObject<string, bool> $seen */
        $seen = new ArrayObject(['valid' => false]);
        $request = (new ServerRequest())->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, new Session([]));
        $middleware->process($request, new class ($manager, $seen) implements RequestHandlerInterface {
            public function __construct(
                private readonly CsrfTokenManagerInterface $manager,
                /** @var ArrayObject<string, bool> */
                private readonly ArrayObject $seen
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen['valid'] = $this->manager->isValid('login', $this->manager->getToken('login'));

                return new EmptyResponse();
            }
        });

        $this->assertTrue($seen['valid']);
    }

    #[Test]
    public function theTranslationsOfThePackageAreGivenToTheTranslator(): void
    {
        $definition = $this->container(compile: false)->getDefinition(CsrfTranslationResourceProvider::class);

        $this->assertArrayHasKey('derafu_translation.resource_provider', $definition->getTags());
    }

    #[Test]
    public function everyConfiguredServiceCanBeConstructedAndTheAliasSharesItsManager(): void
    {
        $container = $this->container(compile: false);
        foreach ($container->getDefinitions() as $definition) {
            $definition->setPublic(true);
        }
        $container->compile(true);

        foreach ([
            SessionCsrfTokenManagerInterface::class => SessionCsrfTokenManager::class,
            CsrfSessionMiddleware::class => CsrfSessionMiddleware::class,
            CsrfTranslationResourceProvider::class => CsrfTranslationResourceProvider::class,
        ] as $id => $class) {
            $this->assertInstanceOf($class, $container->get($id));
        }
        $this->assertSame($container->get(SessionCsrfTokenManagerInterface::class), $container->get(CsrfTokenManagerInterface::class));
        $resources = $container->get(CsrfTranslationResourceProvider::class);
        $this->assertInstanceOf(CsrfTranslationResourceProvider::class, $resources);
        $directories = [...$resources->getDirectories()];
        $this->assertCount(1, $directories);
        $this->assertSame(realpath(dirname(__DIR__, 2) . '/resources/translations'), realpath($directories[0]));
    }

    #[Test]
    public function theConsumerTranslatesARealManagerExceptionUsingTaggedResources(): void
    {
        $container = $this->container(compile: false, configuration: 'translation.yaml');
        $container->compile(true);
        $translator = $container->get(TranslatorInterface::class);
        $this->assertInstanceOf(Translator::class, $translator);
        $manager = $container->get(CsrfTokenManagerInterface::class);
        $this->assertInstanceOf(CsrfTokenManagerInterface::class, $manager);

        try {
            $manager->getToken('contact');
            $this->fail('The manager generated a token without a session.');
        } catch (TranslatableLogicException $exception) {
            $this->assertSame(
                'No hay una sesión para los tokens CSRF. Agrega CsrfSessionMiddleware al pipeline, después del middleware de la sesión.',
                $exception->trans($translator)
            );
        }
    }

    /**
     * @return array<string,array{bool}>
     */
    public static function handlerOutcomes(): array
    {
        return [
            'normal response' => [false],
            'handler exception' => [true],
        ];
    }

    #[DataProvider('handlerOutcomes')]
    public function testCompiledMiddlewareSharesTheManagerAndReleasesItsSession(bool $throws): void
    {
        $container = $this->container();
        $class = 'CsrfSessionContractContainer';
        $code = '';
        if (!class_exists($class, false)) {
            $dump = (new PhpDumper($container))->dump(['class' => $class]);
            self::assertIsString($dump);
            $code = substr($dump, 5);
        }
        $compiled = eval($code . "\nreturn new " . $class . '();');
        self::assertInstanceOf(ContainerInterface::class, $compiled);
        $manager = $compiled->get(CsrfTokenManagerInterface::class);
        self::assertInstanceOf(CsrfTokenManagerInterface::class, $manager);
        self::assertSame($manager, $compiled->get(SessionCsrfTokenManagerInterface::class));
        $middleware = $compiled->get(CsrfSessionMiddleware::class);
        self::assertInstanceOf(CsrfSessionMiddleware::class, $middleware);

        /** @var ArrayObject<string,bool> $seen */
        $seen = new ArrayObject(['valid' => false]);
        $request = (new ServerRequest())->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, new Session([]));
        $handler = new class ($manager, $seen, $throws) implements RequestHandlerInterface {
            /**
             * @param ArrayObject<string,bool> $seen
             */
            public function __construct(
                private readonly CsrfTokenManagerInterface $manager,
                private readonly ArrayObject $seen,
                private readonly bool $throws
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seen['valid'] = $this->manager->isValid('contact', $this->manager->getToken('contact'));
                if ($this->throws) {
                    throw new RuntimeException('Handler failed.');
                }

                return new EmptyResponse();
            }
        };

        try {
            $response = $middleware->process($request, $handler);
            self::assertFalse($throws, 'The handler exception was not propagated.');
            self::assertSame(204, $response->getStatusCode());
        } catch (RuntimeException $exception) {
            self::assertTrue($throws);
            self::assertSame('Handler failed.', $exception->getMessage());
        }
        self::assertTrue($seen['valid']);
        $this->expectException(TranslatableLogicException::class);
        $manager->getToken('contact');
    }
}
