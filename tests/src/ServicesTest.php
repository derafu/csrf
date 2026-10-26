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
use Derafu\Csrf\CsrfSessionMiddleware;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\Csrf\Translation\CsrfTranslationResourceProvider;
use Derafu\Form\Contract\Csrf\CsrfTokenManagerInterface;
use Derafu\Translation\Exception\Core\TranslatableLogicException;
use Derafu\Translation\TranslatorFactory;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Session\Session;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\Translation\Translator;

/**
 * An application that imports the services of the package gets, for the
 * interface that derafu/form asks for, the manager over the session, and the
 * middleware that gives the session to that same manager.
 */
#[CoversNothing]
final class ServicesTest extends TestCase
{
    private function container(bool $compile = true): ContainerBuilder
    {
        $container = new ContainerBuilder();
        (new YamlFileLoader($container, new FileLocator(dirname(__DIR__, 2) . '/resources/config')))
            ->load('csrf-services.yaml');

        $container->getAlias(CsrfTokenManagerInterface::class)->setPublic(true);
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

        foreach ([SessionCsrfTokenManager::class, CsrfSessionMiddleware::class, CsrfTranslationResourceProvider::class] as $class) {
            $this->assertInstanceOf($class, $container->get($class));
        }
        $this->assertSame($container->get(SessionCsrfTokenManager::class), $container->get(CsrfTokenManagerInterface::class));
        $resources = $container->get(CsrfTranslationResourceProvider::class);
        $this->assertInstanceOf(CsrfTranslationResourceProvider::class, $resources);
        $directories = [...$resources->getDirectories()];
        $this->assertCount(1, $directories);
        $this->assertSame(realpath(dirname(__DIR__, 2) . '/resources/translations'), realpath($directories[0]));
    }

    #[Test]
    public function theConsumerTranslatesARealManagerExceptionUsingTaggedResources(): void
    {
        $container = $this->container(compile: false);
        $container->register('app.translator', Translator::class)
            ->setFactory([TranslatorFactory::class, 'create'])
            ->setArguments(['es', ['en'], new TaggedIteratorArgument('derafu_translation.resource_provider')])
            ->setPublic(true);
        $container->compile(true);
        $translator = $container->get('app.translator');
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
}
