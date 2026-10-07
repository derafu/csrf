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
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

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
}
