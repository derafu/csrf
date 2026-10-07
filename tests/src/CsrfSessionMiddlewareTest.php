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

use Derafu\Csrf\CsrfSessionMiddleware;
use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\Translation\Exception\Core\TranslatableLogicException;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Session\Session;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\UsesClass;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use RuntimeException;

/**
 * The manager has the session of the request while the request is handled, and
 * it is released when the request is over.
 */
#[CoversClass(CsrfSessionMiddleware::class)]
#[UsesClass(SessionCsrfTokenManager::class)]
final class CsrfSessionMiddlewareTest extends TestCase
{
    private function request(bool $withSession = true): ServerRequestInterface
    {
        $request = new ServerRequest();

        return $withSession
            ? $request->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, new Session([]))
            : $request;
    }

    private function handler(callable $callback): RequestHandlerInterface
    {
        return new class ($callback) implements RequestHandlerInterface {
            public function __construct(private readonly mixed $callback)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ($this->callback)();

                return new EmptyResponse();
            }
        };
    }

    #[Test]
    public function theManagerHasTheSessionWhileTheRequestIsHandled(): void
    {
        $manager = new SessionCsrfTokenManager();
        $valid = null;

        (new CsrfSessionMiddleware($manager))->process(
            $this->request(),
            $this->handler(function () use ($manager, &$valid): void {
                $valid = $manager->isValid('login', $manager->getToken('login'));
            })
        );

        $this->assertTrue($valid);
    }

    #[Test]
    public function theManagerIsReleasedWhenTheRequestIsOver(): void
    {
        $manager = new SessionCsrfTokenManager();

        (new CsrfSessionMiddleware($manager))->process($this->request(), $this->handler(fn () => null));

        $this->expectException(TranslatableLogicException::class);
        $manager->getToken('login');
    }

    #[Test]
    public function theManagerIsReleasedAlsoWhenTheRequestEndsWithAnException(): void
    {
        $manager = new SessionCsrfTokenManager();

        try {
            (new CsrfSessionMiddleware($manager))->process(
                $this->request(),
                $this->handler(function (): never {
                    throw new RuntimeException('boom');
                })
            );
            $this->fail('The exception did not go through.');
        } catch (RuntimeException $e) {
            $this->assertSame('boom', $e->getMessage());
        }

        $this->expectException(TranslatableLogicException::class);
        $manager->getToken('login');
    }

    #[Test]
    public function aRequestWithoutSessionGoesOnAndTheManagerCanNotBeUsedInIt(): void
    {
        $manager = new SessionCsrfTokenManager();
        $handled = false;
        $failed = false;

        (new CsrfSessionMiddleware($manager))->process(
            $this->request(withSession: false),
            $this->handler(function () use ($manager, &$handled, &$failed): void {
                $handled = true;
                try {
                    $manager->getToken('login');
                } catch (TranslatableLogicException) {
                    $failed = true;
                }
            })
        );

        $this->assertTrue($handled);
        $this->assertTrue($failed);
    }

    #[Test]
    public function anAttributeThatIsNotASessionIsNotOne(): void
    {
        $manager = new SessionCsrfTokenManager();
        $request = $this->request()->withAttribute(SessionMiddleware::SESSION_ATTRIBUTE, 'not a session');
        $failed = false;

        (new CsrfSessionMiddleware($manager))->process($request, $this->handler(function () use ($manager, &$failed): void {
            try {
                $manager->getToken('login');
            } catch (TranslatableLogicException) {
                $failed = true;
            }
        }));

        $this->assertTrue($failed);
    }
}
