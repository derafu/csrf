<?php

declare(strict_types=1);

/**
 * Derafu: Csrf - CSRF tokens for the forms, over the session of Mezzio.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Csrf;

use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionMiddleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Gives the session of the request to the CSRF token manager, for the time that
 * the request is handled.
 *
 * It goes after `Mezzio\Session\SessionMiddleware`, which puts the session in
 * the request. The manager gets only the session, not the request, and it is
 * released when the request is over, also if it ends with an exception.
 */
final class CsrfSessionMiddleware implements MiddlewareInterface
{
    public function __construct(private readonly SessionCsrfTokenManager $manager)
    {
    }

    /**
     * {@inheritDoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $session = $request->getAttribute(SessionMiddleware::SESSION_ATTRIBUTE);

        $this->manager->useSession($session instanceof SessionInterface ? $session : null);

        try {
            return $handler->handle($request);
        } finally {
            $this->manager->useSession(null);
        }
    }
}
