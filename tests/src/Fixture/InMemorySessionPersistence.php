<?php

declare(strict_types=1);

/**
 * Derafu: Csrf - CSRF tokens for the forms, over the session of Mezzio.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\TestsCsrf\Fixture;

use Mezzio\Session\Session;
use Mezzio\Session\SessionInterface;
use Mezzio\Session\SessionPersistenceInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * A session persistence that keeps the sessions in memory, with the contract of
 * the one of PHP (`PhpSessionPersistence`): a request without the cookie `sid`
 * has no session until something is written in it, and then it gets an
 * identifier, that is given in the header `X-Session-Id` of the response (the
 * client sends it back in the cookie). A session that did not change does not
 * set anything.
 */
final class InMemorySessionPersistence implements SessionPersistenceInterface
{
    /**
     * The data of the sessions, by identifier.
     *
     * @var array<string, array<string, mixed>>
     */
    public array $store = [];

    public function initializeSessionFromRequest(ServerRequestInterface $request): SessionInterface
    {
        $id = (string) ($request->getCookieParams()['sid'] ?? '');

        return new Session($id !== '' ? ($this->store[$id] ?? []) : [], $id);
    }

    public function persistSession(SessionInterface $session, ResponseInterface $response): ResponseInterface
    {
        $id = $session->getId();

        if (!$session->hasChanged()) {
            return $response;
        }

        if ($id === '' || $session->isRegenerated()) {
            unset($this->store[$id]);
            $id = bin2hex(random_bytes(16));
        }

        $this->store[$id] = $session->toArray();

        return $response->withHeader('X-Session-Id', $id);
    }
}
