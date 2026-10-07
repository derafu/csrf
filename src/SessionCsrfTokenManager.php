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

use Derafu\Form\Contract\Csrf\CsrfTokenManagerInterface;
use Derafu\Translation\Exception\Core\TranslatableLogicException as LogicException;
use Mezzio\Session\SessionInterface;

/**
 * CSRF token manager over the session of Mezzio.
 *
 * Each id (the form that the token is for) has a secret that lives in the
 * session of the user, and it is the same while the session lasts: checking a
 * token does not use it up, so two tabs of the same form, the back button, or a
 * form that is shown again after an error keep working.
 *
 * The token that is given is not the secret but a **masked** copy of it: the
 * secret combined with random bytes, that are different every time. The token
 * that travels in the HTML changes in every response, so it can not be guessed
 * by comparing compressed responses (BREACH), and checking it takes the mask
 * out and compares in constant time.
 *
 * The session belongs to a request, and the manager is a service of the
 * container, so the session is given to it for the time of the request by
 * `CsrfSessionMiddleware`. Without it, the manager can not be used.
 */
final class SessionCsrfTokenManager implements CsrfTokenManagerInterface
{
    /**
     * Where the secrets are in the session: an array from the id to its secret.
     */
    public const SESSION_KEY = 'derafu.csrf';

    /**
     * Random bytes of a secret (it is kept as hexadecimal).
     */
    private const SECRET_BYTES = 32;

    /**
     * The session of the request that is being handled.
     */
    private ?SessionInterface $session = null;

    /**
     * Gives the session of the request that is being handled, or takes it away
     * with `null` when the request is over.
     */
    public function useSession(?SessionInterface $session): void
    {
        $this->session = $session;
    }

    /**
     * {@inheritDoc}
     */
    public function getToken(string $id): string
    {
        $session = $this->getSession();
        $secrets = $this->getSecrets($session);

        if (!isset($secrets[$id])) {
            $secrets[$id] = bin2hex(random_bytes(self::SECRET_BYTES));
            $session->set(self::SESSION_KEY, $secrets);
        }

        return $this->mask($secrets[$id]);
    }

    /**
     * {@inheritDoc}
     */
    public function isValid(string $id, string $token): bool
    {
        $secret = $this->getSecrets($this->getSession())[$id] ?? null;

        if ($secret === null) {
            return false;
        }

        $unmasked = $this->unmask($token, strlen($secret));

        return $unmasked !== null && hash_equals($secret, $unmasked);
    }

    /**
     * Gets the session of the request.
     *
     * @throws LogicException If there is none.
     */
    private function getSession(): SessionInterface
    {
        return $this->session ?? throw new LogicException(
            'There is no session for the CSRF tokens. Add CsrfSessionMiddleware to the pipeline, after the session middleware.'
        );
    }

    /**
     * Gets the secrets of the session, by id.
     *
     * @return array<string, string>
     */
    private function getSecrets(SessionInterface $session): array
    {
        $secrets = $session->get(self::SESSION_KEY);

        return is_array($secrets) ? array_filter($secrets, 'is_string') : [];
    }

    /**
     * Masks a secret: random bytes, followed by the secret combined with them.
     */
    private function mask(string $secret): string
    {
        $key = random_bytes(strlen($secret));

        return rtrim(strtr(base64_encode($key . ($key ^ $secret)), '+/', '-_'), '=');
    }

    /**
     * Takes the mask out of a token.
     *
     * @param string $token The token, as it was given.
     * @param int $length The length of a secret.
     * @return string|null The secret that it hides, or `null` if it is not a
     * token.
     */
    private function unmask(string $token, int $length): ?string
    {
        $decoded = base64_decode(strtr($token, '-_', '+/'), true);

        if ($decoded === false || strlen($decoded) !== $length * 2) {
            return null;
        }

        return substr($decoded, 0, $length) ^ substr($decoded, $length);
    }
}
