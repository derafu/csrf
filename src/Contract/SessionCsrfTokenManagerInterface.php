<?php

declare(strict_types=1);

/**
 * Derafu: Csrf - CSRF tokens for the forms, over the session of Mezzio.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

namespace Derafu\Csrf\Contract;

use Derafu\Form\Contract\Csrf\CsrfTokenManagerInterface;
use Mezzio\Session\SessionInterface;

/** CSRF tokens bound to the session of the request being handled. */
interface SessionCsrfTokenManagerInterface extends CsrfTokenManagerInterface
{
    /**
     * Attach the request's session, or detach it with null when handling ends.
     */
    public function useSession(?SessionInterface $session): void;
}
