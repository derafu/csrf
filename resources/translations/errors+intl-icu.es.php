<?php

declare(strict_types=1);

/**
 * Derafu: Csrf - CSRF tokens for the forms, over the session of Mezzio.
 *
 * Copyright (c) 2026 Esteban De La Fuente Rubio / Derafu <https://www.derafu.dev>
 * Licensed under the MIT License.
 * See LICENSE file for more details.
 */

return [
    'There is no session for the CSRF tokens. Add CsrfSessionMiddleware to the pipeline, after the session middleware.' =>
        'No hay una sesión para los tokens CSRF. Agrega CsrfSessionMiddleware al pipeline, después del middleware de la sesión.',
];
