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

use Derafu\Csrf\SessionCsrfTokenManager;
use Derafu\Translation\Exception\Core\TranslatableLogicException;
use Mezzio\Session\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The tokens of the manager: one secret for each id in the session of the user,
 * a masked copy of it that is different every time, and a check that does not
 * use the token up.
 */
#[CoversClass(SessionCsrfTokenManager::class)]
final class SessionCsrfTokenManagerTest extends TestCase
{
    private function manager(?Session $session = null): SessionCsrfTokenManager
    {
        $manager = new SessionCsrfTokenManager();
        $manager->useSession($session ?? new Session([]));

        return $manager;
    }

    #[Test]
    public function aTokenIsValidForTheIdAndTheSessionItWasGivenFor(): void
    {
        $manager = $this->manager();

        $this->assertTrue($manager->isValid('login', $manager->getToken('login')));
    }

    #[Test]
    public function theTokenIsDifferentEveryTimeAndAllOfThemAreValid(): void
    {
        $manager = $this->manager();

        $first = $manager->getToken('login');
        $second = $manager->getToken('login');

        $this->assertNotSame($first, $second);
        $this->assertTrue($manager->isValid('login', $first));
        $this->assertTrue($manager->isValid('login', $second));
    }

    #[Test]
    public function checkingATokenDoesNotUseItUp(): void
    {
        $manager = $this->manager();
        $token = $manager->getToken('login');

        $this->assertTrue($manager->isValid('login', $token));
        $this->assertTrue($manager->isValid('login', $token));
    }

    #[Test]
    public function theSecretIsTheSameWhileTheSessionLasts(): void
    {
        $session = new Session([]);
        $token = $this->manager($session)->getToken('login');

        // Another manager, for the same session (another request).
        $this->assertTrue($this->manager($session)->isValid('login', $token));
        $this->assertCount(1, $session->get(SessionCsrfTokenManager::SESSION_KEY));
    }

    #[Test]
    public function theTokenOfAnotherIdIsNotValid(): void
    {
        $manager = $this->manager();
        $manager->getToken('login');
        $other = $manager->getToken('contact');

        $this->assertFalse($manager->isValid('login', $other));
    }

    #[Test]
    public function aTokenOfAnotherSessionIsNotValid(): void
    {
        $token = $this->manager()->getToken('login');
        $other = $this->manager();
        $other->getToken('login');

        $this->assertFalse($other->isValid('login', $token));
    }

    #[Test]
    public function anIdThatNeverHadATokenIsNotValid(): void
    {
        $manager = $this->manager();

        $this->assertFalse($manager->isValid('login', $manager->getToken('contact')));
        $this->assertFalse($this->manager()->isValid('login', 'anything'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function badTokens(): array
    {
        return [
            'empty' => [''],
            'not base64' => ['***'],
            'short' => ['abcd'],
            'too long' => [str_repeat('a', 400)],
            'only the key' => [rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=')],
        ];
    }

    #[Test]
    #[DataProvider('badTokens')]
    public function aTokenThatIsNotOneIsNotValid(string $token): void
    {
        $manager = $this->manager();
        $manager->getToken('login');

        $this->assertFalse($manager->isValid('login', $token));
    }

    #[Test]
    public function aTokenWithAChangedByteIsNotValid(): void
    {
        $manager = $this->manager();
        $token = $manager->getToken('login');
        $changed = ($token[0] === 'A' ? 'B' : 'A') . substr($token, 1);

        $this->assertFalse($manager->isValid('login', $changed));
    }

    #[Test]
    public function aValidTokenWithAnythingAddedOrTakenAwayIsNotValid(): void
    {
        $manager = $this->manager();
        $token = $manager->getToken('login');
        $bytes = base64_decode(strtr($token, '-_', '+/'), true);
        $this->assertIsString($bytes);

        $encode = static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');

        $this->assertTrue($manager->isValid('login', $encode($bytes)));
        $this->assertFalse($manager->isValid('login', $encode($bytes . 'extra')));
        $this->assertFalse($manager->isValid('login', $encode(substr($bytes, 0, -1))));
        $this->assertFalse($manager->isValid('login', substr($token, 0, 10) . '*' . substr($token, 10)));
    }

    #[Test]
    public function theSecretNeverGoesInTheToken(): void
    {
        $session = new Session([]);
        $token = $this->manager($session)->getToken('login');
        $secret = $session->get(SessionCsrfTokenManager::SESSION_KEY)['login'];

        $this->assertStringNotContainsString($secret, $token);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $token);
    }

    #[Test]
    public function whatTheSessionHasInTheKeyThatIsNotSecretsIsIgnored(): void
    {
        $manager = $this->manager(new Session([SessionCsrfTokenManager::SESSION_KEY => 'garbage']));
        $this->assertTrue($manager->isValid('login', $manager->getToken('login')));

        $manager = $this->manager(new Session([SessionCsrfTokenManager::SESSION_KEY => ['login' => ['not a string']]]));
        $this->assertFalse($manager->isValid('login', 'anything'));
        $this->assertTrue($manager->isValid('login', $manager->getToken('login')));
    }

    #[Test]
    public function withoutASessionTheManagerCanNotGiveATokenNorCheckOne(): void
    {
        $manager = new SessionCsrfTokenManager();

        try {
            $manager->getToken('login');
            $this->fail('A token was given without a session.');
        } catch (TranslatableLogicException $e) {
            $this->assertStringContainsString('CsrfSessionMiddleware', $e->getMessage());
        }

        $this->expectException(TranslatableLogicException::class);
        $manager->isValid('login', 'token');
    }

    #[Test]
    public function theSessionCanBeTakenAway(): void
    {
        $manager = $this->manager();
        $manager->useSession(null);

        $this->expectException(TranslatableLogicException::class);
        $manager->getToken('login');
    }
}
