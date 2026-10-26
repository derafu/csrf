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
use Derafu\DataProcessor\ProcessorFactory;
use Derafu\Form\Contract\FormInterface;
use Derafu\Form\Contract\Processor\ProcessResultInterface;
use Derafu\Form\Factory\FormRendererFactory;
use Derafu\Form\Form;
use Derafu\Form\Processor\FormDataProcessor;
use Derafu\Form\Processor\FormRulesResolver;
use Derafu\TestsCsrf\Fixture\InMemorySessionPersistence;
use Laminas\Diactoros\Response\EmptyResponse;
use Laminas\Diactoros\ServerRequest;
use Mezzio\Session\SessionMiddleware;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The manager with what it works with: the session middleware of Mezzio, the
 * renderer and the processor of derafu/form, and visitors that come and go.
 *
 * A visitor that never had a session gets one when the form is shown (writing
 * the secret of the token is what creates it), and its token is the only one
 * that its forms accept.
 */
#[CoversClass(SessionCsrfTokenManager::class)]
#[CoversClass(CsrfSessionMiddleware::class)]
final class CsrfFlowTest extends TestCase
{
    private InMemorySessionPersistence $persistence;

    private SessionCsrfTokenManager $manager;

    protected function setUp(): void
    {
        $this->persistence = new InMemorySessionPersistence();
        $this->manager = new SessionCsrfTokenManager();
    }

    /**
     * @param array<string, mixed> $options
     */
    private function form(array $options = []): Form
    {
        return Form::fromArray([
            'schema' => [
                'name' => 'contact',
                'type' => 'object',
                'properties' => ['email' => ['type' => 'string', 'title' => 'Email']],
            ],
            'uischema' => [
                'type' => 'VerticalLayout',
                'elements' => [['type' => 'Control', 'scope' => '#/properties/email']],
            ],
            'options' => $options,
        ]);
    }

    /**
     * Handles a request through the session middleware and the one of the
     * manager, with the callback as the last handler.
     */
    private function handle(ServerRequestInterface $request, callable $callback): ResponseInterface
    {
        $last = new class ($callback) implements RequestHandlerInterface {
            /**
             * @param callable(): void $callback
             */
            public function __construct(private readonly mixed $callback)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                ($this->callback)();

                return new EmptyResponse();
            }
        };

        $csrf = new CsrfSessionMiddleware($this->manager);
        $middle = new class ($csrf, $last) implements RequestHandlerInterface {
            public function __construct(
                private readonly CsrfSessionMiddleware $csrf,
                private readonly RequestHandlerInterface $last
            ) {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return $this->csrf->process($request, $this->last);
            }
        };

        return (new SessionMiddleware($this->persistence))->process($request, $middle);
    }

    /**
     * A visitor that asks for the form.
     *
     * @return array{token: ?string, sid: ?string}
     */
    private function show(?string $sid = null, bool $protected = true): array
    {
        $renderer = FormRendererFactory::create(['csrf_token_manager' => $this->manager]);
        $html = '';

        $response = $this->handle(
            $this->request($sid),
            function () use ($renderer, &$html, $protected): void {
                $html = $renderer->render($this->form(['csrf_protection' => $protected]));
            }
        );

        preg_match('/name="' . preg_quote(FormInterface::DEFAULT_CSRF_FIELD_NAME, '/') . '" value="([^"]+)"/', $html, $matches);

        return [
            'token' => $matches[1] ?? null,
            'sid' => $response->getHeaderLine('X-Session-Id') ?: null,
        ];
    }

    /**
     * A visitor that sends the form.
     *
     * @param array<string, string> $body
     */
    private function send(?string $sid, array $body): ProcessResultInterface
    {
        $manager = $this->manager;
        $result = null;

        $this->handle($this->request($sid, $body), function () use ($manager, $body, &$result): void {
            $processor = new FormDataProcessor(
                new FormRulesResolver(),
                (new ProcessorFactory())->create(),
                csrfTokenManager: $manager
            );
            $result = $processor->process($this->form(), $body);
        });

        $this->assertInstanceOf(ProcessResultInterface::class, $result);

        return $result;
    }

    /**
     * @param array<string, string>|null $body
     */
    private function request(?string $sid, ?array $body = null): ServerRequestInterface
    {
        $request = (new ServerRequest())->withCookieParams($sid !== null ? ['sid' => $sid] : []);

        return $body === null ? $request : $request->withParsedBody($body);
    }

    #[Test]
    public function aVisitorWithoutSessionGetsOneWithTheFormAndItsTokenIsValid(): void
    {
        $shown = $this->show();

        $this->assertNotNull($shown['token']);
        $this->assertNotNull($shown['sid'], 'The session was not created.');

        $result = $this->send($shown['sid'], ['email' => 'ana@example.com', FormInterface::CSRF_FIELD => $shown['token']]);

        $this->assertTrue($result->isValid());
        $this->assertSame(['email' => 'ana@example.com'], $result->getProcessedData());
    }

    #[Test]
    public function theFormSentWithoutTheTokenIsNotValid(): void
    {
        $shown = $this->show();

        $result = $this->send($shown['sid'], ['email' => 'ana@example.com']);

        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getFormErrors());
    }

    #[Test]
    public function theTokenOfAnotherVisitorIsNotValid(): void
    {
        $ana = $this->show();
        $eve = $this->show();
        $this->assertIsString($ana['token']);

        $result = $this->send($eve['sid'], ['email' => 'eve@example.com', FormInterface::CSRF_FIELD => $ana['token']]);

        $this->assertFalse($result->isValid());
    }

    #[Test]
    public function aFormSentWithoutSessionIsNotValidWhateverTheToken(): void
    {
        $shown = $this->show();

        $this->assertIsString($shown['token']);

        $result = $this->send(null, ['email' => 'ana@example.com', FormInterface::CSRF_FIELD => $shown['token']]);

        $this->assertFalse($result->isValid());
    }

    #[Test]
    public function aVisitorThatComesBackGetsAnotherTokenAndBothAreValid(): void
    {
        $first = $this->show();
        $second = $this->show($first['sid']);

        $this->assertIsString($first['token']);
        $this->assertIsString($second['token']);
        $this->assertNotSame($first['token'], $second['token']);
        $this->assertNull($second['sid'], 'A session that did not change must not be set again.');

        foreach ([$first['token'], $second['token']] as $token) {
            $this->assertTrue($this->send($first['sid'], ['email' => 'ana@example.com', FormInterface::CSRF_FIELD => $token])->isValid());
        }
    }

    #[Test]
    public function aFormThatIsNotProtectedDoesNotCreateASession(): void
    {
        $shown = $this->show(protected: false);

        $this->assertNull($shown['token']);
        $this->assertNull($shown['sid']);
        $this->assertSame([], $this->persistence->store);
    }
}
