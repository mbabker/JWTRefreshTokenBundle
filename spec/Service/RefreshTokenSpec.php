<?php

namespace spec\Gesdinet\JWTRefreshTokenBundle\Service;

use Gesdinet\JWTRefreshTokenBundle\Exception\InvalidRefreshTokenException;
use Gesdinet\JWTRefreshTokenBundle\Model\RefreshTokenInterface;
use Gesdinet\JWTRefreshTokenBundle\Model\RefreshTokenManagerInterface;
use Gesdinet\JWTRefreshTokenBundle\Security\Authenticator\RefreshTokenAuthenticator;
use Gesdinet\JWTRefreshTokenBundle\Security\Exception\MissingTokenException;
use Gesdinet\JWTRefreshTokenBundle\Security\Provider\RefreshTokenProvider;
use Gesdinet\JWTRefreshTokenBundle\Service\RefreshToken;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationFailureHandler;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Http\Authentication\AuthenticationSuccessHandler;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * @require Symfony\Component\Security\Guard\Token\PostAuthenticationGuardToken
 */
class RefreshTokenSpec extends ObjectBehavior
{
    private const TTL = 2592000;
    private const TTL_UPDATE = false;
    private const PROVIDER_KEY = 'testkey';

    public function let(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationSuccessHandler $successHandler,
        AuthenticationFailureHandler $failureHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        EventDispatcherInterface $eventDispatcher
    ) {
        $eventDispatcher->dispatch(Argument::any(), Argument::any())->willReturn(Argument::any());

        $this->beConstructedWith($authenticator, $provider, $successHandler, $failureHandler, $refreshTokenManager, self::TTL, self::PROVIDER_KEY, self::TTL_UPDATE, $eventDispatcher);
    }

    public function it_is_initializable()
    {
        $this->shouldBeAnInstanceOf(RefreshToken::class);
    }

    public function it_refreshes_the_token(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationSuccessHandlerInterface $successHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        Request $request,
        PostAuthenticationGuardToken $postAuthenticationGuardToken,
        RefreshTokenInterface $refreshToken,
        Response $response
    ) {
        $username = 'username';
        $password = 'password';

        if (class_exists(InMemoryUser::class)) {
            $user = new InMemoryUser($username, $password);
        } else {
            $user = new User($username, $password);
        }

        $credentials = ['token' => '1234'];

        $authenticator->getCredentials($request)->willReturn($credentials);
        $authenticator->getUser($credentials, $provider)->willReturn($user);
        $authenticator->createAuthenticatedToken($user, self::PROVIDER_KEY)->willReturn($postAuthenticationGuardToken);

        $refreshTokenManager->get($credentials['token'])->willReturn($refreshToken);
        $refreshToken->isValid()->willReturn(true);

        $successHandler->onAuthenticationSuccess($request, $postAuthenticationGuardToken)->willReturn($response);

        $this->refresh($request)->shouldReturn($response);
    }

    public function it_refreshes_the_token_and_updates_the_ttl(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationSuccessHandler $successHandler,
        AuthenticationFailureHandler $failureHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        EventDispatcherInterface $eventDispatcher,
        Request $request,
        PostAuthenticationGuardToken $postAuthenticationGuardToken,
        RefreshTokenInterface $refreshToken,
        Response $response
    ) {
        $this->beConstructedWith($authenticator, $provider, $successHandler, $failureHandler, $refreshTokenManager, self::TTL, self::PROVIDER_KEY, true, $eventDispatcher);

        $username = 'username';
        $password = 'password';

        if (class_exists(InMemoryUser::class)) {
            $user = new InMemoryUser($username, $password);
        } else {
            $user = new User($username, $password);
        }

        $credentials = ['token' => '1234'];

        $authenticator->getCredentials($request)->willReturn($credentials);
        $authenticator->getUser($credentials, $provider)->willReturn($user);
        $authenticator->createAuthenticatedToken($user, self::PROVIDER_KEY)->willReturn($postAuthenticationGuardToken);

        $refreshTokenManager->get($credentials['token'])->willReturn($refreshToken);
        $refreshToken->isValid()->willReturn(true);

        $refreshToken->setValid(Argument::type(\DateTimeInterface::class))->shouldBeCalled();
        $refreshTokenManager->save($refreshToken)->shouldBeCalled();

        $successHandler->onAuthenticationSuccess($request, $postAuthenticationGuardToken)->willReturn($response);

        $this->refresh($request)->shouldReturn($response);
    }

    public function it_does_not_refresh_the_token_when_the_authenticator_raises_an_exception(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationFailureHandler $failureHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        Request $request,
        PostAuthenticationGuardToken $postAuthenticationGuardToken,
        Response $response
    ) {
        $credentials = ['token' => '1234'];

        $exception = new MissingTokenException('Test');

        $authenticator->getCredentials($request)->willReturn($credentials);
        $authenticator->getUser($credentials, $provider)->willThrow($exception);

        $failureHandler->onAuthenticationFailure($request, $exception)->willReturn($response);

        $this->refresh($request)->shouldReturn($response);
    }

    public function it_does_not_refresh_the_token_when_the_refresh_token_cannot_be_found(
        RefreshTokenAuthenticator $authenticator,
        RefreshTokenProvider $provider,
        AuthenticationFailureHandler $failureHandler,
        RefreshTokenManagerInterface $refreshTokenManager,
        Request $request,
        PostAuthenticationGuardToken $postAuthenticationGuardToken,
        Response $response
    ) {
        $username = 'username';
        $password = 'password';

        if (class_exists(InMemoryUser::class)) {
            $user = new InMemoryUser($username, $password);
        } else {
            $user = new User($username, $password);
        }

        $credentials = ['token' => '1234'];

        $authenticator->getCredentials($request)->willReturn($credentials);
        $authenticator->getUser($credentials, $provider)->willReturn($user);
        $authenticator->createAuthenticatedToken($user, self::PROVIDER_KEY)->willReturn($postAuthenticationGuardToken);

        $refreshTokenManager->get($credentials['token'])->willReturn(null);

        $failureHandler->onAuthenticationFailure($request, Argument::type(InvalidRefreshTokenException::class))->willReturn($response);

        $this->refresh($request)->shouldReturn($response);
    }
}
