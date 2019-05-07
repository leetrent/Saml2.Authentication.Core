using dk.nita.saml20;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Saml2.Authentication.Core.Bindings;
using Saml2.Authentication.Core.Extensions;
using Saml2.Authentication.Core.Factories;
using Saml2.Authentication.Core.Options;
using Saml2.Authentication.Core.Services;
using Saml2.Authentication.Core.Session;
using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Saml2.Authentication.Core.Authentication
{
    public class Saml2Handler : AuthenticationHandler<Saml2Options>, IAuthenticationRequestHandler,
        IAuthenticationSignOutHandler
    {
        private const string AuthnRequestIdKey = "AuthnRequestId";
        private const string LogoutRequestIdKey = "LogoutRequestId";

        private readonly ISaml2ClaimFactory _claimFactory;
        private readonly ISessionStore _sessionStore;
        private readonly IHttpArtifactBinding _httpArtifactBinding;
        private readonly IHttpRedirectBinding _httpRedirectBinding;
        private readonly ILogger _logger;
        private readonly ISamlService _samlService;

        public Saml2Handler(
            IOptionsMonitor<Saml2Options> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            ISamlService samlService,
            IHttpRedirectBinding httpRedirectBinding,
            IHttpArtifactBinding httpArtifactBinding,
            ISaml2ClaimFactory claimFactory,
            ISessionStore sessionStore)
            : base(options, logger, encoder, clock)
        {
            _logger = logger.CreateLogger(typeof(Saml2Handler));
            _samlService = samlService;
            _httpRedirectBinding = httpRedirectBinding;
            _httpArtifactBinding = httpArtifactBinding;
            _claimFactory = claimFactory;
            _sessionStore = sessionStore;
        }

        public async Task<bool> HandleRequestAsync()
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleRequestAsync]=>");

            if (await HandleSignIn())
            {
                return true;
            }

            if (await HandleSignOut())
            {
                return true;
            }

            return await HandleHttpArtifact();
        }

        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][SignOutAsync]=>");

            _logger.LogDebug($"Entering {nameof(SignOutAsync)}", properties);

            var logoutRequestId = CreateUniqueId();
            properties = properties ?? new AuthenticationProperties();

            properties.Items.Add(LogoutRequestIdKey, logoutRequestId);
            await _sessionStore.SaveAsync<AuthenticationProperties>(properties);

            var sessionIndex = Context.User.GetSessionIndex();
            var subject = Context.User.GetSubject();

            var logoutRequestUrl = _samlService.GetLogoutRequest(logoutRequestId, sessionIndex, subject, null);

            _logger.LogDebug(
                $"Method={nameof(SignOutAsync)}. Redirecting to saml identity provider for SLO. Url={logoutRequestUrl}");

            Context.Response.Redirect(logoutRequestUrl, true);
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleAuthenticateAsync]=>");

            return Task.FromResult(AuthenticateResult.Fail("Not supported"));
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleChallengeAsync] =>");

            _logger.LogDebug($"Entering {nameof(HandleChallengeAsync)}", properties);

            properties = properties ?? new AuthenticationProperties();

            var authnRequestId = CreateUniqueId();
            properties.Items.Add(AuthnRequestIdKey, authnRequestId);


            System.Console.WriteLine("[Saml2Handler][HandleChallengeAsync] => AuthnRequestIdKey: " + AuthnRequestIdKey);
            System.Console.WriteLine("[Saml2Handler][HandleChallengeAsync] => authnRequestId: " + authnRequestId);

            await _sessionStore.SaveAsync<AuthenticationProperties>(properties);
            var requestUrl = _samlService.GetAuthnRequest(authnRequestId, null,
                $"{Request.GetBaseUrl()}/{Options.AssertionConsumerServiceUrl}");


            System.Console.WriteLine("[Saml2Handler][HandleChallengeAsync] => requestUrl: " + requestUrl);

            System.Console.WriteLine("");
            _logger.LogDebug($"Method={nameof(HandleChallengeAsync)}. Redirecting to saml identity provider for SSO. Url={requestUrl}");
            System.Console.WriteLine("");

            Context.Response.Redirect(requestUrl, true);
        }

        private async Task<bool> HandleSignOut()
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleSignOut] =>");
            System.Console.WriteLine("[Saml2Handler][HandleSignOut] => Options.SingleLogoutServiceUrl: '" + Options.SingleLogoutServiceUrl + "'");

            if (!Request.Path.Value.EndsWith(Options.SingleLogoutServiceUrl, StringComparison.OrdinalIgnoreCase)
                || !_httpRedirectBinding.IsValid(Context.Request))
            {
                System.Console.WriteLine("[Saml2Handler][HandleSignOut] => returning false");
                return false;
            }

            _logger.LogDebug($"Entering {nameof(HandleSignOut)}");

            var uri = new Uri(Context.Request.GetEncodedUrl());
            //idp initiated logout. TODO: BUG:Context.User and cookies are not populated
            if (_httpRedirectBinding.IsLogoutRequest(Context.Request))
            {
                var logoutResponse = _samlService.GetLogoutReponse(uri);
                if (logoutResponse.StatusCode != Saml2Constants.StatusCodes.Success ||
                    Context.User.Identity.IsAuthenticated)
                {
                    return false;
                }

                var relayState = _httpRedirectBinding.GetCompressedRelayState(Context.Request);
                var url = _samlService.GetLogoutResponseUrl(logoutResponse, relayState);
                await Context.SignOutAsync(Options.SignOutScheme, new AuthenticationProperties());

                Context.Response.Redirect(url, true);
                return true;
            }

            //sp initiated logout
            var properties = await _sessionStore.LoadAsync<AuthenticationProperties>() ?? new AuthenticationProperties();
            properties.Items.TryGetValue(LogoutRequestIdKey, out var initialLogoutRequestId);

            if (!_samlService.IsLogoutResponseValid(uri, initialLogoutRequestId))
            {
                return false;
            }

            await Context.SignOutAsync(Options.SignOutScheme, properties);

            await _sessionStore.RemoveAsync<AuthenticationProperties>();

            var redirectUrl = GetRedirectUrl(properties);

            _logger.LogDebug($"Method={nameof(HandleSignOut)}. Received and handled sp initiated logout response. Redirecting to {redirectUrl}");

            Context.Response.Redirect(redirectUrl, true);
            return true;
        }

        private async Task<bool> HandleSignIn()
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => Options.AssertionConsumerServiceUrl: '" + Options.AssertionConsumerServiceUrl + "'");
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => Request.Path.Value.................: '" + Request.Path.Value + "'");

            if (!Request.Path.Value.EndsWith(Options.AssertionConsumerServiceUrl, StringComparison.OrdinalIgnoreCase)
                || !_httpRedirectBinding.IsValid(Context.Request))
            {
                System.Console.WriteLine("[Saml2Handler][HandleSignIn] => returning false");
                return false;
            }

            _logger.LogDebug($"Entering {nameof(HandleSignIn)}");

            var properties = await _sessionStore.LoadAsync<AuthenticationProperties>() ?? new AuthenticationProperties();         
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => AuthenticationProperties: " + properties);

            properties.Items.TryGetValue(AuthnRequestIdKey, out var initialAuthnRequestId);
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => AuthnRequestIdKey: " + AuthnRequestIdKey);
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => initialAuthnRequestId: " + initialAuthnRequestId);

            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => Context.Request: " + Context.Request);
            var result = _httpRedirectBinding.GetResponse(Context.Request);
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => _httpRedirectBinding.GetResponse: " + result);

            var base64EncodedSamlResponse = result.Response;
            var assertion = _samlService.HandleHttpRedirectResponse(base64EncodedSamlResponse, initialAuthnRequestId);

            await SignIn(assertion, properties);

            await _sessionStore.RemoveAsync<AuthenticationProperties>();
            var redirectUrl = GetRedirectUrl(properties);
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => redirectUrl: " + redirectUrl);

            _logger.LogDebug(
                $"Method={nameof(HandleSignIn)}. Received and handled SSO redirect response. Redirecting to {redirectUrl}");

            Context.Response.Redirect(redirectUrl, true);
            System.Console.WriteLine("[Saml2Handler][HandleSignIn] => Returning true");
            return true;
        }

        private async Task<bool> HandleHttpArtifact()
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][HandleHttpArtifact] => Options.AssertionConsumerServiceUrl: '" + Options.AssertionConsumerServiceUrl + "'");
            System.Console.WriteLine("[Saml2Handler][HandleHttpArtifact] => Request.Path.Value.................: '" + Request.Path.Value + "'");

            if (!Request.Path.Value.EndsWith(Options.AssertionConsumerServiceUrl, StringComparison.OrdinalIgnoreCase)
                || !_httpArtifactBinding.IsValid(Context.Request))
            {
                System.Console.WriteLine("[Saml2Handler][HandleHttpArtifact] => returning false");
                return false;
            }

            _logger.LogDebug($"Entering {nameof(HandleHttpArtifact)}");
            
            var properties = await _sessionStore.LoadAsync<AuthenticationProperties>() ?? new AuthenticationProperties();
            properties.Items.TryGetValue(AuthnRequestIdKey, out string initialAuthnRequestId);

            System.Console.WriteLine("[Saml2Handler][HandleHttpArtifact] => AuthnRequestIdKey: " + AuthnRequestIdKey);
            System.Console.WriteLine("[Saml2Handler][HandleHttpArtifact] => initialAuthnRequestId: " + initialAuthnRequestId);

            var assertion = _samlService.HandleHttpArtifactResponse(Context.Request, initialAuthnRequestId);
            await SignIn(assertion, properties);

            await _sessionStore.RemoveAsync<AuthenticationProperties>();

            var redirectUrl = GetRedirectUrl(properties);

            _logger.LogDebug(
                $"Method={nameof(HandleHttpArtifact)}. Received and handled SSO artifact response. Redirecting to {redirectUrl}");

            Context.Response.Redirect(redirectUrl, true);
            return true;
        }

        private async Task SignIn(Saml2Assertion assertion, AuthenticationProperties authenticationProperties)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[Saml2Handler][SignIn] =>");

            var claims = _claimFactory.Create(assertion);
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);

            System.Console.WriteLine("[Saml2Handler][SignIn] => claims: " + claims);
            System.Console.WriteLine("[Saml2Handler][SignIn] => identity: " + identity);
            System.Console.WriteLine("[Saml2Handler][SignIn] => principal: " + principal);

            await Context.SignInAsync(Options.SignInScheme, principal, authenticationProperties);
        }

        private static string CreateUniqueId() => Convert.ToBase64String(Encoding.UTF8.GetBytes(Guid.NewGuid().ToString()));

        private string GetRedirectUrl(AuthenticationProperties authenticationProperties) => authenticationProperties
            .RedirectUri.IsNotNullOrEmpty()
            ? authenticationProperties.RedirectUri
            : Options.DefaultRedirectUrl;
    }
}