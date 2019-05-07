using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using dk.nita.saml20;
using dk.nita.saml20.Bindings;
using Microsoft.AspNetCore.Http;
using Saml2.Authentication.Core.Bindings.SignatureProviders;
using Saml2.Authentication.Core.Extensions;

namespace Saml2.Authentication.Core.Bindings
{
    /// <summary>
    ///     Handles the creation of redirect locations when using the HTTP redirect binding, which is outlined in [SAMLBind]
    ///     section 3.4.
    /// </summary>
    internal class HttpRedirectBinding : IHttpRedirectBinding
    {
        private const string SamlResponseQueryKey = "SamlResponse";

        private const string SamlRequestQueryKey = "SAMLRequest";

        private const string SamlRelayStateQueryKey = "RelayState";

        private readonly ISignatureProviderFactory _signatureProviderFactory;

        public HttpRedirectBinding(ISignatureProviderFactory signatureProviderFactory)
        {
            _signatureProviderFactory = signatureProviderFactory;
        }

        public bool IsValid(HttpRequest request)
        {
            if (request == null)
                return false;

            if (request.Method == HttpMethods.Get)
                return request.Query.ContainsKey(SamlRequestQueryKey) ||
                       request.Query.ContainsKey(SamlResponseQueryKey);

            if (request.Method != HttpMethods.Post)
                return false;

            var form = request.Form;
            return form != null && form.ContainsKey(SamlResponseQueryKey);
        }

        public bool IsLogoutRequest(HttpRequest request)
        {
            if (request == null)
                return false;

            if (request.Method == HttpMethods.Get)
                return request.Query.ContainsKey(SamlRequestQueryKey);

            if (request.Method != HttpMethods.Post)
                return false;

            var form = request.Form;
            return form != null && form.ContainsKey(SamlRequestQueryKey);
        }

        public Saml2Response GetResponse(HttpRequest request)
        {
            if (request.Method == HttpMethods.Get)
                return new Saml2Response
                {
                    Response = request.Query[SamlResponseQueryKey],
                    RelayState = request.Query[SamlRelayStateQueryKey].ToString()?.DeflateDecompress()
                };

            if (request.Method != HttpMethods.Post)
                return null;

            var form = request.Form;
            if (form == null)
                return null;

            return new Saml2Response
            {
                Response = form[SamlResponseQueryKey],
                RelayState = form[SamlRelayStateQueryKey].ToString()?.DeflateDecompress()
            };
        }

        public string GetCompressedRelayState(HttpRequest request)
        {
            if (request.Method == HttpMethods.Get)
                return request.Query[SamlRelayStateQueryKey].ToString();

            if (request.Method != HttpMethods.Post)
                return null;

            var form = request.Form;

            return form?[SamlRelayStateQueryKey].ToString();
        }

        public string BuildAuthnRequestUrl(Saml2AuthnRequest saml2AuthnRequest, AsymmetricAlgorithm signingKey,
            string hashingAlgorithm, string relayState)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildAuthnRequestUrl] => saml2AuthnRequest: "   + saml2AuthnRequest);
            System.Console.WriteLine("[HttpRedirectBinding][BuildAuthnRequestUrl] => hashingAlgorithm: "    + hashingAlgorithm);
            System.Console.WriteLine("[HttpRedirectBinding][BuildAuthnRequestUrl] => relayState: "          + relayState);

            var request = saml2AuthnRequest.GetXml().OuterXml;

            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildAuthnRequestUrl] => request: " + request);
            System.Console.WriteLine("");

            return BuildRequestUrl(signingKey, hashingAlgorithm, relayState, request, saml2AuthnRequest.Destination);
        }

        public string BuildLogoutRequestUrl(Saml2LogoutRequest saml2LogoutRequest, AsymmetricAlgorithm signingKey,
            string hashingAlgorithm, string relayState)
        {
            var request = saml2LogoutRequest.GetXml().OuterXml;
            return BuildRequestUrl(signingKey, hashingAlgorithm, relayState, request, saml2LogoutRequest.Destination);
        }

        public string BuildLogoutResponseUrl(dk.nita.saml20.Saml2LogoutResponse logoutResponse,
            AsymmetricAlgorithm signingKey, string hashingAlgorithm, string relayState)
        {
            var response = logoutResponse.GetXml().OuterXml;
            return BuildRequestUrl(signingKey, hashingAlgorithm, relayState, response, logoutResponse.Destination);
        }

        public string GetLogoutResponseMessage(Uri uri, AsymmetricAlgorithm key)
        {
            var parser = new HttpRedirectBindingParser(uri);
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (!parser.IsSigned)
                throw new InvalidOperationException("Query is not signed, so there is no signature to verify.");

            // Validates the signature using the public part of the asymmetric key given as parameter.
            var signatureProvider =
                _signatureProviderFactory.CreateFromAlgorithmUri(key.GetType(), parser.SignatureAlgorithm);
            if (!signatureProvider.VerifySignature(key, Encoding.UTF8.GetBytes(parser.SignedQuery),
                parser.DecodeSignature()))
                throw new InvalidOperationException("Logout request signature verification failed");

            return parser.Message;
        }

        public Saml2LogoutResponse GetLogoutReponse(Uri uri, AsymmetricAlgorithm key)
        {
            var response = new Saml2LogoutResponse();
            var parser = new HttpRedirectBindingParser(uri);
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            response.OriginalLogoutRequest = parser.LogoutRequest;

            if (!parser.IsSigned)
                response.StatusCode = Saml2Constants.StatusCodes.RequestDenied;

            // Validates the signature using the public part of the asymmetric key given as parameter.
            var signatureProvider =
                _signatureProviderFactory.CreateFromAlgorithmUri(key.GetType(), parser.SignatureAlgorithm);
            if (!signatureProvider.VerifySignature(key, Encoding.UTF8.GetBytes(parser.SignedQuery),
                parser.DecodeSignature()))
                response.StatusCode = Saml2Constants.StatusCodes.RequestDenied;

            response.StatusCode = Saml2Constants.StatusCodes.Success;
            return response;
        }

        /// <summary>
        ///     If an asymmetric key has been specified, sign the request.
        /// </summary>
        private void AddSignature(StringBuilder result, AsymmetricAlgorithm signingKey,
            ShaHashingAlgorithm hashingAlgorithm)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => result: " + result);
            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => signingKey: " + signingKey);
            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => hashingAlgorithm: " + hashingAlgorithm);
            System.Console.WriteLine("");

            if (signingKey == null)
                return;

            result.Append(string.Format("&{0}=", HttpRedirectBindingConstants.SigAlg));
            //System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => result: " + result);

            var signingProvider =
                _signatureProviderFactory.CreateFromAlgorithmName(signingKey.GetType(), hashingAlgorithm);

            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => signingProvider: " + signingProvider);

            var urlEncoded = signingProvider.SignatureUri.UrlEncode();

            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => urlEncoded: " + urlEncoded);

            result.Append(urlEncoded.UpperCaseUrlEncode());
            //System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => result: " + result);

            // Calculate the signature of the URL as described in [SAMLBind] section 3.4.4.1.            
            var signature = signingProvider.SignData(signingKey, Encoding.UTF8.GetBytes(result.ToString()));

            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => signature: " + signature);

            result.AppendFormat("&{0}=", HttpRedirectBindingConstants.Signature);
            result.Append(HttpUtility.UrlEncode(Convert.ToBase64String(signature)));

            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][AddSignature] => result: " + result);
            System.Console.WriteLine("");
        }

        private string BuildRequestUrl(AsymmetricAlgorithm signingKey, string hashingAlgorithm, string relayState,
            string request, string destination)
        {
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => signingKey: " + signingKey);
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => hashingAlgorithm: " + hashingAlgorithm);
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => relayState: " + relayState);
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => request: " + request);
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => destination: " + destination);
            System.Console.WriteLine("");

            var shaHashingAlgorithm = _signatureProviderFactory.ValidateShaHashingAlgorithm(hashingAlgorithm);

            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => shaHashingAlgorithm: " + shaHashingAlgorithm);

            // Check if the key is of a supported type. [SAMLBind] sect. 3.4.4.1 specifies this.
            if (!(signingKey is RSA || signingKey is DSA || signingKey == null))
                throw new ArgumentException("Signing key must be an instance of either RSA or DSA.");

            var result = new StringBuilder();
            result.AddMessageParameter(request, null);
            result.AddRelayState(request, relayState);
            AddSignature(result, signingKey, shaHashingAlgorithm);

            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => destination: " + destination);
            System.Console.WriteLine("");
            System.Console.WriteLine("[HttpRedirectBinding][BuildRequestUrl] => result: " + result);
            System.Console.WriteLine("");

            return $"{destination}?{result}";
        }
    }
}