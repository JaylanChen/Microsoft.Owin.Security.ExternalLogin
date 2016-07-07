using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.QQ.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.QQ
{
    internal class QQAuthenticationHandler : AuthenticationHandler<QQAuthenticationOptions>
    {
        private const string AuthorizationUrlFormater = "https://graph.qq.com/oauth2.0/authorize?client_id={0}&redirect_uri={1}&scope={2}&state={3}&response_type=code";
        private const string TokenUrl = "https://graph.qq.com/oauth2.0/token";
        private const string UserInfoUrlFormater = "https://openmobile.qq.com/user/get_simple_userinfo?access_token={0}&oauth_consumer_key={1}&openid={2}";
        private const string OpenIdUrlFormater = "https://graph.qq.com/oauth2.0/me?access_token={0}";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public QQAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath != null && string.Equals(Options.CallbackPath, Request.Path.Value, StringComparison.OrdinalIgnoreCase))
            {
                return await InvokeReturnPathAsync();
            }
            return false;
        }

        private async Task<bool> InvokeReturnPathAsync()
        {
            _logger.WriteVerbose("InvokeReturnPath");
            var model = await AuthenticateAsync();
            var context = new QQReturnEndpointContext(Context, model)
            {
                SignInAsAuthenticationType = Options.SignInAsAuthenticationType,
                RedirectUri = model.Properties.RedirectUri
            };
            model.Properties.RedirectUri = null;
            await Options.Provider.ReturnEndpoint(context);
            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity signInIdentity = context.Identity;
                if (!string.Equals(signInIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    signInIdentity = new ClaimsIdentity(signInIdentity.Claims, context.SignInAsAuthenticationType, signInIdentity.NameClaimType, signInIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, signInIdentity);
            }
            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                Response.Redirect(context.RedirectUri);
                context.RequestCompleted();
            }
            return context.IsRequestCompleted;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            _logger.WriteVerbose("AuthenticateCore");
            AuthenticationProperties properties = null;
            try
            {
                string code = null;
                string state = null;
                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }
                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null)
                {
                    return null;
                }
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }
                var tokenRequestParameters = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", Options.AppId),
                    new KeyValuePair<string, string>("client_secret", Options.AppSecret),
                    new KeyValuePair<string, string>("redirect_uri", GenerateRedirectUri()),
                    new KeyValuePair<string, string>("code", code),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                };
                FormUrlEncodedContent requestContent = new FormUrlEncodedContent(tokenRequestParameters);
                HttpResponseMessage response = await _httpClient.PostAsync(TokenUrl, requestContent, Request.CallCancelled);
                response.EnsureSuccessStatusCode();
                var oauthTokenResponse = await response.Content.ReadAsStringAsync();
                var tokenDict = QueryStringToDict(oauthTokenResponse);
                string accessToken;
                if (tokenDict.ContainsKey("access_token"))
                {
                    accessToken = tokenDict["access_token"];
                }
                else
                {
                    _logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }
                var openIdUri = string.Format(OpenIdUrlFormater, Uri.EscapeDataString(accessToken));
                HttpResponseMessage openIdResponse = await _httpClient.GetAsync(openIdUri, Request.CallCancelled);
                openIdResponse.EnsureSuccessStatusCode();
                var openIdString = await openIdResponse.Content.ReadAsStringAsync();
                openIdString = ExtractOpenIdCallbackBody(openIdString);
                var openIdInfo = JObject.Parse(openIdString);
                var clientId = openIdInfo["client_id"].Value<string>();
                var openId = openIdInfo["openid"].Value<string>();
                var userInfoUri = string.Format(UserInfoUrlFormater, Uri.EscapeDataString(accessToken), Uri.EscapeDataString(clientId), Uri.EscapeDataString(openId));
                var userInfoResponse = await _httpClient.GetAsync(userInfoUri, Request.CallCancelled);
                userInfoResponse.EnsureSuccessStatusCode();
                var userInfoString = await userInfoResponse.Content.ReadAsStringAsync();
                var userInfo = JObject.Parse(userInfoString);
                var context = new QQAuthenticatedContext(Context, openId, userInfo, accessToken);
                context.Identity = new ClaimsIdentity(new[]{
                    new Claim(ClaimTypes.NameIdentifier, context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:qqconnect:id", context.Id,XmlSchemaString,Options.AuthenticationType),
                    new Claim("urn:qqconnect:name", context.Name,XmlSchemaString,Options.AuthenticationType),
                });
                await Options.Provider.Authenticated(context);
                context.Properties = properties;
                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            _logger.WriteVerbose("ApplyResponseChallenge");
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge != null)
            {
                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var currentQueryString = Request.QueryString.Value;
                var currentUri = string.IsNullOrEmpty(currentQueryString) ? requestPrefix + Request.PathBase + Request.Path : requestPrefix + Request.PathBase + Request.Path + "?" + currentQueryString;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;
                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }
                GenerateCorrelationId(properties);
                var scope = string.Join(",", Options.Scope);
                var state = Options.StateDataFormat.Protect(properties);
                var authorizationUrl = string.Format(AuthorizationUrlFormater, Uri.EscapeDataString(Options.AppId ?? string.Empty), Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(scope), Uri.EscapeDataString(state));
                Response.Redirect(authorizationUrl);
            }
            return Task.FromResult<object>(null);
        }

        private string GenerateRedirectUri()
        {
            var requestPrefix = Request.Scheme + "://" + Request.Host;
            var redirectUri = requestPrefix + RequestPathBase + Options.CallbackPath;
            return redirectUri;
        }

        private static string ExtractOpenIdCallbackBody(string callbackString)
        {
            var leftBracketIndex = callbackString.IndexOf('{');
            var rightBracketIndex = callbackString.IndexOf('}');
            if (leftBracketIndex >= 0 && rightBracketIndex >= 0)
            {
                return callbackString.Substring(leftBracketIndex, rightBracketIndex - leftBracketIndex + 1).Trim();
            }
            return callbackString;
        }

        private static IDictionary<string, string> QueryStringToDict(string str)
        {
            var strArr = str.Split('&');
            var dict = new Dictionary<string, string>(strArr.Length);
            foreach (var s in strArr)
            {
                var equalSymbolIndex = s.IndexOf('=');
                if (equalSymbolIndex > 0 && equalSymbolIndex < s.Length - 1)
                {
                    dict.Add(s.Substring(0, equalSymbolIndex), s.Substring(equalSymbolIndex + 1, s.Length - equalSymbolIndex - 1));
                }
            }
            return dict;
        }
    }
}
