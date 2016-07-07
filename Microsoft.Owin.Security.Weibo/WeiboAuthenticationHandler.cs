using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Weibo.Provider;

namespace Microsoft.Owin.Security.Weibo
{
    internal class WeiboAuthenticationHandler : AuthenticationHandler<WeiboAuthenticationOptions>
    {
        private const string TokenUrlFormater = "https://api.weibo.com/oauth2/access_token?client_id={0}&client_secret={1}&redirect_uri={2}&code={3}&grant_type=authorization_code";
        private const string UserInfoFormater = "https://api.weibo.com/2/users/show.json?access_token={0}&uid={1}";
        private const string LoginRedirectUrl = "https://api.weibo.com/oauth2/authorize?client_id={0}&redirect_uri={1}&state={2}&response_type=code";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
        private const string NameIdentifierClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public WeiboAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this._httpClient = httpClient;
            this._logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            AuthenticationTicket authenticationTicket;

            IReadableStringCollection query = this.Request.Query;
            properties = this.UnpackStateParameter(query);
            var code = string.Empty;
            IList<string> values = query.GetValues("code");
            if (values != null && values.Count == 1)
                code = values[0];
            if (string.IsNullOrEmpty(code))
            {
                authenticationTicket = new AuthenticationTicket(null, properties);
                return authenticationTicket;
            }

            if (properties == null)
            {
                authenticationTicket = null;
            }
            else if (!this.ValidateCorrelationId(properties, this._logger))
            {
                authenticationTicket = new AuthenticationTicket(null, properties);
            }
            else
            {
                var url = string.Format(TokenUrlFormater, Uri.EscapeDataString(this.Options.AppId), Uri.EscapeDataString(this.Options.AppKey), Uri.EscapeDataString(code), Uri.EscapeDataString("http://" + this.Request.Host));
                HttpResponseMessage tokenResponse = await this._httpClient.PostAsync(url, new StringContent(""), this.Request.CallCancelled);
                tokenResponse.EnsureSuccessStatusCode();
                var accessTokenReturnValue = await tokenResponse.Content.ReadAsStringAsync();
                const string accesstokenpa = "\"access_token\":\"(.+?)\"";
                var accesstoken = Regex.Match(accessTokenReturnValue, accesstokenpa).Groups[1].Value;
                const string uidpa = "\"uid\":\"(.+?)\"";
                var openid = Regex.Match(accessTokenReturnValue, uidpa).Groups[1].Value;
                var nameurl = string.Format(UserInfoFormater, Uri.EscapeDataString(accesstoken), Uri.EscapeDataString(openid));
                var nameResponse = await this._httpClient.GetAsync(nameurl, this.Request.CallCancelled);
                nameResponse.EnsureSuccessStatusCode();
                var nametxt = await nameResponse.Content.ReadAsStringAsync();
                const string namepa = "\"name\":\"(.+?)\"";
                var name = Regex.Match(nametxt, namepa).Groups[1].Value;
                var context = new WeiboAuthenticatedContext(this.Context, accesstoken, openid, name);
                var identity = new ClaimsIdentity(this.Options.AuthenticationType);
                if (!string.IsNullOrEmpty(context.OpenId))
                {
                    identity.AddClaim(new Claim(NameIdentifierClaimType, context.OpenId, XmlSchemaString, this.Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    identity.AddClaim(new Claim(NameClaimType, context.Name, XmlSchemaString, this.Options.AuthenticationType));
                }
                await this.Options.Provider.Authenticated(context);
                authenticationTicket = new AuthenticationTicket(identity, properties);
            }
            return authenticationTicket;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (this.Response.StatusCode != 401)
                return Task.FromResult((object)null);
            AuthenticationResponseChallenge responseChallenge = this.Helper.LookupChallenge(this.Options.AuthenticationType, this.Options.AuthenticationMode);
            if (responseChallenge != null)
            {
                var stringToEscape = this.Request.Scheme + Uri.SchemeDelimiter + this.Request.Host;
                AuthenticationProperties properties = responseChallenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                    properties.RedirectUri = string.Concat(new object[] { stringToEscape, this.Request.PathBase, this.Request.Path, this.Request.QueryString });
                this.GenerateCorrelationId(properties);
                var protector = this.Options.StateDataFormat.Protect(properties);
                var url = string.Format(LoginRedirectUrl, Uri.EscapeDataString(this.Options.AppId), Uri.EscapeDataString(GenerateRedirectUri()), Uri.EscapeDataString(protector));
                this.Response.StatusCode = 302;
                this.Response.Headers.Set("Location", url);
            }
            return base.ApplyResponseChallengeAsync();
        }

        public override async Task<bool> InvokeAsync()
        {
            bool flag;
            if (!string.IsNullOrEmpty(this.Options.CallbackPath) && this.Options.CallbackPath == this.Request.Path.ToString())
                flag = await this.InvokeReturnPathAsync();
            else
                flag = false;
            return flag;
        }

        public async Task<bool> InvokeReturnPathAsync()
        {
            AuthenticationTicket model = await this.AuthenticateAsync();
            bool flag;
            if (model == null)
            {
                this.Response.StatusCode = 500;
                flag = true;
            }
            else
            {
                var context = new WeiboReturnEndpointContext(this.Context, model)
                {
                    SignInAsAuthenticationType = this.Options.SignInAsAuthenticationType,
                    RedirectUri = model.Properties.RedirectUri
                };
                model.Properties.RedirectUri = null;
                await this.Options.Provider.ReturnEndpoint(context);
                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity claimsIdentity = context.Identity;
                    if (!string.Equals(claimsIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                        claimsIdentity = new ClaimsIdentity(claimsIdentity.Claims, context.SignInAsAuthenticationType, claimsIdentity.NameClaimType, claimsIdentity.RoleClaimType);
                    this.Context.Authentication.SignIn(context.Properties, new ClaimsIdentity[1] { claimsIdentity });
                }
                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    if (context.Identity == null)
                        context.RedirectUri = WebUtilities.AddQueryString(context.RedirectUri, "error", "access_denied");
                    this.Response.Redirect(context.RedirectUri);
                    context.RequestCompleted();
                }
                flag = context.IsRequestCompleted;
            }
            return flag;
        }

        private static string GetStateParameter(IReadableStringCollection query)
        {
            IList<string> values = query.GetValues("state");
            if (values != null && values.Count == 1)
                return values[0];
            else
                return null;
        }

        private AuthenticationProperties UnpackStateParameter(IReadableStringCollection query)
        {
            var stateParameter = GetStateParameter(query);
            if (stateParameter != null)
                return this.Options.StateDataFormat.Unprotect(stateParameter);
            else
                return null;
        }

        private string GenerateRedirectUri()
        {
            return this.Request.Scheme + "://" + this.Request.Host + this.RequestPathBase + this.Options.CallbackPath;
        }
    }
}