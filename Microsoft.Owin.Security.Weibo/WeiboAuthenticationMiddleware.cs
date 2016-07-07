using System;
using System.Net.Http;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Weibo.Provider;
using Owin;

namespace Microsoft.Owin.Security.Weibo
{
    public class WeiboAuthenticationMiddleware : AuthenticationMiddleware<WeiboAuthenticationOptions>
    {
        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;
        public WeiboAuthenticationMiddleware(OwinMiddleware next,IAppBuilder app, WeiboAuthenticationOptions options)
            : base(next, options)
        {
            _logger = app.CreateLogger<WeiboAuthenticationOptions>();
            if (Options.Provider == null)
            {
                Options.Provider = new WeiboAuthenticationProvider();
            }
            if (Options.StateDataFormat == null)
            {
                var dataProtecter = app.CreateDataProtector(typeof(WeiboAuthenticationMiddleware).FullName,Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtecter);
            }
            _httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        protected override AuthenticationHandler<WeiboAuthenticationOptions> CreateHandler()
        {
            return new WeiboAuthenticationHandler(this._httpClient, this._logger);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(WeiboAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackChannelHttpHandler ?? new WebRequestHandler();
            if (options.BackchannelCertificateValidator != null)
            {
                WebRequestHandler webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }
            return handler;
        }
    }
}