using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Weibo.Provider
{
    public class WeiboAuthenticationProvider : IWeiboAuthenticationProvider
    {
        public WeiboAuthenticationProvider()
        {
            this.OnAuthenticated = (context => Task.FromResult((object)null));
            this.OnReturnEndpoint = (context => Task.FromResult((object)null));
        }

        public Func<WeiboAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<WeiboReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(WeiboAuthenticatedContext context)
        {
            return this.OnAuthenticated(context);
        }

        public Task ReturnEndpoint(WeiboReturnEndpointContext context)
        {
            return this.OnReturnEndpoint(context);
        }
    }
}