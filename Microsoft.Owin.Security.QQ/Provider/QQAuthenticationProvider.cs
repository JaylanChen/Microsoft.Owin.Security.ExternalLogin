using System;
using System.Threading.Tasks;

namespace Microsoft.Owin.Security.QQ.Provider
{
    public class QQAuthenticationProvider : IQQAuthenticationProvider
    {
        public QQAuthenticationProvider()
        {
            OnAuthenticated = (c) => Task.FromResult<QQAuthenticatedContext>(null);
            OnReturnEndpoint = (c) => Task.FromResult<QQReturnEndpointContext>(null);
        }

        public Func<QQAuthenticatedContext, Task> OnAuthenticated { get; set; }

        public Func<QQReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(QQAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(QQReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}
