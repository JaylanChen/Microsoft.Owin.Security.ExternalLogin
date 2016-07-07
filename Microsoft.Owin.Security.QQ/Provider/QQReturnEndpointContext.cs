using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.QQ.Provider
{
    public class QQReturnEndpointContext : ReturnEndpointContext
    {
        public QQReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
