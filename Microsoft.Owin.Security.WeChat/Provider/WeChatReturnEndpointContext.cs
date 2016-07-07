using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.WeChat.Provider
{
    public class WeChatReturnEndpointContext : ReturnEndpointContext
    {
        public WeChatReturnEndpointContext(IOwinContext context,AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
