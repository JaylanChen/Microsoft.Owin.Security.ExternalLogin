using System.Threading.Tasks;

namespace Microsoft.Owin.Security.Weibo.Provider
{
    public interface IWeiboAuthenticationProvider
    {
        Task Authenticated(WeiboAuthenticatedContext context);

        Task ReturnEndpoint(WeiboReturnEndpointContext context);
    }
}