using System.Threading.Tasks;

namespace Microsoft.Owin.Security.QQ.Provider
{
    public interface IQQAuthenticationProvider
    {
        Task Authenticated(QQAuthenticatedContext context);

        Task ReturnEndpoint(QQReturnEndpointContext context);
    }
}
