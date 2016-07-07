using System;
using Owin;

namespace Microsoft.Owin.Security.QQ
{
    public static class QQAuthenticationExtensions
    {
        public static void UseQQConnectAuthentication(this IAppBuilder app, QQAuthenticationOptions options)
        { 
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }
            app.Use(typeof(QQAuthenticationMiddleware), app, options);
        }

        public static void UseQQConnectAuthentication(this IAppBuilder app, string appId, string appSecret)
        {
            UseQQConnectAuthentication(app, new QQAuthenticationOptions()
            {
                AppId = appId,
                AppSecret = appSecret,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            });
        }
    }
}
