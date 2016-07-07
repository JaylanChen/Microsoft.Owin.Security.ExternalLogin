using System;
using Owin;

namespace Microsoft.Owin.Security.Weibo
{
    public static class WeiboAuthenticationExtensions
    {
        public static IAppBuilder UseWeiboAuthentication(this IAppBuilder app, WeiboAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(WeiboAuthenticationMiddleware), app, options);
            return app;
        }

        public static IAppBuilder UseWeiboAuthentication(this IAppBuilder app, string appId, string appKey)
        {
            return app.UseWeiboAuthentication(new WeiboAuthenticationOptions
            {
                AppId = appId,
                AppKey = appKey,
                SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType()
            });
        } 
    }
}