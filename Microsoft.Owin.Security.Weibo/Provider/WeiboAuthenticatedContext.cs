using System;
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Weibo.Provider
{
    public class WeiboAuthenticatedContext : BaseContext
    {
        public string AccessToken { get; private set; }

        public TimeSpan? ExpiresIn { get; private set; }

        public string OpenId { get; private set; }

        public string Name { get; private set; }

        public WeiboAuthenticatedContext(IOwinContext context,string accessToken,string openid,string name)
            : base(context)
        {
            this.OpenId = openid;
            this.AccessToken = accessToken;
            this.Name = name;
        }
    }
}