using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin.Security.Weibo.Provider;

namespace Microsoft.Owin.Security.Weibo
{
    public class WeiboAuthenticationOptions : AuthenticationOptions
    {
        private const string authenticationType = "Weibo";
        public WeiboAuthenticationOptions()
            : base(authenticationType)
        {
            Caption = "WeiboUser";
            CallbackPath = "/signin-weibo";
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string>();
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }


        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public WebRequestHandler BackChannelHttpHandler { get; set; }

        public IWeiboAuthenticationProvider Provider { get; set; }

        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        public IList<string> Scope { get; private set; }

        public string CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        public string AppId { get; set; }

        public string AppKey { get; set; }
    }
}