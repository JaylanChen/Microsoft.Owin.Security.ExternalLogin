using System;
using System.Collections.Generic;
using System.Net.Http;
using Microsoft.Owin.Security.WeChat.Provider;

namespace Microsoft.Owin.Security.WeChat
{
    public class WeChatAuthenticationOptions : AuthenticationOptions
    {
        private const string authenticationType = "WeChat";
        public WeChatAuthenticationOptions()
            : base(authenticationType)
        {
            Caption = "WeChatUser";
            CallbackPath = "/signin-wechat";
            AuthenticationMode = AuthenticationMode.Passive;
            Scope = new List<string> { "get_user_info" };
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public TimeSpan BackchannelTimeout { get; set; }

        public WebRequestHandler BackChannelHttpHandler { get; set; }

        public IWeChatAuthenticationProvider Provider { get; set; }

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

        public string AppSecret { get; set; }
    }
}
