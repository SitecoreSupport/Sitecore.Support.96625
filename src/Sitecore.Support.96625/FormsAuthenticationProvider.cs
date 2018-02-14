using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using Sitecore.Diagnostics;
using Sitecore.Security.Accounts;

namespace Sitecore.Support.Security.Authentication
{
  public class FormsAuthenticationProvider :Sitecore.Security.Authentication.FormsAuthenticationProvider
  {
    private FormsAuthenticationHelper helper;

    public override User GetActiveUser()
    {
      return helper.GetActiveUser();
    }

    public override void Initialize(string name, NameValueCollection config)
    {
      base.Initialize(name, config);
      helper = new FormsAuthenticationHelper(this);
    }

    public override void SetAuthenticationData(string key, string authenticationData)
    {
      Assert.ArgumentNotNull(key, "key");
      Assert.ArgumentNotNull(authenticationData, "authenticationData");
      helper.SetAuthenticationData(key, authenticationData);
    }

    public override string GetAuthenticationData(string key)
    {
      Assert.ArgumentNotNull(key, "key");
      return helper.GetAuthenticationData(key);
    }
  }
}