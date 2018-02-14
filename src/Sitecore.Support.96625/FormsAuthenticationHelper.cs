using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Security;
using Sitecore.Configuration;
using Sitecore.Diagnostics;
using Sitecore.localhost;
using Sitecore.Security.Authentication;
using Sitecore.Common;

namespace Sitecore.Support.Security.Authentication
{
    public class FormsAuthenticationHelper :Sitecore.Security.Authentication.FormsAuthenticationHelper
  {

  private const string userDataCookiePrefix = "sc_user_data_";

  private const string passwordHashValue = "SCexper14nce501ut10n";

  private Dictionary<string, string> userDataDictionary;

  private string userDataFromCookie;

  private static readonly byte[] saltValue = Encoding.ASCII.GetBytes("#!:)_rrr");

  private static readonly byte[] rgbIVValue = Encoding.ASCII.GetBytes("v6T@>quD%mE5GstI");

  public FormsAuthenticationHelper(AuthenticationProvider provider) : base(provider)
		{
    this.userDataDictionary = new Dictionary<string, string>();
    this.userDataFromCookie = string.Empty;
  }

  public override string GetAuthenticationData(string key)
  {
    Assert.ArgumentNotNull(key, "key");
    string text = ClientContext.GetValue(key) as string;
    if (string.IsNullOrEmpty(text))
    {
      FormsAuthenticationTicket ticket = this.GetTicket();
      if (ticket != null && !string.IsNullOrEmpty(this.userDataFromCookie))
      {
        new Serializer().Deserialize<IDictionary<string, string>>(this.userDataFromCookie).TryGetValue(key, out text);
      }
      if (!string.IsNullOrEmpty(text))
      {
        ClientContext.SetValue(key, text);
      }
    }
    return text;
  }

  public override void SetAuthenticationData(string key, string authenticationData)
  {
    Assert.ArgumentNotNull(key, "key");
    Assert.ArgumentNotNull(authenticationData, "authenticationData");
    ClientContext.SetValue(key, authenticationData);
    FormsAuthenticationTicket ticket = this.GetTicket();
    if (ticket != null)
    {
      Serializer serializer = new Serializer();
      IDictionary<string, string> dictionary = string.IsNullOrEmpty(ticket.UserData) ? new Dictionary<string, string>() : serializer.Deserialize<IDictionary<string, string>>(ticket.UserData);
      dictionary[key] = authenticationData;
      string text = serializer.Serialize<IDictionary<string, string>>(dictionary);
      text = this.EncryptUserData(text);
      FormsAuthenticationTicket ticket2 = new FormsAuthenticationTicket(ticket.Version, ticket.Name, ticket.IssueDate, ticket.Expiration, ticket.IsPersistent, string.Empty, ticket.CookiePath);
      int num = 1;
      this.userDataDictionary.Clear();
      while (text.Length > 0)
      {
        int num2 = (text.Length > 4000) ? 4000 : text.Length;
        string value = text.Substring(0, num2);
        text = text.Remove(0, num2);
        this.userDataDictionary.Add("sc_user_data_" + num++, value);
      }
      this.SaveTicket(ticket2);
    }
  }

  private FormsAuthenticationTicket GetTicket()
  {
    HttpContext current = HttpContext.Current;
    HttpCookie httpCookie = null;
    if (current != null)
    {
      for (int i = current.Request.Cookies.Count - 1; i >= 0; i--)
      {
        HttpCookie httpCookie2 = current.Request.Cookies[i];
        if (httpCookie2 != null && httpCookie2.Name.Equals(FormsAuthentication.FormsCookieName))
        {
          httpCookie = httpCookie2;
          break;
        }
      }
    }
    if (httpCookie != null && !string.IsNullOrEmpty(httpCookie.Value))
    {
      FormsAuthenticationTicket result = FormsAuthentication.Decrypt(httpCookie.Value);
      int num = 1;
      this.userDataDictionary.Clear();
      for (HttpCookie httpCookie3 = current.Request.Cookies.Get("sc_user_data_" + num); httpCookie3 != null; httpCookie3 = current.Request.Cookies.Get("sc_user_data_" + ++num))
      {
        this.userDataFromCookie += httpCookie3.Value;
      }
      this.userDataFromCookie = this.DecryptUserData(this.userDataFromCookie);
      return result;
    }
    return null;
  }

  private void SaveTicket(FormsAuthenticationTicket ticket)
  {
    Assert.ArgumentNotNull(ticket, "ticket");
    if (HttpContext.Current != null)
    {
      string value = FormsAuthentication.Encrypt(ticket);
      HttpCookie httpCookie = new HttpCookie(FormsAuthentication.FormsCookieName, value)
      {
        Path = ticket.CookiePath
      };
      if (ticket.IsPersistent)
      {
        httpCookie.Expires = ticket.Expiration;
      }
      httpCookie.Value = value;
      httpCookie.Secure = FormsAuthentication.RequireSSL;
      httpCookie.HttpOnly = true;
      if (FormsAuthentication.CookieDomain != null)
      {
        httpCookie.Domain = FormsAuthentication.CookieDomain;
      }
      HttpContext.Current.Response.Cookies.Remove(httpCookie.Name);
      HttpContext.Current.Response.Cookies.Add(httpCookie);
      foreach (KeyValuePair<string, string> current in this.userDataDictionary)
      {
        HttpContext.Current.Response.Cookies.Remove(current.Key);
        HttpCookie httpCookie2 = new HttpCookie(current.Key, current.Value)
        {
          Path = ticket.CookiePath
        };
        if (ticket.IsPersistent)
        {
          httpCookie2.Expires = ticket.Expiration;
        }
        HttpContext.Current.Response.Cookies.Add(httpCookie2);
      }
    }
  }

  private string EncryptUserData(string userData)
  {
    string result;
    try
    {
      byte[] bytes = Encoding.UTF8.GetBytes(userData);
      byte[] bytes2 = new Rfc2898DeriveBytes("SCexper14nce501ut10n", FormsAuthenticationHelper.saltValue).GetBytes(32);
      RijndaelManaged rijndaelManaged = new RijndaelManaged
      {
        Mode = CipherMode.CBC,
        Padding = PaddingMode.Zeros
      };
      ICryptoTransform transform = rijndaelManaged.CreateEncryptor(bytes2, FormsAuthenticationHelper.rgbIVValue);
      byte[] inArray;
      using (MemoryStream memoryStream = new MemoryStream())
      {
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
        {
          cryptoStream.Write(bytes, 0, bytes.Length);
          cryptoStream.FlushFinalBlock();
          inArray = memoryStream.ToArray();
        }
      }
      result = System.Convert.ToBase64String(inArray);
    }
    catch (Exception ex)
    {
      Log.Error(ex.ToString(), this);
      result = string.Empty;
    }
    return result;
  }

  private string DecryptUserData(string userData)
  {
    string result;
    try
    {
      byte[] array = System.Convert.FromBase64String(userData);
      byte[] bytes = new Rfc2898DeriveBytes("SCexper14nce501ut10n", FormsAuthenticationHelper.saltValue).GetBytes(32);
      RijndaelManaged rijndaelManaged = new RijndaelManaged
      {
        Mode = CipherMode.CBC,
        Padding = PaddingMode.None
      };
      ICryptoTransform transform = rijndaelManaged.CreateDecryptor(bytes, FormsAuthenticationHelper.rgbIVValue);
      using (MemoryStream memoryStream = new MemoryStream(array))
      {
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
        {
          byte[] array2 = new byte[array.Length];
          int count = cryptoStream.Read(array2, 0, array2.Length);
          result = Encoding.UTF8.GetString(array2, 0, count).TrimEnd("\0".ToCharArray());
        }
      }
    }
    catch (Exception ex)
    {
      Log.Error(ex.ToString(), this);
      result = string.Empty;
    }
    return result;
  }
}
}