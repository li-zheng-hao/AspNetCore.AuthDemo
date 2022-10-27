using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace 认证授权Demo;

public class CustomAuthHandler:AuthenticationHandler<AuthenticationSchemeOptions>
{
    public CustomAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {

    }

    public const string SchemeName= "自定义验证";

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var auth=Request.Headers["Authorization"].ToString();
        if (auth == "自定义验证条件")
        {
            //验证成功后创建用户信息
            var claimsIdentity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Name, "testUser"),
                new Claim(ClaimTypes.Role, "testRole")
            }, SchemeName);

            var principal = new ClaimsPrincipal(claimsIdentity);
            var ticket = new AuthenticationTicket(principal, this.Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        else
        {
            return AuthenticateResult.Fail("验证失败");
        }
    }
}