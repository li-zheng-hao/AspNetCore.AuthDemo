using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JwtConstants = Microsoft.IdentityModel.JsonWebTokens.JwtConstants;

namespace 认证授权Demo.Controllers;

[ApiController]
[Route("[controller]/[action]")]
public class WeatherForecastController : ControllerBase
{
    

    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(ILogger<WeatherForecastController> logger)
    {
        _logger = logger;
    }
    /// <summary>
    /// 用默认的jwt验证
    /// </summary>
    /// <returns></returns>
    [Authorize(JwtBearerDefaults.AuthenticationScheme)]
    [HttpGet]
    public List<string> TestJwt()
    {
        List<string> res = new List<string>();
        foreach (var claim in HttpContext.User.Claims)
        {
            res.Add( claim.Type + "-" + claim.Value);
        }

        return res;
    }
    [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    [HttpGet]
    public List<string> TestCookie()
    {
        List<string> res = new List<string>();
        foreach (var claim in HttpContext.User.Claims)
        {
            res.Add( claim.Type + "-" + claim.Value);
        }

        return res;
    }
    [Authorize(AuthenticationSchemes = CustomAuthHandler.SchemeName)]
    [HttpGet]
    public List<string> TestCustom()
    {
        List<string> res = new List<string>();
        foreach (var claim in HttpContext.User.Claims)
        {
            res.Add( claim.Type + "-" + claim.Value);
        }

        return res;
    }
    [Authorize(Roles = "admin",AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    [HttpGet]
    public List<string> TestRole()
    {
        List<string> res = new List<string>();
        foreach (var claim in HttpContext.User.Claims)
        {
            res.Add( claim.Type + "-" + claim.Value);
        }

        return res;
    }
    [HttpPost]
    public IActionResult LoginByJwt(string username,string password)
    {
        if (username == "test" && password == "test")
        {
            //JWT载荷(Payload)
            var key = Encoding.ASCII.GetBytes("miyaomiyao12312312312312312312");
            var authTime = DateTime.UtcNow;
            var expiresAt = authTime.AddDays(7);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "benji",
                Audience = "benji",
                //自定义内容
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name,"local"),
                    new Claim(ClaimTypes.Sid,"123456"),
                    new Claim("随便定义一个字段","字段对应的值"),
                    new Claim(ClaimTypes.Role,"admin"),
                    new Claim(ClaimTypes.Role,"user"),
                    new Claim(ClaimTypes.Role,"superadmin"),
                }),
                //过期时间
                Expires = expiresAt,
                //签证
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            return Ok(new
            {
                access_token = tokenString,
                token_type = "Bearer"
            });
        }
        else
        {
            return BadRequest("账号错误");
        }
    }

    [HttpPost]
    public async Task<IActionResult> LoginByCookie(string username, string password)
    {
        if (username == "test" && password == "test")
        {
            //1.创建cookie 保存用户信息，使用claim。将序列化用户信息并将其存储在cookie中
            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.MobilePhone,"123"),
                new Claim(ClaimTypes.Name,"test"),
                new Claim(ClaimTypes.Role,"admin"),
                new Claim("Id","123"),
                new Claim(ClaimTypes.Role,"user"),
                new Claim(ClaimTypes.Role,"superadmin"),
            };
 
            //2.创建声明主题 指定认证方式 这里使用cookie
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
 
            //3.配置认证属性 比如过期时间，是否持久化。。。。
            var authProperties = new AuthenticationProperties
            {
                // ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                
                // 是否持久化,类似于前端勾选记住密码
                //IsPersistent = true,
 
                //IssuedUtc = <DateTimeOffset>,
            };
 
            //4.登录
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);
            return Ok();
        }
        else
        {
            return BadRequest("账号密码错误");
        }
    }
}