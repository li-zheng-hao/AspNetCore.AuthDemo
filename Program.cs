using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using 认证授权Demo;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(
        JwtBearerDefaults.AuthenticationScheme,
        opt =>
        {
            opt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = "benji",
                ValidAudience = "benji",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("miyaomiyao12312312312312312312")),
                // 是否验证Token有效期，使用当前时间与Token的Claims中的NotBefore和Expires对比
                ValidateLifetime = true
            };
        })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, opt =>
    {
        // opt.Cookie
        opt.Cookie.Name = "MyCookie";
        opt.ExpireTimeSpan = TimeSpan.FromMinutes(10);
        opt.Events.OnRedirectToLogin = context =>
        {
            context.Response.Headers["Location"] = context.RedirectUri;
            context.Response.StatusCode = 401;
            return Task.CompletedTask;
        };
    }).AddScheme<AuthenticationSchemeOptions, CustomAuthHandler>(CustomAuthHandler.SchemeName, it => { });

builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeHandler>();

builder.Services.AddAuthorization(options =>
{
    //基于角色组的策略
    options.AddPolicy("管理员", policy =>
    {
        policy.RequireRole("admin", "system");
        // 三种认证的结果都算进来
        policy.AuthenticationSchemes=new []{ JwtBearerDefaults.AuthenticationScheme,CustomAuthHandler.SchemeName,CookieAuthenticationDefaults.AuthenticationScheme};
    });
     options.AddPolicy("自定义策略", policy =>
     {
         policy.Requirements.Add(new MinimumAgeRequirement(1));
     });
    
    //基于用户名
    options.AddPolicy("用户名是张三", policy => policy.RequireUserName("张三"));
    // 基于ClaimType
    options.AddPolicy("地址是中国", policy => policy.RequireClaim(ClaimTypes.Country,"中国"));
    //自定义值
    options.AddPolicy("自定义Claim要求", policy => policy.RequireClaim("date","2017-09-02"));
   
});
var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();