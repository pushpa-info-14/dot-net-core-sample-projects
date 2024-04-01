### Sample 1

```cs
var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/login", (HttpContext ctx) =>
{
    ctx.Response.Headers["set-cookie"] = "auth=usr:pushpa";
    return "ok";
});

app.MapGet("/username", (HttpContext ctx) =>
{
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var payload = authCookie.Split('=').Last();
    var parts = payload.Split(':');
    var key = parts[0];
    var value = parts[1];
    return value;
});

app.Run();
```

### Sample 2

```cs
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();

var app = builder.Build();

app.MapGet("/login", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    var protector = idp.CreateProtector("auth-cookie");
    ctx.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:pushpa")}";
    return "ok";
});

app.MapGet("/username", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    var protector = idp.CreateProtector("auth-cookie");
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    var protectedPayload = authCookie.Split('=').Last();
    var payload = protector.Unprotect(protectedPayload);
    var parts = payload.Split(':');
    var key = parts[0];
    var value = parts[1];
    return value;
});

app.Run();
```

### Sample 3

```cs
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

const string authScheme = "cookie";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme);

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
    return "ok";
});

app.MapGet("/username", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr").Value;
});

app.Run();

```