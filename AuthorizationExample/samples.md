### Sample 1

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
        new("usr", "pushpa"),
        new("passport_type", "eur")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
});

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});

app.MapGet("/sweden", (HttpContext ctx) =>
{
    if (ctx.User.Identities.All(x => x.AuthenticationType != authScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }

    if (!ctx.User.HasClaim("passport_type", "eur"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.Run();
```

### Sample 2

```cs
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

const string authScheme = "cookie";
const string authScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme)
    .AddCookie(authScheme2);

var app = builder.Build();

app.UseAuthentication();

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa"),
        new("passport_type", "eur")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
});

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});

app.MapGet("/sweden", (HttpContext ctx) =>
{
    if (ctx.User.Identities.All(x => x.AuthenticationType != authScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }

    if (!ctx.User.HasClaim("passport_type", "eur"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.MapGet("/norway", (HttpContext ctx) =>
{
    if (ctx.User.Identities.All(x => x.AuthenticationType != authScheme))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }

    if (!ctx.User.HasClaim("passport_type", "nor"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.MapGet("/denmark", (HttpContext ctx) =>
{
    if (ctx.User.Identities.All(x => x.AuthenticationType != authScheme2))
    {
        ctx.Response.StatusCode = 401;
        return "";
    }

    if (!ctx.User.HasClaim("passport_type", "nor"))
    {
        ctx.Response.StatusCode = 403;
        return "";
    }

    return "allowed";
});

app.Run();
```

### Sample 3

```cs
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

const string authScheme = "cookie";
const string authScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme)
    .AddCookie(authScheme2);

var app = builder.Build();

app.UseAuthentication();

app.Use((ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/login"))
    {
        return next();
    }

    if (ctx.User.Identities.All(x => x.AuthenticationType != authScheme))
    {
        ctx.Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    if (!ctx.User.HasClaim("passport_type", "eur"))
    {
        ctx.Response.StatusCode = 403;
        return Task.CompletedTask;
    }

    return next();
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa"),
        new("passport_type", "eur")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
});

app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});

app.MapGet("/sweden", (HttpContext ctx) =>
{
    return "allowed";
});

app.MapGet("/norway", (HttpContext ctx) =>
{
    return "allowed";
});

// [AuthScheme(authScheme2)]
// [AuthClaim("passport_type", "eur")]
app.MapGet("/denmark", (HttpContext ctx) =>
{
    return "allowed";
});

app.Run();
```

### Sample 4

```cs
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

const string authScheme = "cookie";
const string authScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme)
    .AddCookie(authScheme2);

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("eur passport", pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(authScheme)
            .RequireClaim("passport_type", "eur");
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa"),
        new("passport_type", "eur")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
}).AllowAnonymous();

// [Authorize(Policy = "eur passport")]
app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
}).RequireAuthorization("eur passport");

app.MapGet("/sweden", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.MapGet("/norway", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.MapGet("/denmark", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.Run();
```

### Sample 5

```cs
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

const string authScheme = "cookie";
const string authScheme2 = "cookie2";

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme)
    .AddCookie(authScheme2);

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("eur passport", pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(authScheme)
            .AddRequirements(new MyRequirement())
            .RequireClaim("passport_type", "eur");
    });
});

builder.Services.AddSingleton<IAuthorizationHandler, MyRequirementHandler>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa"),
        new("passport_type", "eur")
    };
    var identity = new ClaimsIdentity(claims, authScheme);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(authScheme, user);
}).AllowAnonymous();

// [Authorize(Policy = "eur passport")]
app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
}).RequireAuthorization("eur passport");

app.MapGet("/sweden", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.MapGet("/norway", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.MapGet("/denmark", (HttpContext ctx) =>
{
    return "allowed";
}).RequireAuthorization("eur passport");

app.Run();

public class MyRequirement : IAuthorizationRequirement
{

}

public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
{
    public MyRequirementHandler()
    {

    }

    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
        // context.User
        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}
```