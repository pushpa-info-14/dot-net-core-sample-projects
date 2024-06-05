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
