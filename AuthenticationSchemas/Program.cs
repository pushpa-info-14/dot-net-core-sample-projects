using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>(Schemas.VisitorSchema, o => { })
    .AddCookie(Schemas.LocalSchema)
    .AddCookie(Schemas.PatreonCookie)
    .AddOAuth("External-Patreon", o =>
    {
        o.ClientId = "id";
        o.ClientSecret = "secret";

        o.AuthorizationEndpoint = "https:oauth.mocklab.io/oauth/authorize";
        o.TokenEndpoint = "https:oauth.mocklab.io/oauth/token";
        o.UserInformationEndpoint = "https:oauth.mocklab.io/userinfo";

        o.CallbackPath = "/cb-patreon";

        o.Scope.Add("Profile");
        o.SaveTokens = true;
    });

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("Customer", p =>
    {
        p.AddAuthenticationSchemes(Schemas.PatreonCookie, Schemas.LocalSchema, Schemas.VisitorSchema)
            .RequireAuthenticatedUser();
    });
    b.AddPolicy("User", p =>
    {
        p.AddAuthenticationSchemes(Schemas.LocalSchema)
            .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Task.FromResult("Hello World!")).RequireAuthorization("Customer");

app.MapGet("/login-local", async (HttpContext ctx) =>
{
    var claims = new List<Claim>
    {
        new("usr", "pushpa")
    };
    var identity = new ClaimsIdentity(claims, Schemas.LocalSchema);
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(Schemas.LocalSchema, user);
});

app.MapGet("/login-patreon", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync("External-Patreon", new AuthenticationProperties()
    {
        RedirectUri = "/"
    });
}).RequireAuthorization("User");

app.Run();

public static class Schemas
{
    public const string VisitorSchema = "Visitor";
    public const string LocalSchema = "Local";
    public const string PatreonCookie = "Patreon-Cookie";
}

public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(IOptionsMonitor<CookieAuthenticationOptions> options,
        ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>
        {
            new("usr", "pushpa")
        };
        var identity = new ClaimsIdentity(claims, Schemas.VisitorSchema);
        var user = new ClaimsPrincipal(identity);

        await Context.SignInAsync(Schemas.VisitorSchema, user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, Schemas.VisitorSchema));
    }
}