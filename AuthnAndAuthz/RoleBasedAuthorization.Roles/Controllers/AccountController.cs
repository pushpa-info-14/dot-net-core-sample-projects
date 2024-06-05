using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace RoleBasedAuthorization.Roles.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult Login()
        {
            var claims = new Claim[] {
                new (ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new ("my_role_claim_extravaganza", "admin")
            };
            var claimsIdentity = new ClaimsIdentity(claims, "cookie", nameType: null, roleType: "my_role_claim_extravaganza");
            var claimsPrinciple = new ClaimsPrincipal(claimsIdentity);

            return SignIn(claimsPrinciple, authenticationScheme: "cookie");
        }
    }
}
