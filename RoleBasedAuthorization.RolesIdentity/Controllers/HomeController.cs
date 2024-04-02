using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RoleBasedAuthorization.RolesIdentity.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public string Index()
        {
            return "Index Route";
        }

        [HttpGet("secret")]
        [Authorize(Roles = "admin")]
        public string Secret()
        {
            return "Secret Route";
        }
    }
}
