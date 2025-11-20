using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi_Prasanna.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class Rolebased_authenticationController : ControllerBase
    {
        // Only Admin can access
        [Authorize(Roles = "Admin")]
        [HttpGet("admin")]
        public IActionResult AdminOnly()
        {
            return Ok("Hi Admin, you are authorized!");
        }

        // Only Manager can access
        [Authorize(Roles = "Manager")]
        [HttpGet("manager")]
        public IActionResult ManagerOnly()
        {
            return Ok("Hi Manager, you are authorized!");
        }

        // Admin or User
        [Authorize(Roles = "Admin,User")]
        [HttpGet("common")]
        public IActionResult CommonForAdminAndUser()
        {
            return Ok("Admin and User both can access this.");
        }
    }
}
