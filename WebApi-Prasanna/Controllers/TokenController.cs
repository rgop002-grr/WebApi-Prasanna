using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApi_Prasanna.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        // Use same values as in Program.cs
        private const string SecretKey = "ThisIsMySuperLongSecureKeyForJWTToken123!";
        private const string Issuer = "WebApi-Prasanna";
        private const string Audience = "WebApi-Prasanna";

        [AllowAnonymous]
        [HttpGet("generate")]
        public IActionResult GenerateToken(string username, string role)
        {
            if (string.IsNullOrWhiteSpace(username)) return BadRequest("username required");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role ?? "User")
            };

            var token = new JwtSecurityToken(
                issuer: Issuer,
                audience: Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new { token = jwt, expires = token.ValidTo });
        }


        // Protected endpoint — requires a valid JWT in Authorization header
        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedEndpoint()
        {
            // You can read claims from HttpContext.User
            var username = User.Identity?.Name;
            var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new
            {
                message = "You reached a protected endpoint",
                username,
                role,
                claims = User.Claims.Select(c => new { c.Type, c.Value })
            });
        }

        
    }
}
