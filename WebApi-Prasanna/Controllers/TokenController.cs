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
        [HttpGet("generate")]
        public IActionResult GenerateToken(string username, string role)
        {
            // Hardcoded secret key (NO appsettings.json)
            var secretKey = "ThisIsMySuperLongSecureKeyForJWTToken123!";

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Claims added into token
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
                issuer: "WebApi-Prasanna",
                audience: "WebApi-Prasanna",
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return Ok(new
            {
                token = jwt,
                expires = token.ValidTo
            });
        }

        [HttpGet("validate")]
        public IActionResult ValidateToken(string token)
        {
            try
            {
                var secretKey = "ThisIsMySuperLongSecureKeyForJWTToken123!"; // SAME KEY

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
                var tokenHandler = new JwtSecurityTokenHandler();

                // VALIDATION SETTINGS
                var validationParams = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,

                    ValidIssuer = "WebApi-Prasanna",
                    ValidAudience = "WebApi-Prasanna",
                    IssuerSigningKey = key,
                    ClockSkew = TimeSpan.Zero  // no extra time allowed
                };

                // VALIDATE
                var principal = tokenHandler.ValidateToken(token, validationParams, out SecurityToken validatedToken);

                // If validation works, return success + claims
                return Ok(new
                {
                    message = "Token is valid",
                    username = principal.Identity?.Name,
                    role = principal.FindFirst(ClaimTypes.Role)?.Value
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    message = "Invalid token",
                    error = ex.Message
                });
            }
        }
    }
}

