using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    [HttpGet("generate")]
    public IActionResult Generate()
    {
        var token = JwtTokenGenerator.GenerateToken(
            secretKey: "super_secret_key_which_should_be_long",
            issuer: "my-app",
            audience: "my-users",
            expiryMinutes: 60,
            extraClaims: new Dictionary<string, string>
            {
                { "sub", "123" },
                { "role", "admin" }
            }
        );

        return Ok(new { token });
    }
}
