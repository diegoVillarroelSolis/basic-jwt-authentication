using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
namespace jwtAuthentication.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/login")]
    public class LoginController : Controller
    {
        private readonly IConfiguration _configuration;

        public LoginController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpGet("hello")]
        public string Get()
        {
            return "hello world!";
        }

        // POST api/Login
        //[AllowAnonymous]
        //[HttpPost]
        //public IActionResult ValidateUser([FromBody] UserDto user)
        //{
        //    if (user.Name == "user" && user.Password == "secret")
        //    {
        //        return Ok("The user has been succesfully autthenticated");
        //    }
        //    return BadRequest("Could not verify username and password");
        //}

        [AllowAnonymous]
        [HttpPost]
        public IActionResult RequestToken([FromBody] UserDto user)
        {
            if (user.Name == "user" && user.Password == "secret")
            {
                var claims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Name)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecurityKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: "mydomain.com",
                    audience: "mydomain.com",
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)
                });
            }

            return BadRequest("Could not verify username and password");
        }

        [HttpGet("test")]
        public IActionResult Test()
        {
            return Ok("Operation with authentication");
        }

        public class UserDto
        {
            //[Required]
            public string Name { get; set; }

            //[Required]
            public string Password { get; set; }

        }
    }
}