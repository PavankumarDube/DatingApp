using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _config = config;
            _repo = repo;

        }


        public async Task<IActionResult> Register(UserForRegisterDtos userForRegisterDtos)
        {


            userForRegisterDtos.Username = userForRegisterDtos.Username.ToLower();
            if (await _repo.UserExists(userForRegisterDtos.Username))
                return BadRequest("Username already exists");

            var userToCreate = new User
            {
                UserName = userForRegisterDtos.Username
            };
            var createdUser = await _repo.Register(userToCreate, userForRegisterDtos.Password);

            return StatusCode(201);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(UserForLoginDtos userForRegisterDtos)
        {

            var userForRepo = await _repo.Login(userForRegisterDtos.UserName.ToLower(), userForRegisterDtos.Password);
            if (userForRepo == null)
                return Unauthorized();
            var claims = new[]{

                new Claim(ClaimTypes.NameIdentifier, userForRepo.Id.ToString()),
                new Claim (ClaimTypes.Name, userForRepo.UserName)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8
                .GetBytes(_config.GetSection("AppSettings:Token").Value));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
                var tokenDecriptor = new SecurityTokenDescriptor{

                    Subject = new ClaimsIdentity(claims),
                    Expires = DateTime.Now.AddDays(1),
                    SigningCredentials = creds

                };
                var tokenHandler = new JwtSecurityTokenHandler();
                var token = tokenHandler.CreateToken(tokenDecriptor);
                return Ok(new {
                    token = tokenHandler.WriteToken(token)
                });
        }

    }
}
