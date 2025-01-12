using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Net;
using API.Attributes;
using Microsoft.AspNetCore.RateLimiting;

namespace API.Controllers
{

    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : DefaultController
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };
        public WeatherForecastController(ILogger<WeatherForecastController> logger) : base(logger)
        {
        }
        [Authorize]
        [RequiresJWT]
        [HttpGet("GetWeatherForecast")]
        [EndpointSummary("Get weather forecast")]
        public IEnumerable<WeatherForecast> Get()
        {
            return Enumerable.Range(1, 5).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            })
            .ToArray();
        }
        [AllowAnonymous]
        [HttpPost("CreateKey")]
        [EndpointSummary("Create JWT key here")]
        [EnableRateLimiting("JWTLimiter")]

        public string CreateJWTKey(string email, CancellationToken cancellationToken)
        {
            var remoteIP = HttpContext.Connection.RemoteIpAddress;
            if(remoteIP.IsIPv4MappedToIPv6)
            {
                remoteIP = remoteIP.MapToIPv4();
            }
            var key = Encoding.ASCII.GetBytes("3LanLotVaoDoiHinhNguNhatWC2010-2014-2022");
            var tokenHandler = new JwtSecurityTokenHandler();
            var secretKeyBytes = System.Text.Encoding.UTF8.GetBytes("3LanLotVaoDoiHinhNguNhatWC2010-2014-2022");
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Email, email),
                    new Claim(ClaimTypes.Name, "Penaldog"),
                    new Claim("IP", remoteIP.ToString()),
                }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var accessToken = tokenHandler.WriteToken(token);
            _logger.LogInformation($"Created JWT key for {email} from {remoteIP}");
            return accessToken.Trim();
        }
    }
}
