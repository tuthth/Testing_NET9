using API.Attributes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace API.Middlewares
{
    public class ValidateIPAdressMiddleware
    {
        private readonly RequestDelegate _next;
        public ValidateIPAdressMiddleware(RequestDelegate next)
        {
            _next = next;
        }
        public async Task InvokeAsync(HttpContext context)
        {
            var endpoint = context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<RequiresJWTAttribute>() == null)
            {
                await _next(context);
                return;
            }
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsync("JWT token is missing.");
                return;
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadJwtToken(token);

                // Extract IP from the JWT
                var tokenIp = jwtToken.Claims.FirstOrDefault(c => c.Type == "IP")?.Value;
                var clientIp = context.Connection.RemoteIpAddress;

                if (clientIp != null && clientIp.IsIPv4MappedToIPv6)
                {
                    clientIp = clientIp.MapToIPv4();
                }

                if (clientIp?.ToString() != tokenIp)
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("IP address mismatch.");
                    return;
                }
            }
            catch
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid JWT token.");
                return;
            }

            await _next(context);
        }
    }
}
