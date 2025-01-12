using API.Attributes;
using System.IdentityModel.Tokens.Jwt;

namespace API.Middlewares
{
    public class ValidateKeyExpireMiddleware
    {
        private readonly RequestDelegate _next;
        public ValidateKeyExpireMiddleware(RequestDelegate next)
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

                var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;

                if (expClaim != null && long.TryParse(expClaim, out var expTimestamp))
                {
                    var expDate = DateTimeOffset.FromUnixTimeSeconds(expTimestamp).UtcDateTime;
                    if (DateTime.UtcNow > expDate)
                    {
                        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                        await context.Response.WriteAsync("JWT token has expired.");
                        return;
                    }
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
