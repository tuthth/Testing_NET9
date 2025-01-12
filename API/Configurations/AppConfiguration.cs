using API.Middlewares;

namespace API.Configurations
{
    public static class AppConfiguration
    {
        public static void AddMiddlewares(this IApplicationBuilder app)
        {
            app.UseMiddleware<ValidateKeyExpireMiddleware>();
            app.UseMiddleware<ValidateIPAdressMiddleware>();
        }
    }
}
