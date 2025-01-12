using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    public class DefaultController : ControllerBase
    {
       public readonly ILogger<DefaultController> _logger;
       public DefaultController(ILogger<DefaultController> logger)
        {
            _logger = logger;
        }
    }
}
