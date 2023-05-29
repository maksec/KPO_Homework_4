using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace KPO_2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OrderCycle : ControllerBase
    {
        [HttpPost("Gay222")]
        public IActionResult Get2()
        {
            return Ok();
        }
    }
}
