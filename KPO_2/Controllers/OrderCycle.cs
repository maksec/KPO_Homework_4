using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace KPO_2.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class OrderCycle : ControllerBase
    {
        [HttpPost("GetDish")]
        public IActionResult GetDish()
        {
            return Ok();
        }
    }
}
