using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JSW.Controllers;
[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    public UserController()
    {
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login()
    {
        return Ok("Succes");
    }
}
