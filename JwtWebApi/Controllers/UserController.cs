using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JwtWebApi.Controllers;
[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    private static string[] Users = new[]
    {
        "Abdulaziz", "A'zamjon", "Nuriddin", "MuhammadDiyor"
    };

    [HttpGet("Users")]
    [Authorize(Roles = "Admin")]
    public string[] GetUsers()
    {
        return Users;
    }
}
