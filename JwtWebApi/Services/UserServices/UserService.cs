using Microsoft.AspNetCore.Components.Forms;
using System.Security.Claims;

namespace JwtWebApi.Services.UserServices;

public class UserService : IUserService
{
    private readonly IHttpContextAccessor httpContext;

    public UserService(IHttpContextAccessor httpContext)
    {
        this.httpContext = httpContext;
    }

    public string GetMyName()
    {
        string result = string.Empty;
        if (httpContext.HttpContext != null)
            result = httpContext.HttpContext.User.FindFirstValue(ClaimTypes.Name);

        return result;
    }
}
