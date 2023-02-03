﻿using JwtWebApi.Dtos;
using JwtWebApi.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Forms;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    public static User user = new User();
    private readonly IConfiguration configuration;
    private readonly IUserService userService;

    public AuthController(IConfiguration configuration, IUserService userService)
    {
        this.configuration = configuration;
        this.userService = userService;
    }

    [HttpGet, Authorize]
    public ActionResult GetMe()
    {
        var userName = userService.GetMyName();
        return Ok(userName);
    }

    [HttpPost("register")]
    public async Task<ActionResult> Register(UserDto userDto)
    {
        CreatePasswordHash(userDto.Password, out byte[] passwordHash, out byte[] passwordSalt);

        user.UserName = userDto.UserName;
        user.PasswordHash = passwordHash;
        user.PasswordSalt = passwordSalt;

        return Ok(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult> Login(UserDto userDto)
    {
        if (user.UserName != userDto.UserName)
            return BadRequest("User not found");

        if (!VerifyPasswordHash(userDto.Password, user.PasswordHash, user.PasswordSalt))
            return BadRequest("Wrong Password");

        string token = CreateToken(user);

        return Ok(token);
    }

    private string CreateToken(User user)
    {
        List<Claim> claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName),
            new Claim(ClaimTypes.Role, "Admin")
        };

        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
            configuration.GetSection("AppSettings:Token").Value));

        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

        var token = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.Now.AddDays(1),
            signingCredentials: creds);

        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

        return jwt;
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512())
        {
            passwordSalt = hmac.Key;
            passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }
    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using (var hmac = new HMACSHA512(passwordSalt))
        {
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            return computedHash.SequenceEqual(passwordHash);
        }
    }
}
