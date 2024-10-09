using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityProvider.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AccountController : ControllerBase
{
    private readonly SignInManager<ApplicationUser> _signInManager;

    public AccountController(SignInManager<ApplicationUser> signInManager)
    {
        _signInManager = signInManager;
    }

    // GET: api/Account/ExternalLogin
    [HttpGet("ExternalLogin")]
    public IActionResult ExternalLogin(string provider)
    {
        var redirectUrl = Url.Action("ExternalLoginCallback", "Account");
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    // GET: api/Account/ExternalLoginCallback
    [HttpGet("ExternalLoginCallback")]
    public async Task<IActionResult> ExternalLoginCallback()
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return Unauthorized();
        }

        var signInResult =
            await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (signInResult.Succeeded)
        {
            return Ok(new { message = "Login successful" });
        }

        var user = new ApplicationUser
        {
            UserName = info.Principal.FindFirstValue(ClaimTypes.Email),
            Email = info.Principal.FindFirstValue(ClaimTypes.Email)
        };
        var result = await _signInManager.UserManager.CreateAsync(user);
        if (result.Succeeded)
        {
            await _signInManager.UserManager.AddLoginAsync(user, info);
            await _signInManager.SignInAsync(user, isPersistent: false);
            return Ok(new { message = "User registered and logged in successfully" });
        }

        return BadRequest(result.Errors);
    }

    [HttpGet("WhoAmI")]
    [Authorize]
    public IActionResult WhoAmI()
    {
        var user = User.Identity;
        if (user != null && user.IsAuthenticated)
        {
            var userInfo = new
            {
                email = user.Name,
            };
            return Ok(userInfo);
        }

        return Unauthorized();
    }
}