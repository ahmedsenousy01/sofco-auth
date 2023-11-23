using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace MyApp.Namespace
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public LoginInputModel Input { get; set; }

        public IActionResult OnGet()
        {
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                HttpContext.Request.Query.TryGetValue("response_type", out var responseType);
                HttpContext.Request.Query.TryGetValue("client_id", out var clientId);
                HttpContext.Request.Query.TryGetValue("code_challenge", out var codeChallenge);
                // HttpContext.Request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
                HttpContext.Request.Query.TryGetValue("redirect_uri", out var redirectUri);
                HttpContext.Request.Query.TryGetValue("scope", out var scope);
                HttpContext.Request.Query.TryGetValue("state", out var state);

                var redirectUrl = $"/authorize?" +
                $"client_id={clientId}&" +
                $"redirect_uri={redirectUri}&" +
                $"scope={scope}&" +
                $"response_type={responseType}&" +
                $"code_challenge={codeChallenge}&" +
                // $"code_challenge_method={codeChallengeMethod}&" +
                $"state={state}";
                return Redirect(redirectUrl);
            }
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (ModelState.IsValid)
            {
                if (Input.Email == "admin@sofco.org" && Input.Password == "admin")
                {
                    var user = new ClaimsPrincipal(new ClaimsIdentity(new List<Claim>()
                    {
                        new(ClaimTypes.Name, Input.Email)
                    }, CookieAuthenticationDefaults.AuthenticationScheme));
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);
                    HttpContext.Request.Query.TryGetValue("response_type", out var responseType);
                    HttpContext.Request.Query.TryGetValue("client_id", out var clientId);
                    HttpContext.Request.Query.TryGetValue("code_challenge", out var codeChallenge);
                    // HttpContext.Request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
                    HttpContext.Request.Query.TryGetValue("redirect_uri", out var redirectUri);
                    HttpContext.Request.Query.TryGetValue("scope", out var scope);
                    HttpContext.Request.Query.TryGetValue("state", out var state);

                    var redirectUrl = $"/authorize?" +
                    $"client_id={clientId}&" +
                    $"redirect_uri={redirectUri}&" +
                    $"scope={scope}&" +
                    $"response_type={responseType}&" +
                    $"code_challenge={codeChallenge}&" +
                    // $"code_challenge_method={codeChallengeMethod}&" +
                    $"state={state}";
                    return Redirect(redirectUrl);
                }
            }
            return Page();
        }
    }

    public class LoginInputModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Display(Name = "Remember me")]
        public bool RememberMe { get; set; }
    }
}
