using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Web;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebApp;
using WebApp.Data;
using WebApp.Security;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services
.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/login";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});
builder.Services.AddRazorPages();

var app = builder.Build();

app.MapGet("/authorize", (HttpContext ctx) =>
{
    var user = ctx.User;
    Console.WriteLine(user.Identity.IsAuthenticated);
    string redirectUrl;
    ctx.Request.Query.TryGetValue("response_type", out var responseType);
    ctx.Request.Query.TryGetValue("client_id", out var clientId);
    ctx.Request.Query.TryGetValue("code_challenge", out var codeChallenge);
    // ctx.Request.Query.TryGetValue("code_challenge_method", out var codeChallengeMethod);
    ctx.Request.Query.TryGetValue("redirect_uri", out var redirectUri);
    ctx.Request.Query.TryGetValue("scope", out var scope);
    ctx.Request.Query.TryGetValue("state", out var state);
    // TODO: fix this issue: code_challenge_method is read as code_challenge_metho is the url
    if (string.IsNullOrEmpty(clientId) ||
        string.IsNullOrEmpty(codeChallenge) ||
        // string.IsNullOrEmpty(codeChallengeMethod) ||
        string.IsNullOrEmpty(redirectUri) ||
        string.IsNullOrEmpty(state) ||
        string.IsNullOrEmpty(scope) ||
        responseType != "code"
        )
    {
        return Results.Redirect(@$"{redirectUri}?error=invalid_request");
    }

    if (FakeDatabase.Clients.FirstOrDefault(c => c.ClientId == clientId) is null)
    {
        return Results.Redirect(@$"{redirectUri}?error=unknown_client", true);
    }

    // TODO: handle edge cases (validation)

    // Check if the user is authenticated
    if (!user.Identity!.IsAuthenticated)
    {
        redirectUrl = $"/login?" +
        $"client_id={clientId}&" +
        $"redirect_uri={redirectUri}&" +
        $"scope={scope}&" +
        $"response_type={responseType}&" +
        $"code_challenge={codeChallenge}&" +
        // $"code_challenge_method={codeChallengeMethod}&" +
        $"state={state}";
        return Results.Redirect(redirectUrl, true);
    }

    var authCode = new AuthCode();
    var newCodeChallenge = new CodeChallenge()
    {
        CodeChallengeString = codeChallenge!,
        // CodeChallengeMethod = codeChallengeMethod!
    };

    FakeDatabase.ClientAuthCodes.FirstOrDefault(c => c.Key == clientId)!.Value.Add(authCode);
    FakeDatabase.AuthCodeCodeChallenges.TryAdd(authCode.Code, new List<CodeChallenge>() { newCodeChallenge });

    redirectUrl = $"{redirectUri}?" +
    $"code={authCode.Code}&" +
    $"state={state}&" +
    $"iss={HttpUtility.UrlEncode("http://localhost:5024")}";
    return Results.Redirect(redirectUrl, true);
});

app.MapPost("/token", ([FromBody] TokenRequestDto body) =>
{
    Console.WriteLine(body.GrantType.ToString());
    Console.WriteLine(body.ClientId.ToString());
    Console.WriteLine(body.Code.ToString());
    // System.Console.WriteLine(body.CodeVerifier.ToString());
    var client = FakeDatabase.Clients.FirstOrDefault(c => c.ClientId == body.ClientId);
    if (client is null)
    {
        return Results.BadRequest("client not found");
    }
    var clientSecret = client.ClientSecret;

    if (body.GrantType != "authorization_code")
    {
        return Results.BadRequest("grant type error");
    }

    var clientAuthCodeList = FakeDatabase.ClientAuthCodes.FirstOrDefault(c => c.Key == body.ClientId).Value;
    if (clientAuthCodeList.IsNullOrEmpty())
    {
        return Results.BadRequest("auth code not found");
    }
    var authCode = clientAuthCodeList.FirstOrDefault(c => c.Code == body.Code);
    if (authCode is null || body.Code != authCode.Code)
    {
        return Results.BadRequest("Invalid auth code");
    }

    var accessTokenClaims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user_id"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "user_role")
        };

    var access_token = Tokens.GenerateJwtToken(clientSecret, "server", "sofco sms", 10, accessTokenClaims);
    var identityTokenClaims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, "user_id"),
            new Claim(JwtRegisteredClaimNames.GivenName, "ahmed"),
            new Claim(JwtRegisteredClaimNames.FamilyName, "senousy"),
            // other user claims if needed
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "user_role")
        };

    var identity_token = Tokens.GenerateJwtToken(clientSecret, "server", "sofco sms", 10, identityTokenClaims);
    return Results.Json(new
    {
        access_token = access_token,
        identity_token = identity_token
    });
});

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
