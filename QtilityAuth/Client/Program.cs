using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using QtilityAuth.Client;
using System.Text.Json;
using System.Text;
using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Components.Authorization;
using Radzen;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddOptions();
builder.Services.AddAuthorizationCore();
builder.Services.AddSingleton<JwtAuthenticationStateProvider>();
builder.Services.AddSingleton<AuthenticationStateProvider>(provider => provider.GetRequiredService<JwtAuthenticationStateProvider>());
builder.Services.AddHttpClient();
builder.Services.AddSingleton<Api>();

builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

var appUri = new Uri(builder.HostEnvironment.BaseAddress);

builder.Services.AddScoped(provider => new JwtTokenMessageHandler(appUri, provider.GetRequiredService<JwtAuthenticationStateProvider>()));
builder.Services.AddHttpClient("QtilityAuth.Server", client => client.BaseAddress = appUri)
    .AddHttpMessageHandler<JwtTokenMessageHandler>();
builder.Services.AddScoped(sp => sp.GetRequiredService<IHttpClientFactory>().CreateClient("QtilityAuth.Server"));
builder.Services.AddRadzenComponents();
var application = builder.Build();
await RefreshJwtToken(application);

await application.RunAsync();

static async Task RefreshJwtToken(WebAssemblyHost application)
{
    using var boostrapScope = application.Services.CreateScope();
    using var api = boostrapScope.ServiceProvider.GetRequiredService<Api>();

    var refreshTokenResponse = await api.Auth.RefreshToken();
    if (refreshTokenResponse.succeeded)
    {
        var loginStateService = boostrapScope.ServiceProvider.GetRequiredService<JwtAuthenticationStateProvider>();
        loginStateService.Login(refreshTokenResponse.jwt);
    }
}

public class Api : IServiceProvider, IDisposable
{
    public Auth Auth{ get; set; } = new Auth();
    public void Dispose()
    {

    }

    public object? GetService(Type serviceType)
    {
        return new { };
    }
}
public record TokenResponse(bool succeeded, string jwt);
public class Auth
{
    public async Task<TokenResponse> RefreshToken()
    {
        var httpClient = new HttpClient();

        using HttpResponseMessage response = await httpClient.PostAsync(
            "https://localhost:7235/refresh", null);

        if (!response.IsSuccessStatusCode)
        {
            return new TokenResponse(false, string.Empty);
        }

        var jsonResponse = await response.Content.ReadAsStringAsync();
        var logResponse = JsonSerializer.Deserialize<TokenResponse>(jsonResponse);

        if(logResponse == null)
        {
            return new TokenResponse(false, string.Empty);
        }

        if (!logResponse.succeeded)
        {
            return new TokenResponse(false, string.Empty);
        }

        return new TokenResponse(logResponse.succeeded, logResponse.jwt);
    }
}

public class JwtAuthenticationStateProvider : AuthenticationStateProvider
{
    private static AuthenticationState NotAuthenticatedState = new AuthenticationState(new ClaimsPrincipal());

    private LoginUser _user;

    /// <summary>
    /// The display name of the user.
    /// </summary>
    public string DisplayName => this._user?.DisplayName;

    /// <summary>
    /// <see langword="true"/> if there is a user logged in, otherwise false.
    /// </summary>
    public bool IsLoggedIn => this._user != null;

    /// <summary>
    /// The current JWT token or <see langword="null"/> if there is no user authenticated.
    /// </summary>
    public string Token => this._user?.Jwt;

    /// <summary>
    /// Login the user with a given JWT token.
    /// </summary>
    /// <param name="jwt">The JWT token.</param>
    public void Login(string jwt)
    {
        var principal = JwtSerialize.Deserialize(jwt);
        this._user = new LoginUser(principal.Identity.Name, jwt, principal);
        this.NotifyAuthenticationStateChanged(Task.FromResult(GetState()));
    }

    /// <summary>
    /// Logout the current user.
    /// </summary>
    public void Logout()
    {
        this._user = null;
        this.NotifyAuthenticationStateChanged(Task.FromResult(GetState()));
    }

    /// <inheritdoc/>
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return Task.FromResult(GetState());
    }

    /// <summary>
    /// Constructs an authentication state.
    /// </summary>
    /// <returns>The created state.</returns>
    private AuthenticationState GetState()
    {
        if (this._user != null)
        {
            return new AuthenticationState(this._user.claimsPrincipal);
        }
        else
        {
            return NotAuthenticatedState;
        }
    }
}

internal class LoginUser
{
    public LoginUser(string name, string jwt, ClaimsPrincipal principal)
    {
        this.DisplayName = name;
        this.Jwt = jwt;
        this.claimsPrincipal = principal;
    }
    public string DisplayName { get; set; }
    public string Jwt { get; set; }
    public ClaimsPrincipal claimsPrincipal { get; set; }
}

public class JwtSerialize
{
    public static ClaimsPrincipal Deserialize(string jwtToken)
    {
        var segments = jwtToken.Split('.');

        if (segments.Length != 3)
        {
            throw new Exception("Invalid JWT");
        }

        Console.WriteLine(segments[1]);
        var dataSegment = Encoding.UTF8.GetString(FromUrlBase64(segments[1]));
        var data = JsonSerializer.Deserialize<JsonObject>(dataSegment);

        var claims = new Claim[data.Count];
        int index = 0;
        foreach (var entry in data)
        {
            claims[index] = JwtNodeToClaim(entry.Key, entry.Value);
            index++;
        }

        var claimIdentity = new ClaimsIdentity(claims, "jwt");
        var principal = new ClaimsPrincipal(new[] { claimIdentity });

        return principal;
    }

    private static Claim JwtNodeToClaim(string key, JsonNode node)
    {
        var jsonValue = node.AsValue();

        if (jsonValue.TryGetValue<string>(out var str))
        {
            return new Claim(key, str, ClaimValueTypes.String);
        }
        else if (jsonValue.TryGetValue<double>(out var num))
        {
            return new Claim(key, num.ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Double);
        }
        else
        {
            throw new Exception("Unsupported JWT claim type");
        }
    }

    private static byte[] FromUrlBase64(string jwtSegment)
    {
        string fixedBase64 = jwtSegment
            .Replace('-', '+')
            .Replace('_', '/');

        switch (jwtSegment.Length % 4)
        {
            case 2: fixedBase64 += "=="; break;
            case 3: fixedBase64 += "="; break;
            default: throw new Exception("Illegal base64url string!");
        }

        return Convert.FromBase64String(fixedBase64);
    }
}

public class JwtTokenMessageHandler : DelegatingHandler
{
    private readonly Uri _allowedBaseAddress;
    private readonly JwtAuthenticationStateProvider _loginStateService;

    public JwtTokenMessageHandler(Uri allowedBaseAddress, JwtAuthenticationStateProvider loginStateService)
    {
        this._allowedBaseAddress = allowedBaseAddress;
        this._loginStateService = loginStateService;
    }

    protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        return this.SendAsync(request, cancellationToken).Result;
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        var isSelfApiAccess = this._allowedBaseAddress.IsBaseOf(uri);

        if (isSelfApiAccess)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", this._loginStateService.Token ?? string.Empty);
        }

        return base.SendAsync(request, cancellationToken);
    }
}