using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Text.Json;

namespace BackendForFrontend;

public class CustomCookieAuthenticationOptions
    : IConfigureNamedOptions<CookieAuthenticationOptions>
{
    private readonly HttpClient httpClient;
    private readonly OpenIdConfiguration openIdConfiguration;

    public CustomCookieAuthenticationOptions(IOptions<OpenIdConfiguration> options,
        HttpClient httpClient)
    {
        openIdConfiguration = options.Value;
        this.httpClient = httpClient;
    }

    public void Configure(string? name, CookieAuthenticationOptions options)
    {
        if (name == CookieAuthenticationDefaults.AuthenticationScheme) 
            GetDefaultOptions(options);
    }

    public void Configure(CookieAuthenticationOptions options)
    {
        Configure(Options.DefaultName, options);
    }

    private void GetDefaultOptions(CookieAuthenticationOptions options)
    {
        options.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = async context =>
            {
                var refreshToken = context.Properties.GetTokenValue("refresh_token");
                var expiresAt = context.Properties.GetTokenValue("expires_at");

                if (refreshToken != null && expiresAt != null &&
                    DateTimeOffset.UtcNow >= DateTimeOffset.Parse(expiresAt).AddMinutes(-5))
                {
                    var response = await RequestRefreshTokenAsync(refreshToken);

                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        var tokenResponse = JsonSerializer.Deserialize<Dictionary<string, string>>(content);

                        if (tokenResponse != null &&
                            IsValidResponse(tokenResponse))
                        {
                            var newAccessToken = tokenResponse["access_token"];
                            var newRefreshToken = tokenResponse["refresh_token"];
                            var newExpiresAt = DateTime.UtcNow
                                .AddSeconds(int.Parse(tokenResponse["expires_in"]))
                                .ToString("o");

                            context.Properties.StoreTokens(new List<AuthenticationToken>
                            {
                                new() { Name = "access_token", Value = newAccessToken },
                                new() { Name = "refresh_token", Value = newRefreshToken },
                                new() { Name = "expires_at", Value = newExpiresAt }
                            });

                            context.ShouldRenew = true;
                            return;
                        }
                    }

                    context.RejectPrincipal();
                    await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults
                        .AuthenticationScheme);
                }
            }
        };
    }

    private static bool IsValidResponse(IReadOnlyDictionary<string, string> tokenResponse)
    {
        return tokenResponse.ContainsKey("access_token") &&
               tokenResponse.ContainsKey("refresh_token") &&
               tokenResponse.ContainsKey("expires_in");
    }

    private async Task<HttpResponseMessage> RequestRefreshTokenAsync(string refreshToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"{openIdConfiguration.Authority}/as/token.oauth2");

        var fields = new Dictionary<string, string>
        {
            { "client_id", openIdConfiguration.ClientId },
            { "client_secret", openIdConfiguration.ClientSecret },
            { "grant_type", "refresh_token" },
            { "refresh_token", refreshToken }
        };

        request.Content = new FormUrlEncodedContent(fields);

        return await httpClient.SendAsync(request);
    }
}