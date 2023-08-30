using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Polly;
using Polly.Extensions.Http;
using Yarp.ReverseProxy.Transforms;

namespace BackendForFrontend;

public class Startup
{
    public Startup(IConfiguration configuration)
    {
        Configuration = configuration;
    }

    public IConfiguration Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
        services.Configure<OpenIdConfiguration>(Configuration.GetSection("OpenId"));
        services.AddHttpClient<CustomCookieAuthenticationOptions>()
            .AddPolicyHandler(GetRetryPolicy());
        services.AddSingleton<IConfigureOptions<CookieAuthenticationOptions>, 
            CustomCookieAuthenticationOptions>();

        var proxyBuilder = services.AddReverseProxy();

        proxyBuilder.LoadFromConfig(Configuration.GetSection("ReverseProxy"))
            .AddTransforms(transformBuilderContext =>
            {
                transformBuilderContext.AddRequestTransform(async transformContext =>
                {
                    var httpContext = transformContext.HttpContext;

                    var token = await httpContext.GetTokenAsync("access_token");
                    if (token != null)
                    {
                        transformContext.ProxyRequest.Headers
                            .Remove("Authorization");
                        transformContext.ProxyRequest.Headers
                            .Add("Authorization", $"Bearer {token}");
                    }
                });
            });

        services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddOpenIdConnect();
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseHsts();
        }

        app.UseHttpsRedirection();

        app.UseRouting();

        app.UseStaticFiles();
        // app.UseDefaultFiles();

        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<AuthorizationMiddleware>();

        app.UseEndpoints(endpoints => { endpoints.MapReverseProxy(); });

        app.UseSpa(spa =>
        {
            if (env.IsDevelopment())
            {
                // spa.UseReactDevelopmentServer(npmScript: "start");
                spa.UseProxyToSpaDevelopmentServer("http://localhost:8081");
            }
        });
    }

    private static IAsyncPolicy<HttpResponseMessage> GetRetryPolicy()
    {
        return HttpPolicyExtensions
            .HandleTransientHttpError()
            .OrResult(msg => msg.StatusCode == HttpStatusCode.NotFound)
            .WaitAndRetryAsync(6, retryAttempt =>
                TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));
    }
}