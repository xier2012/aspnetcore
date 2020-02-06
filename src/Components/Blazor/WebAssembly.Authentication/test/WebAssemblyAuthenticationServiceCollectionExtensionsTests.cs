using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Blazor.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    public class WebAssemblyAuthenticationServiceCollectionExtensionsTests
    {
        [Fact]
        public void CanResolve_AccessTokenProvider()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            host.Services.GetRequiredService<IAccessTokenProvider>();
        }

        [Fact]
        public void CanResolve_IRemoteAuthenticationService()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            host.Services.GetRequiredService<IRemoteAuthenticationService<RemoteAuthenticationState>>();
        }

        [Fact]
        public void CanCreate_DefaultAuthenticationManager()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            var componentFactory = new ComponentFactory();
            componentFactory.InstantiateComponent(host.Services, typeof(AuthenticationManager<RemoteAuthenticationState>));
        }

        [Fact]
        public void ApiAuthorizationOptions_ConfigurationDefaultsGetApplied()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization();
            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<ApiAuthorizationProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("authentication/login", paths.LoginPath);
            Assert.Equal("authentication/login-callback", paths.LoginCallbackPath);
            Assert.Equal("authentication/login-failed", paths.LoginFailedPath);
            Assert.Equal("authentication/register", paths.RegisterPath);
            Assert.Equal("authentication/profile", paths.ProfilePath);
            Assert.Equal("Identity/Account/Register", paths.RemoteRegisterPath);
            Assert.Equal("Identity/Account/Manage", paths.RemoteProfilePath);
            Assert.Equal("authentication/logout", paths.LogoutPath);
            Assert.Equal("authentication/logout-callback", paths.LogoutCallbackPath);
            Assert.Equal("authentication/logout-failed", paths.LogoutFailedPath);
            Assert.Equal("authentication/logged-out", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("Microsoft.AspNetCore.Components.WebAssembly.Authentication.Tests", user.AuthenticationType);
            Assert.Equal("scope", user.ScopeClaim);
            Assert.Equal("scope", user.RoleClaim);
            Assert.Equal("name", user.NameClaim);

            Assert.Equal(
                "_configuration/Microsoft.AspNetCore.Components.WebAssembly.Authentication.Tests",
                options.Value.ProviderOptions.ConfigurationEndpoint);
        }

        [Fact]
        public void ApiAuthorizationOptions_DefaultsCanBeOverriden()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddApiAuthorization(options =>
            {
                options.AuthenticationPaths = new RemoteAuthenticationApplicationPathsOptions
                {
                    LoginPath = "a",
                    LoginCallbackPath = "a",
                    LoginFailedPath = "a",
                    RegisterPath = "a",
                    ProfilePath = "a",
                    RemoteRegisterPath = "a",
                    RemoteProfilePath = "a",
                    LogoutPath = "a",
                    LogoutCallbackPath = "a",
                    LogoutFailedPath = "a",
                    LogoutSucceededPath = "a",
                };
                options.UserOptions = new RemoteAuthenticationUserOptions
                {
                    AuthenticationType = "a",
                    ScopeClaim = "a",
                    RoleClaim = "a",
                    NameClaim = "a",
                };
                options.ProviderOptions = new ApiAuthorizationProviderOptions
                {
                    ConfigurationEndpoint = "a"
                };
            });

            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<ApiAuthorizationProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("a", paths.LoginPath);
            Assert.Equal("a", paths.LoginCallbackPath);
            Assert.Equal("a", paths.LoginFailedPath);
            Assert.Equal("a", paths.RegisterPath);
            Assert.Equal("a", paths.ProfilePath);
            Assert.Equal("a", paths.RemoteRegisterPath);
            Assert.Equal("a", paths.RemoteProfilePath);
            Assert.Equal("a", paths.LogoutPath);
            Assert.Equal("a", paths.LogoutCallbackPath);
            Assert.Equal("a", paths.LogoutFailedPath);
            Assert.Equal("a", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("a", user.AuthenticationType);
            Assert.Equal("a", user.ScopeClaim);
            Assert.Equal("a", user.RoleClaim);
            Assert.Equal("a", user.NameClaim);

            Assert.Equal("a", options.Value.ProviderOptions.ConfigurationEndpoint);
        }

        [Fact]
        public void OidcOptions_ConfigurationDefaultsGetApplied()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.Replace(ServiceDescriptor.Singleton<NavigationManager, TestNavigationManager>());
            builder.Services.AddOidcAuthentication(options => { });
            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<OidcProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("authentication/login", paths.LoginPath);
            Assert.Equal("authentication/login-callback", paths.LoginCallbackPath);
            Assert.Equal("authentication/login-failed", paths.LoginFailedPath);
            Assert.Equal("authentication/register", paths.RegisterPath);
            Assert.Equal("authentication/profile", paths.ProfilePath);
            Assert.Null(paths.RemoteRegisterPath);
            Assert.Null(paths.RemoteProfilePath);
            Assert.Equal("authentication/logout", paths.LogoutPath);
            Assert.Equal("authentication/logout-callback", paths.LogoutCallbackPath);
            Assert.Equal("authentication/logout-failed", paths.LogoutFailedPath);
            Assert.Equal("authentication/logged-out", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Null(user.AuthenticationType);
            Assert.Null(user.ScopeClaim);
            Assert.Null(user.RoleClaim);
            Assert.Equal("name", user.NameClaim);

            var provider = options.Value.ProviderOptions;
            Assert.Null(provider.Authority);
            Assert.Null(provider.ClientId);
            Assert.Equal(new[] { "openid", "profile" }, provider.DefaultScopes);
            Assert.Equal("https://www.example.com/base/authentication/login-callback", provider.RedirectUri);
            Assert.Equal("https://www.example.com/base/authentication/logout-callback", provider.PostLogoutRedirectUri);
        }

        [Fact]
        public void OidcOptions_DefaultsCanBeOverriden()
        {
            var builder = WebAssemblyHostBuilder.CreateDefault();
            builder.Services.AddOidcAuthentication(options =>
            {
                options.AuthenticationPaths = new RemoteAuthenticationApplicationPathsOptions
                {
                    LoginPath = "a",
                    LoginCallbackPath = "a",
                    LoginFailedPath = "a",
                    RegisterPath = "a",
                    ProfilePath = "a",
                    RemoteRegisterPath = "a",
                    RemoteProfilePath = "a",
                    LogoutPath = "a",
                    LogoutCallbackPath = "a",
                    LogoutFailedPath = "a",
                    LogoutSucceededPath = "a",
                };
                options.UserOptions = new RemoteAuthenticationUserOptions
                {
                    AuthenticationType = "a",
                    ScopeClaim = "a",
                    RoleClaim = "a",
                    NameClaim = "a",
                };
                options.ProviderOptions = new OidcProviderOptions
                {
                    Authority = "a",
                    ClientId = "a",
                    DefaultScopes = Array.Empty<string>(),
                    RedirectUri = "https://www.example.com/base/custom-login",
                    PostLogoutRedirectUri = "https://www.example.com/base/custom-logout",
                };
            });

            var host = builder.Build();

            var options = host.Services.GetRequiredService<IOptions<RemoteAuthenticationOptions<OidcProviderOptions>>>();

            var paths = options.Value.AuthenticationPaths;

            Assert.Equal("a", paths.LoginPath);
            Assert.Equal("a", paths.LoginCallbackPath);
            Assert.Equal("a", paths.LoginFailedPath);
            Assert.Equal("a", paths.RegisterPath);
            Assert.Equal("a", paths.ProfilePath);
            Assert.Equal("a", paths.RemoteRegisterPath);
            Assert.Equal("a", paths.RemoteProfilePath);
            Assert.Equal("a", paths.LogoutPath);
            Assert.Equal("a", paths.LogoutCallbackPath);
            Assert.Equal("a", paths.LogoutFailedPath);
            Assert.Equal("a", paths.LogoutSucceededPath);

            var user = options.Value.UserOptions;
            Assert.Equal("a", user.AuthenticationType);
            Assert.Equal("a", user.ScopeClaim);
            Assert.Equal("a", user.RoleClaim);
            Assert.Equal("a", user.NameClaim);

            var provider = options.Value.ProviderOptions;
            Assert.Equal("a", provider.Authority);
            Assert.Equal("a", provider.ClientId);
            Assert.Equal(Array.Empty<string>(), provider.DefaultScopes);
            Assert.Equal("https://www.example.com/base/custom-login", provider.RedirectUri);
            Assert.Equal("https://www.example.com/base/custom-logout", provider.PostLogoutRedirectUri);
        }

        private class TestNavigationManager : NavigationManager
        {
            public TestNavigationManager()
            {
                Initialize("https://www.example.com/base/", "https://www.example.com/base/counter");
            }

            protected override void NavigateToCore(string uri, bool forceLoad) => throw new System.NotImplementedException();
        }
    }
}
