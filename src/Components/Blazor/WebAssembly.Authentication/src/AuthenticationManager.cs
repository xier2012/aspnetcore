// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.JSInterop;

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    /// <summary>
    /// A component that handles remote authentication operations in an application.
    /// </summary>
    /// <typeparam name="TAuthenticationState">The user state type persisted while the operation is in progress. It must be serializable.</typeparam>
    public class AuthenticationManager<TAuthenticationState> : ComponentBase where TAuthenticationState : RemoteAuthenticationState
    {
        private string _message;

        /// <summary>
        /// Gets or sets the <see cref="RemoteAuthenticationActions"/> action the component needs to handle.
        /// </summary>
        [Parameter] public string Action { get; set; }

        /// <summary>
        /// Gets or sets the <typeparamref name="TAuthenticationState"/> to be preserved during the authentication operation.
        /// </summary>
        [Parameter] public TAuthenticationState AuthenticationState { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.Login"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment LoginFragment { get; set; } = DefaultLoginFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.Register"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment RegisterFragment { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.Profile"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment ProfileFragment { get; set; }

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.LoginCallback"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment LoginCallbackFragment { get; set; } = DefaultLoginCallbackFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.LoginFailed"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment<string> LoginFailedFragment { get; set; } = DefaultLoginFailedFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.Logout"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment LogoutFragment { get; set; } = DefaultLogoutFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.LogoutCallback"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment LogoutCallbackFragment { get; set; } = DefaultLogoutCallbackFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.LogoutFailed"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment<string> LogoutFailedFragment { get; set; } = DefaultLogoutFailedFragment;

        /// <summary>
        /// Gets or sets a <see cref="RenderFragment"/> with the UI to display while <see cref="RemoteAuthenticationActions.LogoutSucceeded"/> is being handled.
        /// </summary>
        [Parameter] public RenderFragment LoggedOutFragment { get; set; } = DefaultLoggedOutFragment;

        /// <summary>
        /// Gets or sets the <see cref="IJSRuntime"/> to use for performin JavaScript interop.
        /// </summary>
        [Inject] public IJSRuntime JS { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="NavigationManager"/> to use for redirecting the browser.
        /// </summary>
        [Inject] public NavigationManager Navigation { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IRemoteAuthenticationService{TRemoteAuthenticationState}"/> to use for handling the underlying authentication protocol.
        /// </summary>
        [Inject] public IRemoteAuthenticationService<TAuthenticationState> AuthenticationService { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="RemoteAuthenticationApplicationPathsOptions"/> with the paths to different authentication pages.
        /// </summary>
        [Parameter] public RemoteAuthenticationApplicationPathsOptions ApplicationPaths { get; set; }

        /// <inheritdoc />
        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            base.BuildRenderTree(builder);
            switch (Action)
            {
                case RemoteAuthenticationActions.Profile:
                case RemoteAuthenticationActions.Register:
                case RemoteAuthenticationActions.Login:
                    builder.AddContent(0, LoginFragment);
                    break;
                case RemoteAuthenticationActions.LoginCallback:
                    builder.AddContent(0, LoginCallbackFragment);
                    break;
                case RemoteAuthenticationActions.LoginFailed:
                    builder.AddContent(0, LoginFailedFragment(_message));
                    break;
                case RemoteAuthenticationActions.Logout:
                    builder.AddContent(0, LogoutFragment);
                    break;
                case RemoteAuthenticationActions.LogoutCallback:
                    builder.AddContent(0, LogoutCallbackFragment);
                    break;
                case RemoteAuthenticationActions.LogoutFailed:
                    builder.AddContent(0, LogoutFailedFragment(_message));
                    break;
                case RemoteAuthenticationActions.LogoutSucceeded:
                    builder.AddContent(0, LoggedOutFragment);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid action '{Action}'.");
            }
        }

        /// <inheritdoc />
        protected override async Task OnParametersSetAsync()
        {
            switch (Action)
            {
                case RemoteAuthenticationActions.Login:
                    await ProcessLogin(GetReturnUrl(state: null));
                    break;
                case RemoteAuthenticationActions.LoginCallback:
                    await ProcessLoginCallback();
                    break;
                case RemoteAuthenticationActions.LoginFailed:
                    _message = GetErrorMessage();
                    break;
                case RemoteAuthenticationActions.Profile:
                    if (ApplicationPaths.RemoteProfilePath == null)
                    {
                        ProfileFragment??= ProfileNotSupportedFragment;
                    }
                    else
                    {
                        ProfileFragment??= LoginFragment;
                        await RedirectToProfile();
                    }
                    break;
                case RemoteAuthenticationActions.Register:
                    if (ApplicationPaths.RemoteRegisterPath == null)
                    {
                        RegisterFragment ??= RegisterNotSupportedFragment;
                    }
                    else
                    {
                        RegisterFragment ??= LoginFragment;
                    }

                    await RedirectToRegister();
                    break;
                case RemoteAuthenticationActions.Logout:
                    await ProcessLogout(GetReturnUrl(state: null, Navigation.ToAbsoluteUri(ApplicationPaths.LogoutSucceededPath).AbsoluteUri));
                    break;
                case RemoteAuthenticationActions.LogoutCallback:
                    await ProcessLogoutCallback();
                    break;
                case RemoteAuthenticationActions.LogoutFailed:
                    _message = GetErrorMessage();
                    break;
                case RemoteAuthenticationActions.LogoutSucceeded:
                    break;
                default:
                    throw new InvalidOperationException($"Invalid action '{Action}'.");
            }
        }

        private async Task ProcessLogin(string returnUrl)
        {
            AuthenticationState.ReturnUrl = returnUrl;
            var result = await AuthenticationService.SignInAsync(new RemoteAuthenticationContext<TAuthenticationState>
            {
                State = AuthenticationState
            });
            switch (result.Status)
            {
                case RemoteAuthenticationStatus.Redirect:
                    break;
                case RemoteAuthenticationStatus.Success:
                    Navigation.NavigateTo(returnUrl);
                    break;
                case RemoteAuthenticationStatus.Failure:
                    var uri = Navigation.ToAbsoluteUri($"{ApplicationPaths.LoginFailedPath}?message={result.ErrorMessage}").ToString();
                    Navigation.NavigateTo(uri);
                    break;
                default:
                    break;
            }
        }

        private async Task ProcessLoginCallback()
        {
            var url = Navigation.Uri;
            var result = await AuthenticationService.CompleteSignInAsync(new RemoteAuthenticationContext<TAuthenticationState> { Url = url });
            switch (result.Status)
            {
                case RemoteAuthenticationStatus.Redirect:
                    // There should not be any redirects as the only time CompleteSignInAsync finishes
                    // is when we are doing a redirect sign in flow.
                    throw new InvalidOperationException("Should not redirect.");
                case RemoteAuthenticationStatus.Success:
                    await NavigateToReturnUrl(GetReturnUrl(result.State));
                    break;
                case RemoteAuthenticationStatus.OperationCompleted:
                    break;
                case RemoteAuthenticationStatus.Failure:
                    var uri = Navigation.ToAbsoluteUri($"{ApplicationPaths.LoginFailedPath}?message={result.ErrorMessage}").ToString();
                    Navigation.NavigateTo(uri);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid authentication result status '{result.Status}'.");
            }
        }

        private async Task ProcessLogout(string returnUrl)
        {
            AuthenticationState.ReturnUrl = returnUrl;
            var user = await AuthenticationService.GetCurrentUser();
            var isauthenticated = user.Identity.IsAuthenticated;

            if (isauthenticated)
            {
                var result = await AuthenticationService.SignOutAsync(new RemoteAuthenticationContext<TAuthenticationState> { State = AuthenticationState });
                switch (result.Status)
                {
                    case RemoteAuthenticationStatus.Redirect:
                        break;
                    case RemoteAuthenticationStatus.Success:
                        await NavigateToReturnUrl(returnUrl);
                        break;
                    case RemoteAuthenticationStatus.OperationCompleted:
                        break;
                    case RemoteAuthenticationStatus.Failure:
                        var uri = Navigation.ToAbsoluteUri($"{ApplicationPaths.LogoutFailedPath}?message={result.ErrorMessage}").ToString();
                        Navigation.NavigateTo(uri);
                        break;
                    default:
                        throw new InvalidOperationException($"Invalid authentication result status '{result.Status ?? "(null)"}'.");
                }
            }
        }

        private async Task ProcessLogoutCallback()
        {
            var result = await AuthenticationService.CompleteSignOutAsync(new RemoteAuthenticationContext<TAuthenticationState> { Url = Navigation.Uri });
            switch (result.Status)
            {
                case RemoteAuthenticationStatus.Redirect:
                    // There should not be any redirects as the only time completeAuthentication finishes
                    // is when we are doing a redirect sign in flow.
                    throw new InvalidOperationException("Should not redirect.");
                case RemoteAuthenticationStatus.Success:
                    await NavigateToReturnUrl(GetReturnUrl(result.State, Navigation.ToAbsoluteUri(ApplicationPaths.LogoutSucceededPath).ToString()));
                    break;
                case RemoteAuthenticationStatus.OperationCompleted:
                    break;
                case RemoteAuthenticationStatus.Failure:
                    var uri = Navigation.ToAbsoluteUri($"{ApplicationPaths.LogoutFailedPath}?message={result.ErrorMessage}").ToString();
                    Navigation.NavigateTo(uri);
                    break;
                default:
                    throw new InvalidOperationException($"Invalid authentication result status '{result.Status ?? "(null)"}'.");
            }
        }

        private string GetReturnUrl(TAuthenticationState state, string defaultReturnUrl = null)
        {
            var fromQuery = GetParameter("returnUrl");
            if (!string.IsNullOrWhiteSpace(fromQuery) && !fromQuery.StartsWith(Navigation.BaseUri))
            {
                // This is an extra check to prevent open redirects.
                throw new InvalidOperationException("Invalid return url. The return url needs to have the same origin as the current page.");
            }

            return state?.ReturnUrl ?? fromQuery ?? defaultReturnUrl ?? Navigation.BaseUri;
        }

        private string GetParameter(string key)
        {
            var queryString = new Uri(Navigation.Uri).Query;

            if (string.IsNullOrEmpty(queryString) || queryString == "?")
            {
                return null;
            }

            var scanIndex = 0;
            if (queryString[0] == '?')
            {
                scanIndex = 1;
            }

            var textLength = queryString.Length;
            var equalIndex = queryString.IndexOf('=');
            if (equalIndex == -1)
            {
                equalIndex = textLength;
            }

            while (scanIndex < textLength)
            {
                var ampersandIndex = queryString.IndexOf('&', scanIndex);
                if (ampersandIndex == -1)
                {
                    ampersandIndex = textLength;
                }

                if (equalIndex < ampersandIndex)
                {
                    while (scanIndex != equalIndex && char.IsWhiteSpace(queryString[scanIndex]))
                    {
                        ++scanIndex;
                    }
                    var name = queryString[scanIndex..equalIndex];
                    var value = queryString.Substring(equalIndex + 1, ampersandIndex - equalIndex - 1);
                    var processedName = Uri.UnescapeDataString(name.Replace('+', ' '));
                    if (string.Equals(processedName, key, StringComparison.OrdinalIgnoreCase))
                    {
                        return Uri.UnescapeDataString(value.Replace('+', ' '));
                    }

                    equalIndex = queryString.IndexOf('=', ampersandIndex);
                    if (equalIndex == -1)
                    {
                        equalIndex = textLength;
                    }
                }
                else
                {
                    if (ampersandIndex > scanIndex)
                    {
                        var value = queryString[scanIndex..ampersandIndex];
                        if (string.Equals(value, key, StringComparison.OrdinalIgnoreCase))
                        {
                            return string.Empty;
                        }
                    }
                }

                scanIndex = ampersandIndex + 1;
            }

            return null;
        }

        private async Task NavigateToReturnUrl(string returnUrl) => await JS.InvokeVoidAsync("location.replace", returnUrl);

        private ValueTask RedirectToRegister()
        {
            var loginUrl = Navigation.ToAbsoluteUri(ApplicationPaths.LoginPath).PathAndQuery;
            var registerUrl = Navigation.ToAbsoluteUri($"{ApplicationPaths.RemoteRegisterPath}?returnUrl={loginUrl}").PathAndQuery;

            return JS.InvokeVoidAsync("location.replace", registerUrl);
        }

        private ValueTask RedirectToProfile() => JS.InvokeVoidAsync("location.replace", Navigation.ToAbsoluteUri(ApplicationPaths.RemoteProfilePath).PathAndQuery);

        private string GetErrorMessage() => GetParameter("message");

        private static void DefaultLoginFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Checking login state...");
            builder.CloseElement();
        }

        private static void RegisterNotSupportedFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Registration is not supported.");
            builder.CloseElement();
        }

        private static void ProfileNotSupportedFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Editing the profile is not supported.");
            builder.CloseElement();
        }

        private static void DefaultLoginCallbackFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Completing login...");
            builder.CloseElement();
        }

        private static RenderFragment DefaultLoginFailedFragment(string message)
        {
            return builder =>
            {
                builder.OpenElement(0, "p");
                builder.AddContent(1, "There was an error trying to log you in: '");
                builder.AddContent(2, message);
                builder.AddContent(3, "'");
                builder.CloseElement();
            };
        }

        private static void DefaultLogoutFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Processing logout...");
            builder.CloseElement();
        }

        private static void DefaultLogoutCallbackFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "Processing logout callback...");
            builder.CloseElement();
        }

        private static RenderFragment DefaultLogoutFailedFragment(string message)
        {
            return builder =>
            {
                builder.OpenElement(0, "p");
                builder.AddContent(1, "There was an error trying to log you out: '");
                builder.AddContent(2, message);
                builder.AddContent(3, "'");
                builder.CloseElement();
            };
        }

        private static void DefaultLoggedOutFragment(RenderTreeBuilder builder)
        {
            builder.OpenElement(0, "p");
            builder.AddContent(1, "You successfully logged out!");
            builder.CloseElement();
        }
    }
}
