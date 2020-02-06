using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.RenderTree;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.JSInterop;
using Moq;
using Xunit;

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    public class AuthenticationManagerTests
    {
        private const string _action = nameof(AuthenticationManager<RemoteAuthenticationState>.Action);

        [Fact]
        public async Task AuthenticationManager_Throws_ForInvalidAction()
        {
            // Arrange
            var manager = new AuthenticationManager<RemoteAuthenticationState>();

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = ""
            });

            // Act & assert
            await Assert.ThrowsAsync<InvalidOperationException>(() => manager.SetParametersAsync(parameters));
        }

        [Fact]
        public async Task AuthenticationManager_Login_NavigatesToReturnUrlOnSuccess()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/login?returnUrl=https://www.example.com/base/fetchData");

            authServiceMock.Setup(s => s.SignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Success,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Login
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal("https://www.example.com/base/fetchData", manager.Navigation.Uri);
            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Login_DoesNothingOnRedirect()
        {
            // Arrange
            var originalUrl = "https://www.example.com/base/authentication/login?returnUrl=https://www.example.com/base/fetchData";
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(originalUrl);

            authServiceMock.Setup(s => s.SignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Redirect,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Login
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(originalUrl, manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Login_NavigatesToLoginFailureOnError()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/login?returnUrl=https://www.example.com/base/fetchData");

            authServiceMock.Setup(s => s.SignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Failure,
                    ErrorMessage = "There was an error trying to log in"
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Login
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(
                "https://www.example.com/base/authentication/login-failed?message=There was an error trying to log in",
                manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LoginCallback_ThrowsOnRedirectResult()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/login?returnUrl=https://www.example.com/base/fetchData");

            authServiceMock.Setup(s => s.CompleteSignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Redirect
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LoginCallback
            });

            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await renderer.Dispatcher.InvokeAsync<object>(async () =>
                {
                    await manager.SetParametersAsync(parameters);
                    return null;
                }));
        }

        [Fact]
        public async Task AuthenticationManager_LoginCallback_DoesNothingOnOperationCompleted()
        {
            // Arrange
            var originalUrl = "https://www.example.com/base/authentication/login-callback?code=1234";
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                originalUrl);

            authServiceMock.Setup(s => s.CompleteSignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.OperationCompleted
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LoginCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(originalUrl, manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LoginCallback_NavigatesToReturnUrlFromStateOnSuccess()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/login-callback?code=1234");

            var fetchDataUrl = "https://www.example.com/base/fetchData";
            manager.AuthenticationState.ReturnUrl = fetchDataUrl;

            authServiceMock.Setup(s => s.CompleteSignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Success,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LoginCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(fetchDataUrl, jsRuntime.LastInvocation.args[0]);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LoginCallback_NavigatesToLoginFailureOnError()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/login-callback?code=1234");

            var fetchDataUrl = "https://www.example.com/base/fetchData";
            manager.AuthenticationState.ReturnUrl = fetchDataUrl;

            authServiceMock.Setup(s => s.CompleteSignInAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Failure,
                    ErrorMessage = "There was an error trying to log in"
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LoginCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(
                "https://www.example.com/base/authentication/login-failed?message=There was an error trying to log in",
                manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Logout_NavigatesToReturnUrlOnSuccess()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout?returnUrl=https://www.example.com/base/");

            authServiceMock.Setup(s => s.GetCurrentUser())
                .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("Test")));

            authServiceMock.Setup(s => s.SignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Success,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Logout
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal("https://www.example.com/base/", jsRuntime.LastInvocation.args[0]);
            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Logout_NavigatesToDefaultReturnUrlWhenNoReturnUrlIsPresent()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout");

            authServiceMock.Setup(s => s.GetCurrentUser())
                .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("Test")));

            authServiceMock.Setup(s => s.SignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Success,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Logout
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal("https://www.example.com/base/authentication/logged-out", jsRuntime.LastInvocation.args[0]);
            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Logout_DoesNothingOnRedirect()
        {
            // Arrange
            var originalUrl = "https://www.example.com/base/authentication/login?returnUrl=https://www.example.com/base/fetchData";
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(originalUrl);

            authServiceMock.Setup(s => s.GetCurrentUser())
                .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("Test")));

            authServiceMock.Setup(s => s.SignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Redirect,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Logout
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(originalUrl, manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_Logout_NavigatesToLogoutFailureOnError()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout?returnUrl=https://www.example.com/base/fetchData");

            authServiceMock.Setup(s => s.GetCurrentUser())
                .ReturnsAsync(new ClaimsPrincipal(new ClaimsIdentity("Test")));

            authServiceMock.Setup(s => s.SignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Failure,
                    ErrorMessage = "There was an error trying to log out"
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.Logout
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(
                "https://www.example.com/base/authentication/logout-failed?message=There was an error trying to log out",
                manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LogoutCallback_ThrowsOnRedirectResult()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout-callback?returnUrl=https://www.example.com/base/fetchData");

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LogoutCallback
            });

            authServiceMock.Setup(s => s.CompleteSignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Redirect,
                });


            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await renderer.Dispatcher.InvokeAsync<object>(async () =>
                {
                    await manager.SetParametersAsync(parameters);
                    return null;
                }));
        }

        [Fact]
        public async Task AuthenticationManager_LogoutCallback_DoesNothingOnOperationCompleted()
        {
            // Arrange
            var originalUrl = "https://www.example.com/base/authentication/logout-callback?code=1234";
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                originalUrl);

            authServiceMock.Setup(s => s.CompleteSignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.OperationCompleted
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LogoutCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(originalUrl, manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LogoutCallback_NavigatesToReturnUrlFromStateOnSuccess()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout-callback-callback?code=1234");

            var fetchDataUrl = "https://www.example.com/base/fetchData";
            manager.AuthenticationState.ReturnUrl = fetchDataUrl;

            authServiceMock.Setup(s => s.CompleteSignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Success,
                    State = manager.AuthenticationState
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LogoutCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(fetchDataUrl, jsRuntime.LastInvocation.args[0]);

            authServiceMock.Verify();
        }

        [Fact]
        public async Task AuthenticationManager_LogoutCallback_NavigatesToLoginFailureOnError()
        {
            // Arrange
            var (manager, renderer, authServiceMock, jsRuntime) = CreateAuthenticationManager(
                "https://www.example.com/base/authentication/logout-callback?code=1234");

            var fetchDataUrl = "https://www.example.com/base/fetchData";
            manager.AuthenticationState.ReturnUrl = fetchDataUrl;

            authServiceMock.Setup(s => s.CompleteSignOutAsync(It.IsAny<RemoteAuthenticationContext<RemoteAuthenticationState>>()))
                .ReturnsAsync(new RemoteAuthenticationResult<RemoteAuthenticationState>()
                {
                    Status = RemoteAuthenticationStatus.Failure,
                    ErrorMessage = "There was an error trying to log out"
                });

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = RemoteAuthenticationActions.LogoutCallback
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.Equal(
                "https://www.example.com/base/authentication/logout-failed?message=There was an error trying to log out",
                manager.Navigation.Uri);

            authServiceMock.Verify();
        }

        public static TheoryData<UIValidator> DisplaysRightUIData { get; } = new TheoryData<UIValidator>
        {
            { new UIValidator {
                Action = "login", SetupAction = (validator, manager) => { manager.LoginFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "login-callback", SetupAction = (validator, manager) => { manager.LoginCallbackFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "login-failed", SetupAction = (validator, manager) => { manager.LoginFailedFragment = m => builder => validator.Render(builder); } }
            },
            { new UIValidator {
                Action = "profile", SetupAction = (validator, manager) => { manager.LoginFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "register", SetupAction = (validator, manager) => { manager.LoginFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "logout", SetupAction = (validator, manager) => { manager.LogoutFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "logout-callback", SetupAction = (validator, manager) => { manager.LogoutCallbackFragment = validator.Render; } }
            },
            { new UIValidator {
                Action = "logout-failed", SetupAction = (validator, manager) => { manager.LogoutFailedFragment = m => builder => validator.Render(builder); } }
            },
            { new UIValidator {
                Action = "logged-out", SetupAction = (validator, manager) => { manager.LoggedOutFragment = validator.Render; } }
            },
        };

        [Theory]
        [MemberData(nameof(DisplaysRightUIData))]
        public async Task AuthenticationManager_DisplaysRightUI_ForEachStateAsync(UIValidator validator)
        {
            // Arrange
            var renderer = new TestRenderer(new ServiceCollection().BuildServiceProvider());
            var manager = new TestAuthenticationManager();
            renderer.Attach(manager);
            validator.Setup(manager);

            var parameters = ParameterView.FromDictionary(new Dictionary<string, object>
            {
                [_action] = validator.Action
            });

            // Act
            await renderer.Dispatcher.InvokeAsync<object>(() => manager.SetParametersAsync(parameters));

            // Assert
            Assert.True(validator.WasCalled);
        }

        public class UIValidator
        {
            public string Action { get; set; }
            public Action<UIValidator, AuthenticationManager<RemoteAuthenticationState>> SetupAction { get; set; }
            public bool WasCalled { get; set; }
            public RenderFragment Render { get; set; }

            public UIValidator() => Render = builder => WasCalled = true;

            internal void Setup(TestAuthenticationManager manager) => SetupAction(this, manager);
        }

        private static
            (AuthenticationManager<RemoteAuthenticationState> manager,
            TestRenderer renderer,
            Mock<IRemoteAuthenticationService<RemoteAuthenticationState>> authenticationServiceMock,
            TestJsRuntime js)

            CreateAuthenticationManager(
            string currentUri,
            string baseUri = "https://www.example.com/base/")
        {
            var renderer = new TestRenderer(new ServiceCollection().BuildServiceProvider());
            var manager = new AuthenticationManager<RemoteAuthenticationState>();
            renderer.Attach(manager);

            manager.Navigation = new TestNavigationManager(
                baseUri,
                currentUri);

            manager.AuthenticationState = new RemoteAuthenticationState();
            manager.ApplicationPaths = new RemoteAuthenticationApplicationPathsOptions();

            var authenticationServiceMock = new Mock<IRemoteAuthenticationService<RemoteAuthenticationState>>();

            manager.AuthenticationService = authenticationServiceMock.Object;
            var jsRuntime = new TestJsRuntime();
            manager.JS = jsRuntime;
            return (manager, renderer, authenticationServiceMock, jsRuntime);
        }

        private class TestNavigationManager : NavigationManager
        {
            public TestNavigationManager(string baseUrl, string currentUrl) => Initialize(baseUrl, currentUrl);

            protected override void NavigateToCore(string uri, bool forceLoad) => Uri = uri;
        }

        private class TestJsRuntime : IJSRuntime
        {
            public (string identifier, object[] args) LastInvocation { get; set; }
            public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object[] args)
            {
                LastInvocation = (identifier, args);
                return default;
            }

            public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object[] args)
            {
                LastInvocation = (identifier, args);
                return default;
            }
        }

        public class TestAuthenticationManager : AuthenticationManager<RemoteAuthenticationState>
        {
            protected override Task OnParametersSetAsync() => Task.CompletedTask;
        }

        private class TestRenderer : Renderer
        {
            public TestRenderer(IServiceProvider services)
                : base(services, NullLoggerFactory.Instance)
            {
            }

            public int Attach(IComponent component) => AssignRootComponentId(component);

            private static readonly Dispatcher _dispatcher = new RendererSynchronizationContextDispatcher();

            public override Dispatcher Dispatcher => _dispatcher;

            protected override void HandleException(Exception exception)
                => ExceptionDispatchInfo.Capture(exception).Throw();

            protected override Task UpdateDisplayAsync(in RenderBatch renderBatch) =>
                Task.CompletedTask;
        }
    }
}
