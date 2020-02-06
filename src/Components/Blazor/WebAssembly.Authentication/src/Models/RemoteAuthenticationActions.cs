// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    /// <summary>
    /// Represents the list of authentication actions that can be performed by the <see cref="AuthenticationManager{TAuthenticationState}"/>.
    /// </summary>
    public class RemoteAuthenticationActions
    {
        /// <summary>
        /// The login action.
        /// </summary>
        public const string Login = "login";

        /// <summary>
        /// The login callback action.
        /// </summary>
        public const string LoginCallback = "login-callback";

        /// <summary>
        /// The login failed action.
        /// </summary>
        public const string LoginFailed = "login-failed";

        /// <summary>
        /// The navigate to user profile action.
        /// </summary>
        public const string Profile = "profile";

        /// <summary>
        /// The navigate to register action.
        /// </summary>
        public const string Register = "register";

        /// <summary>
        /// The logout action.
        /// </summary>
        public const string Logout = "logout";

        /// <summary>
        /// The logout callback action.
        /// </summary>
        public const string LogoutCallback = "logout-callback";

        /// <summary>
        /// The logout failed action.
        /// </summary>
        public const string LogoutFailed = "logout-failed";

        /// <summary>
        /// The logout succeeded action.
        /// </summary>
        public const string LogoutSucceeded = "logged-out";

        /// <summary>
        /// Whether or not a given <paramref name="candidate"/> represents a given <see cref="RemoteAuthenticationActions"/>.
        /// </summary>
        /// <param name="action">The <see cref="RemoteAuthenticationActions"/>.</param>
        /// <param name="candidate">The candidate.</param>
        /// <returns>Whether or not is the given <see cref="RemoteAuthenticationActions"/> action.</returns>
        public static bool IsAction(string action, string candidate) => action != null && string.Equals(action, candidate, System.StringComparison.OrdinalIgnoreCase);
    }
}
