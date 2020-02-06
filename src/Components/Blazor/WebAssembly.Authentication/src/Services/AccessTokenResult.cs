// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    /// <summary>
    /// Represents the result of trying to provision an access token.
    /// </summary>
    public class AccessTokenResult
    {
        /// <summary>
        /// Gets or sets the status of the current operation. See <see cref="AccessTokenResultStatus"/> for a list of statuses.
        /// </summary>
        public string Status { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="AccessToken"/> if <see cref="Status"/> was <see cref="AccessTokenResultStatus.Success"/>.
        /// </summary>
        public AccessToken Token { get; set; }

        /// <summary>
        /// Gets or sets the redirect url to navigate to if <see cref="Status"/> was <see cref="AccessTokenResultStatus.RequiresRedirect"/>.
        /// </summary>
        public string RedirectUrl { get; set; }
    }
}
