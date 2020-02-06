// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace Microsoft.AspNetCore.Components.WebAssembly.Authentication
{
    /// <summary>
    /// Represents the minimal amount of authentication state to be preserved during authentication operations.
    /// </summary>
    public class RemoteAuthenticationState
    {
        /// <summary>
        /// Gets or sets the return url to redirect the application to after a successful authentication operation.
        /// It must be a url within the page.
        /// </summary>
        public string ReturnUrl { get; set; }
    }
}
