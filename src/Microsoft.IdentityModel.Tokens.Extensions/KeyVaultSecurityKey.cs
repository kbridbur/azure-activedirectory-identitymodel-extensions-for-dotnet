//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

namespace Microsoft.IdentityModel.Tokens.Extensions
{
    using System;
    using System.Collections;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.KeyVault.Models;
    using Microsoft.Azure.Services.AppAuthentication;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.IdentityModel.Logging;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Provides signing and verifying operations using Azure Key Vault.
    /// </summary>
    public abstract class KeyVaultSecurityKey : SecurityKey, IDisposable
    {
        private protected readonly IKeyVaultClient _client;
        private protected readonly KeyBundle _bundle;
        private readonly int _keySize;
        private bool _disposed = false;

        /// <summary>
        /// The authentication callback delegate which is to be implemented by the client code.
        /// </summary>
        /// <param name="authority">Identifier of the authority, a URL.</param>
        /// <param name="resource">Identifier of the target resource that is the recipient of the requested token, a URL.</param>
        /// <param name="scope">The scope of the authentication request.</param>
        /// <returns>An access token for Azure Key Vault.</returns>
        public delegate Task<string> AuthenticationCallback(string authority, string resource, string scope);

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="client">Client class to perform cryptographic key operations and vault operations against the Key Vault service.</param>
        private protected KeyVaultSecurityKey(string keyIdentifier, IKeyVaultClient client)
        {
            _client = client ?? throw LogHelper.LogArgumentNullException(nameof(client));
            _bundle = _client.GetKeyAsync(keyIdentifier, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
            _keySize = (new BitArray(_bundle.Key.N)).Length;
        }

        /// <summary>
        /// The size of the security key.
        /// </summary>
        public override int KeySize => _keySize;

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _client.Dispose();
        }

        /// <summary>
        /// Creates a <see cref="KeyVaultClient"/> using Managed Service Identity.
        /// </summary>
        /// <returns>A client class to perform cryptographic key operations and vault operations against the Key Vault service.</returns>
        private protected static KeyVaultClient CreateClient()
        {
            var azureServiceTokenProvider = new AzureServiceTokenProvider();
            var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
            return new KeyVaultClient(authenticationCallback);
        }

        /// <summary>
        /// Creates a <see cref="KeyVaultClient"/> using a custom callback delegate.
        /// </summary>
        /// <param name="callback">The authentication callback.</param>
        /// <returns>A client class to perform cryptographic key operations and vault operations against the Key Vault service.</returns>
        private protected static KeyVaultClient CreateClient(AuthenticationCallback callback)
        {
            return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(callback));
        }

        /// <summary>
        /// Creates a <see cref="KeyVaultClient"/> using client credentials.
        /// </summary>
        /// <param name="clientId">Identifier of the client requesting the token.</param>
        /// <param name="clientSecret">Secret of the client requesting the token.</param>
        /// <returns>A client class to perform cryptographic key operations and vault operations against the Key Vault service.</returns>
        private protected static KeyVaultClient CreateClient(string clientId, string clientSecret)
        {
            var clientCredential = new ClientCredential(clientId, clientSecret);
            return new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(async (string authority, string resource, string scope) =>
            {
                var context = new AuthenticationContext(authority, TokenCache.DefaultShared);
                var result = await context.AcquireTokenAsync(resource, clientCredential);
                return result.AccessToken;
            }));
        }
    }
}
