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
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault;

    /// <summary>
    /// Provides signing and verifying operations using Azure Key Vault.
    /// </summary>
    public class KeyVaultKeyWrapSecurityKey : KeyVaultSecurityKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultKeyWrapSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        public KeyVaultKeyWrapSecurityKey(string keyIdentifier)
            : base(keyIdentifier, CreateClient())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultKeyWrapSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="callback">The authentication callback.</param>
        public KeyVaultKeyWrapSecurityKey(string keyIdentifier, AuthenticationCallback callback)
            : base(keyIdentifier, CreateClient(callback))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultKeyWrapSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="clientId">Identifier of the client.</param>
        /// <param name="clientSecret">Secret of the client identity.</param>
        public KeyVaultKeyWrapSecurityKey(string keyIdentifier, string clientId, string clientSecret)
            : base(keyIdentifier, CreateClient(clientId, clientSecret))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultKeyWrapSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="client">Client class to perform cryptographic key operations and vault operations against the Key Vault service.</param>
        internal KeyVaultKeyWrapSecurityKey(string keyIdentifier, IKeyVaultClient client)
            : base(keyIdentifier, client)
        {
        }

        /// <summary>
        /// Wraps a symmetric key using Azure Key Vault.
        /// </summary>
        /// <param name="algorithm">The key wrap algorithm.</param>
        /// <param name="key">The bytes to wrap.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<byte[]> WrapKeyAsync(string algorithm, byte[] key, CancellationToken cancellation)
        {
            var keyOperation = await _client.WrapKeyAsync(_bundle.KeyIdentifier.Identifier, algorithm, key, cancellation).ConfigureAwait(false);
            return keyOperation.Result;
        }

        /// <summary>
        /// Unwraps a symmetric key using Azure Key Vault.
        /// </summary>
        /// <param name="algorithm">The key wrap algorithm.</param>
        /// <param name="wrappedKey">The bytes to unwrap.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<byte[]> UnwrapKeyAsync(string algorithm, byte[] wrappedKey, CancellationToken cancellation)
        {
            var keyOperation = await _client.UnwrapKeyAsync(_bundle.KeyIdentifier.Identifier, algorithm, wrappedKey, cancellation);
            return keyOperation.Result;
        }
    }
}
