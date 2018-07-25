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
    public class KeyVaultSignatureSecurityKey : KeyVaultSecurityKey
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        public KeyVaultSignatureSecurityKey(string keyIdentifier)
            : base(keyIdentifier, CreateClient())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="callback">The authentication callback.</param>
        public KeyVaultSignatureSecurityKey(string keyIdentifier, AuthenticationCallback callback)
            : base(keyIdentifier, CreateClient(callback))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="clientId">Identifier of the client.</param>
        /// <param name="clientSecret">Secret of the client identity.</param>
        public KeyVaultSignatureSecurityKey(string keyIdentifier, string clientId, string clientSecret)
            : base(keyIdentifier, CreateClient(clientId, clientSecret))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultSignatureSecurityKey"/> class.
        /// </summary>
        /// <param name="keyIdentifier">The key identifier.</param>
        /// <param name="client">Client class to perform cryptographic key operations and vault operations against the Key Vault service.</param>
        internal KeyVaultSignatureSecurityKey(string keyIdentifier, IKeyVaultClient client)
            : base(keyIdentifier, client)
        {
        }

        /// <summary>
        /// Creates a digital signature using Azure Key Vault.
        /// </summary>
        /// <param name="algorithm">The signing algorithm.</param>
        /// <param name="digest">The bytes to sign.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<byte[]> SignAsync(string algorithm, byte[] digest, CancellationToken cancellation)
        {
            var keyOperation = await _client.SignAsync(_bundle.KeyIdentifier.Identifier, algorithm, digest, cancellation).ConfigureAwait(false);
            return keyOperation.Result;
        }

        /// <summary>
        /// Verifies a digital signature using Azure Key Vault.
        /// </summary>
        /// <param name="algorithm">The signing algorithm.</param>
        /// <param name="digest">The bytes to verify.</param>
        /// <param name="signature">The expected signature.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        public async Task<bool> VerifyAsync(string algorithm, byte[] digest, byte[] signature, CancellationToken cancellation)
        {
            return await _client.VerifyAsync(_bundle.KeyIdentifier.Identifier, algorithm, digest, signature, cancellation);
        }
    }
}
