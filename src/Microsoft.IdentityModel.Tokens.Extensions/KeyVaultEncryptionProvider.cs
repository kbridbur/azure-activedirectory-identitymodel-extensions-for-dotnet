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
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.Azure.KeyVault;
    using Microsoft.Azure.KeyVault.WebKey;
    using Microsoft.IdentityModel.Logging;
    using Microsoft.IdentityModel.Tokens;

    /// <summary>
    /// Provides wrap and unwrap operations using Azure Key Vault.
    /// </summary>
    public class KeyVaultEncryptionProvider : AuthenticatedEncryptionProvider, IDisposable
    {
        private readonly IKeyVaultClient _client;
        private readonly KeyVaultSecurityKey _key;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyVaultEncryptionProvider"/> class.
        /// </summary>
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for signature operations.</param>
        /// <param name="algorithm">The signature algorithm to apply.</param>
        public KeyVaultEncryptionProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        {
            _key = key as KeyVaultSecurityKey ?? throw LogHelper.LogArgumentException<ArgumentException>(nameof(key), $"");
            _client = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(_key.Callback));
        }

        /// <summary>
        /// Decrypts ciphertext into plaintext
        /// </summary>
        /// <param name="ciphertext">the encrypted text to decrypt.</param>
        /// <param name="authenticatedData">the authenticateData that is used in verification.</param>
        /// <param name="iv">the initialization vector used when creating the ciphertext.</param>
        /// <param name="authenticationTag">the authenticationTag that was created during the encyption.</param>
        /// <returns>decrypted ciphertext</returns>
        public override byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            return DecryptAsync(ciphertext, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                _disposed = true;
                _client.Dispose();
            }
        }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            return Encrypt(plaintext, authenticatedData, iv: null);
        }

        /// <summary>
        /// Encrypts the 'plaintext'
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <param name="iv">initialization vector for encryption.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData, byte[] iv)
        {
            return EncryptAsync(plaintext, authenticatedData, iv, CancellationToken.None).ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Called to obtain the byte[] needed to create a <see cref="KeyedHashAlgorithm"/>
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/>that will be used to obtain the byte[].</param>
        /// <returns><see cref="byte"/>[] that is used to populated the KeyedHashAlgorithm.</returns>
        protected override byte[] GetKeyBytes(SecurityKey key)
        {
            if (key is KeyVaultSecurityKey keyVaultSecurityKey)
                return keyVaultSecurityKey.SymmetricKey;

            return base.GetKeyBytes(key);
        }

        /// <summary>
        /// Checks if an 'key, algorithm' pair is supported
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <param name="algorithm">the algorithm to check.</param>
        /// <returns>true if 'key, algorithm' pair is supported.</returns>
        protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            return key is KeyVaultSecurityKey
                && JsonWebKeyEncryptionAlgorithm.AllAlgorithms.Contains(algorithm, StringComparer.Ordinal);
        }

        /// <summary>
        /// Checks that the key has sufficient length
        /// </summary>
        /// <param name="key"><see cref="SecurityKey"/> that contains bytes.</param>
        /// <param name="algorithm">the algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">if 'key' is null.</exception>
        /// <exception cref="ArgumentNullException">if 'algorithm' is null or empty.</exception>
        protected override void ValidateKeySize(SecurityKey key, string algorithm)
        {
            base.ValidateKeySize(key, algorithm);
        }

        /// <summary>
        /// Decrypts cipher text data using Azure Key Vault.
        /// </summary>
        /// <param name="ciphertext">the encrypted text to decrypt.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns></returns>
        private async Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken cancellation)
        {
            return (await _client.DecryptAsync(_key.KeyId, Algorithm, ciphertext, cancellation).ConfigureAwait(false)).Result;
        }

        /// <summary>
        /// Encrypts plain text data using Azure Key Vault.
        /// </summary>
        /// <param name="plaintext">the data to be encrypted.</param>
        /// <param name="authenticatedData">will be combined with iv and ciphertext to create an authenticationtag.</param>
        /// <param name="iv">initialization vector for encryption.</param>
        /// <param name="cancellation">Propagates notification that operations should be canceled.</param>
        /// <returns><see cref="AuthenticatedEncryptionResult"/>containing ciphertext, iv, authenticationtag.</returns>
        private async Task<AuthenticatedEncryptionResult> EncryptAsync(byte[] plaintext, byte[] authenticatedData, byte[] iv, CancellationToken cancellation)
        {
            return new AuthenticatedEncryptionResult(Key, (await _client.EncryptAsync(_key.KeyId, Algorithm, plaintext, cancellation).ConfigureAwait(false)).Result, iv, authenticationTag: null);
        }
    }
}
