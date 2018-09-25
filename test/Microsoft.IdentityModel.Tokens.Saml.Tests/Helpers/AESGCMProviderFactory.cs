using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    // Helper CryptoProviderFactory which binds to AesGcmAuthenticatedEncryptionProvider when creating AuthenticatedEncryptionProvider
    public class AesGcmProviderFactory : CryptoProviderFactory
    {
        public override AuthenticatedEncryptionProvider CreateAuthenticatedEncryptionProvider(SecurityKey key, string algorithm)
        {
            return new AesGcmAuthenticatedEncryptionProvider(key, algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            return true;
        }
    }
}
