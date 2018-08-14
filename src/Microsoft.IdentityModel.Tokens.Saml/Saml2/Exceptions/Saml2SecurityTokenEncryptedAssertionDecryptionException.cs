using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// This exception is thrown when SAML2 assertion decryption failed.
    /// </summary>
    public class Saml2SecurityTokenEncryptedAssertionDecryptionException : Saml2SecurityTokenEncryptedAssertionException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionDecryptionException"/> class.
        /// </summary>
        public Saml2SecurityTokenEncryptedAssertionDecryptionException()
            : base()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionDecryptionException"/> class.
        /// </summary>
        /// <param name="message">Additional information to be included in the exception and displayed to user.</param>
        public Saml2SecurityTokenEncryptedAssertionDecryptionException(string message)
            : base(message)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionDecryptionException"/> class.
        /// </summary>
        /// <param name="message">Additional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public Saml2SecurityTokenEncryptedAssertionDecryptionException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }
}
