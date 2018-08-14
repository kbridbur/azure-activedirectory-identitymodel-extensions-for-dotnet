using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// This exception is thrown when SAML2 assertion encryption failed.
    /// </summary>
    public class Saml2SecurityTokenEncryptedAssertionEncryptionException : Saml2SecurityTokenEncryptedAssertionException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionEncryptionException"/> class.
        /// </summary>
        public Saml2SecurityTokenEncryptedAssertionEncryptionException()
            : base()
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionEncryptionException"/> class.
        /// </summary>
        /// <param name="message">Additional information to be included in the exception and displayed to user.</param>
        public Saml2SecurityTokenEncryptedAssertionEncryptionException(string message)
            : base(message)
        { }

        /// <summary>
        /// Initializes a new instance of the <see cref="Saml2SecurityTokenEncryptedAssertionEncryptionException"/> class.
        /// </summary>
        /// <param name="message">Additional information to be included in the exception and displayed to user.</param>
        /// <param name="innerException">A <see cref="Exception"/> that represents the root cause of the exception.</param>
        public Saml2SecurityTokenEncryptedAssertionEncryptionException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }
}
