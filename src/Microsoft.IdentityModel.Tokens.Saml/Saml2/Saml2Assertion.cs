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

using System;
using System.Collections.Generic;
using System.Xml;
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Assertion element specified in [Saml2Core, 2.3.3].
    /// see: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public class Saml2Assertion
    {
        private Saml2Id _id;
        private DateTime _issueInstant;
        private Saml2NameIdentifier _issuer;
        private Signature _signature;
        private Saml2Advice _advice;
        private Saml2Conditions _conditions;
        private string _inclusiveNamespacesPrefixList;
        private SigningCredentials _signingCredentials;
        private Saml2Subject _subject;
        private List<Saml2Statement> _statements;

        /// <summary>
        /// Creates an instance of a Saml2Assertion.
        /// </summary>
        /// <param name="issuer">Issuer of the assertion.</param>
        public Saml2Assertion(Saml2NameIdentifier issuer)
        {
            Id = new Saml2Id();
            IssueInstant = DateTime.UtcNow;
            Issuer = issuer;
            _statements = new List<Saml2Statement>();
        }

        /// <summary>
        /// Gets or sets the <see cref="Signature"/> on the Assertion.
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public Signature Signature
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Signature))));

                return _signature;
            }
            set => _signature = value;
        }

        /// <summary>
        /// Gets or sets additional information related to the assertion that assists processing in certain
        /// situations but which may be ignored by applications that do not understand the 
        /// advice or do not wish to make use of it. [Saml2Core, 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public Saml2Advice Advice
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Advice))));

                return _advice;
            }
            set => _advice = value;
        }

        /// <summary>
        /// Gets or sets conditions that must be evaluated when assessing the validity of and/or
        /// when using the assertion. [Saml2Core 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public Saml2Conditions Conditions
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Conditions))));

                return _conditions;
            }
            set => _conditions = value;
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2Id"/> identifier for this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        /// <exception cref="ArgumentNullException">if 'value' if null.</exception>
        public Saml2Id Id
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Id))));

                return _id;
            }
            set => _id = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the time instant of issue in UTC. [Saml2Core, 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        /// <exception cref="ArgumentNullException">if 'value' if null.</exception>
        public DateTime IssueInstant
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(IssueInstant))));

                return _issueInstant;
            }
            set
            {
                if (value == null)
                    throw LogArgumentNullException(nameof(value));
                else
                    _issueInstant = DateTimeUtil.ToUniversalTime(value);
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2NameIdentifier"/> as the authority that is making the claim(s) in the assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        /// <exception cref="ArgumentNullException">if 'value' if null.</exception>
        public Saml2NameIdentifier Issuer
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Issuer))));

                return _issuer;
            }
            set => _issuer = value ?? throw LogArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Gets or sets the a PrefixList to use when there is a need to include InclusiveNamespaces writing token.
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public string InclusiveNamespacesPrefixList
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(InclusiveNamespacesPrefixList))));

                return _inclusiveNamespacesPrefixList;
            }
            set => _inclusiveNamespacesPrefixList = value;
        }

        /// <summary>
        /// Gets or sets the <see cref="SigningCredentials"/> used by the issuer to protect the integrity of the assertion.
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public SigningCredentials SigningCredentials
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(SigningCredentials))));

                return _signingCredentials;
            }
            set => _signingCredentials = value;
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2Subject"/> of the statement(s) in the assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public Saml2Subject Subject
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Subject))));

                return _subject;
            }

            set => _subject = value;
        }

        /// <summary>
        /// Gets the <see cref="Saml2Statement"/>(s) regarding the subject.
        /// </summary>
        /// <exception cref="Saml2SecurityTokenEncryptedAssertionException"> If this assertion is encrypted.</exception>
        public ICollection<Saml2Statement> Statements
        {
            get
            {
                if (Encrypted)
                    throw LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionException(FormatInvariant(LogMessages.IDX13608, nameof(Statements))));

                return _statements;
            }
        }

        /// <summary>
        /// Gets the version of this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        public string Version
        {
            get => Saml2Constants.Version;
        }

        /// <summary>
        /// Gets or sets the credentials used for encrypting the assertion.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials
        {
            get;
            set;
        }

        /// <summary>
        /// Indicates if this assertion is Encrypted
        /// </summary>
        public bool Encrypted { get; internal set; } = false;

        /// <summary>
        /// String representation of this EncryptedAssertion
        /// </summary>
        public string EncryptedAssertion { get; internal set; }
    }
}
