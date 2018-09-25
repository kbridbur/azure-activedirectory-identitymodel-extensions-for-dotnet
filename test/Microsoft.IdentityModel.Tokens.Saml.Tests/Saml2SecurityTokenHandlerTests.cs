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
using System.Security.Claims;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class Saml2SecurityTokenHandlerTests
    {
        [Fact]
        public void Constructors()
        {
            var saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
        }

        [Fact]
        public void Defaults()
        {
            var samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Assert.True(samlSecurityTokenHandler.MaximumTokenSizeInBytes == TokenValidationParameters.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
        }

        [Fact]
        public void GetSets()
        {
            var samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("MaximumTokenSizeInBytes", new List<object>{(object)TokenValidationParameters.DefaultMaximumTokenSizeInBytes, (object)1000, (object)10}),
                    new KeyValuePair<string, List<object>>("SetDefaultTimesOnTokenCreation", new List<object>{true, false, true}),
                    new KeyValuePair<string, List<object>>("TokenLifetimeInMinutes", new List<object>{(object)60, (object)1000, (object)10}),
                },
                Object = samlSecurityTokenHandler
            };

            TestUtilities.GetSet(context);

            samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException("IDX10101:"), context);
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected, context);
            TestUtilities.SetGet(samlSecurityTokenHandler, "Serializer", null, ExpectedException.ArgumentNullException(), context);

            TestUtilities.AssertFailIfErrors("Saml2SecurityTokenHandlerTests_GetSets", context.Errors);
        }

        [Theory, MemberData(nameof(CanReadTokenTheoryData))]
        public void CanReadToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CanReadToken", theoryData);
            var context = new CompareContext($"{this}.CanReadToken, {theoryData}");
            try
            {
                // TODO - need to pass actual Saml2Token
                if (theoryData.CanRead != theoryData.Handler.CanReadToken(theoryData.Token))
                    Assert.False(true, $"Expected CanRead != CanRead, token: {theoryData.Token}");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> CanReadTokenTheoryData
        {
            get => new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    CanRead = false,
                    First = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = "Null Token",
                    Token = null
                },
                new Saml2TheoryData
                {
                    CanRead = false,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = "DefaultMaximumTokenSizeInBytes + 1",
                    Token = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 2)
                },
                new Saml2TheoryData
                {
                    CanRead = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                    Token = ReferenceTokens.Saml2Token_Valid
                },
                new Saml2TheoryData
                {
                    CanRead = false,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.SamlToken_Valid),
                    Token = ReferenceTokens.SamlToken_Valid
                },
                new Saml2TheoryData
                {
                    CanRead = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid
                }
            };
        }

        [Theory, MemberData(nameof(ConsolidateAttributesTheoryData))]
        public void ConsolidateAttributes(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ConsolidateAttributes", theoryData);
            var context = new CompareContext($"{this}.ConsolidateAttributes, {theoryData}");
            var handler = theoryData.Handler as Saml2SecurityTokenHandlerPublic;
            try
            {
                var consolidatedAttributes = handler.ConsolidateAttributesPublic(theoryData.Attributes);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEnumsEqual(consolidatedAttributes, theoryData.ConsolidatedAttributes, context, AreSaml2AttributesEqual);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ConsolidateAttributesTheoryData
        {
            get
            {
                var theoryData = new TheoryData<Saml2TheoryData>
                {
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        First = true,
                        TestId = "param attributes null"
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>(),
                        ConsolidatedAttributes = new List<Saml2Attribute>(),
                        TestId = "Empty Attribute List"
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue
                        },
                        ConsolidatedAttributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue
                        },
                        TestId = nameof(Default.Saml2AttributeSingleValue)
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue,
                            Default.Saml2AttributeSingleValue
                        },
                        ConsolidatedAttributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeMultiValue
                        },
                        TestId = nameof(Default.Saml2AttributeMultiValue)
                    }
                };

                var attribute = Default.Saml2AttributeSingleValue;
                attribute.AttributeValueXsiType = Guid.NewGuid().ToString();
                theoryData.Add(CreateAttributeTheoryData(attribute, "AttributeValueXsiType"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.FriendlyName = Guid.NewGuid().ToString();
                theoryData.Add(CreateAttributeTheoryData(attribute, "FriendlyName"));

                attribute = new Saml2Attribute(Guid.NewGuid().ToString(), Guid.NewGuid().ToString());
                theoryData.Add(CreateAttributeTheoryData(attribute, "Name, Value"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.NameFormat = new Uri(Default.Uri);
                theoryData.Add(CreateAttributeTheoryData(attribute, "NameFormat"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.OriginalIssuer = NotDefault.OriginalIssuer;
                theoryData.Add(CreateAttributeTheoryData(attribute, "OrginalIssuer"));

                return theoryData;
            }
        }

        private static Saml2TheoryData CreateAttributeTheoryData(Saml2Attribute attribute, string testId)
        {
            return new Saml2TheoryData
            {
                Attributes = new List<Saml2Attribute>
                {
                    Default.Saml2AttributeSingleValue,
                    attribute,
                    Default.Saml2AttributeSingleValue,
                },
                ConsolidatedAttributes = new List<Saml2Attribute>
                {
                    Default.Saml2AttributeMultiValue,
                    attribute
                },
                TestId = testId
            };
        }

        public static bool AreSaml2AttributesEqual(Saml2Attribute attribute1, Saml2Attribute attribute2, CompareContext context)
        {
            var localContext = new CompareContext("AreSaml2AttributesEqual");
            if (!IdentityComparer.ContinueCheckingEquality(attribute1, attribute2, localContext))
                return context.Merge(localContext);

            IdentityComparer.AreStringsEqual(attribute1.AttributeValueXsiType, attribute2.AttributeValueXsiType, localContext);
            IdentityComparer.AreStringsEqual(attribute1.FriendlyName, attribute2.FriendlyName, localContext);
            IdentityComparer.AreStringsEqual(attribute1.Name, attribute2.Name, localContext);
            IdentityComparer.AreStringsEqual(attribute1.NameFormat?.AbsoluteUri, attribute2.NameFormat?.AbsoluteUri, localContext);
            IdentityComparer.AreStringsEqual(attribute1.OriginalIssuer, attribute2.OriginalIssuer, localContext);

            return context.Merge(localContext);
        }

        [Theory, MemberData(nameof(ReadTokenTheoryData))]
        public void ReadToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadToken", theoryData);
            var context = new CompareContext($"{this}.ReadToken, {theoryData}");
            try
            {
                theoryData.Handler.ReadToken(theoryData.Token);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ReadTokenTheoryData
        {
            get
            {
                return new TheoryData<Saml2TheoryData>
                {
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        First = true,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                        Token = ReferenceTokens.Saml2Token_Valid
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_InclusiveNamespaces_WithPrefix),
                        Token = ReferenceTokens.Saml2Token_InclusiveNamespaces_WithPrefix
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_InclusiveNamespaces_WithoutPrefix),
                        Token = ReferenceTokens.Saml2Token_InclusiveNamespaces_WithoutPrefix
                    }
                };
            }
        }

        [Theory, MemberData(nameof(RoundTripTokenTheoryData))]
        public void RoundTripToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripToken", theoryData);
            try
            {
                var samlToken = theoryData.Handler.CreateToken(theoryData.TokenDescriptor);
                var token = theoryData.Handler.WriteToken(samlToken);
                var principal = theoryData.Handler.ValidateToken(token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> RoundTripTokenTheoryData
        {
            get => new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    First = true,
                    TestId = nameof(Default.ClaimsIdentity),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = Default.AsymmetricSigningKey,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    }
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.RsaSigningCreds_2048),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.RsaSigningCreds_2048,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.RsaSigningCreds_2048_Public.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    },
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.RsaSigningCreds_2048_FromRsa),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.RsaSigningCreds_2048_FromRsa,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.RsaSigningCreds_2048_FromRsa_Public.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    },
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.JsonWebKeyRsa256SigningCredentials),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256PublicSigningCredentials.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    }
                }
            };
        }

        [Theory, MemberData(nameof(RoundTripActorTheoryData))]
        public void RoundTripActor(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.RoundTripActor", theoryData);
            CompareContext context = new CompareContext($"{this}.RoundTripActor, {theoryData}");

            var handler = theoryData.Handler as Saml2SecurityTokenHandlerPublic;
            var actor = handler.CreateActorStringPublic(theoryData.TokenDescriptor.Subject);
        }

        [Theory, MemberData(nameof(WriteTokenTheoryData))]
        public void WriteToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteToken", theoryData);
            context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
            {
                { typeof(Saml2Assertion), new List<string> { "IssueInstant", "InclusiveNamespacesPrefixList", "Signature", "SigningCredentials" } },
                { typeof(Saml2SecurityToken), new List<string> { "SigningKey" } },
            };

            try
            {
                var token = theoryData.Handler.WriteToken(theoryData.SecurityToken);
                theoryData.Handler.ValidateToken(token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(validatedToken, theoryData.SecurityToken, context);
                if (!string.IsNullOrEmpty(theoryData.InclusiveNamespacesPrefixList))
                {
                    if (!string.Equals(theoryData.InclusiveNamespacesPrefixList, (theoryData.SecurityToken as Saml2SecurityToken).Assertion.InclusiveNamespacesPrefixList))
                        context.Diffs.Add("!string.Equals(theoryData.InclusivePrefixList, (theoryData.SecurityToken as Saml2SecurityToken).Assertion.InclusivePrefixList)");

                    if (!string.Equals(theoryData.InclusiveNamespacesPrefixList, (validatedToken as Saml2SecurityToken).Assertion.Signature.SignedInfo.References[0].CanonicalizingTransfrom.InclusiveNamespacesPrefixList))
                        context.Diffs.Add("!string.Equals(theoryData.InclusivePrefixList, (validatedToken as Saml2SecurityToken).Assertion.Signature.SignedInfo.References[0].CanonicalizingTransfrom.InclusivePrefixList))");
                }
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> WriteTokenTheoryData
        {
            get
            {
                var key = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_128;

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    NotBefore = Default.NotBefore,
                    Expires = Default.Expires,
                    Issuer = Default.Issuer,
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                    Subject = new ClaimsIdentity(Default.SamlClaims)
                };

                var tokenDescriptorWithPreSharedEncryptingCredentials = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    NotBefore = Default.NotBefore,
                    Expires = Default.Expires,
                    Issuer = Default.Issuer,
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                    Subject = new ClaimsIdentity(Default.SamlClaims)
                };

                var tokenDescriptorWithEncryptingCredentials = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    NotBefore = Default.NotBefore,
                    Expires = Default.Expires,
                    Issuer = Default.Issuer,
                    SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                    Subject = new ClaimsIdentity(Default.SamlClaims)
                };

                var validationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "Federation",
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    IssuerSigningKey = key
                };

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                var token = tokenHandler.CreateToken(tokenDescriptor) as Saml2SecurityToken;
                token.Assertion.InclusiveNamespacesPrefixList = "#default saml ds xml";

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    InclusiveNamespacesPrefixList = "#default saml ds xml",
                    SecurityToken = token,
                    TestId = "WithInclusivePrefixList",
                    ValidationParameters = validationParameters
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptorWithPreSharedEncryptingCredentials) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(ArgumentNullException)),
                    TestId = "EncryptedAssertion_PreSharedKey",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptorWithEncryptingCredentials) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(ArgumentNullException)),
                    TestId = "EncryptedAssertion_KeyWrap",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor),
                    TestId = "WithoutInclusivePrefixList",
                    ValidationParameters = validationParameters
                });

                validationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "Federation",
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyValidator = ValidationDelegates.IssuerSecurityKeyValidatorThrows,
                    IssuerSigningKey = key
                };

                theoryData.Add(new Saml2TheoryData
                {
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSigningKeyException)),
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor),
                    TestId = nameof(ValidationDelegates.IssuerSecurityKeyValidatorThrows),
                    ValidationParameters = validationParameters
                });

                validationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "Federation",
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = false,
                    IssuerSigningKeyValidator = ValidationDelegates.IssuerSecurityKeyValidatorThrows,
                    IssuerSigningKey = key
                };

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor),
                    TestId = nameof(ValidationDelegates.IssuerSecurityKeyValidatorThrows) + "-false",
                    ValidationParameters = validationParameters
                });

                validationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "Federation",
                    ValidateAudience = true,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = false,
                    AudienceValidator = ValidationDelegates.AudienceValidatorThrows,
                    IssuerSigningKey = key
                };

                theoryData.Add(new Saml2TheoryData
                {
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidAudienceException)),
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor),
                    TestId = nameof(ValidationDelegates.AudienceValidatorThrows),
                    ValidationParameters = validationParameters
                });

                validationParameters = new TokenValidationParameters
                {
                    AuthenticationType = "Federation",
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = false,
                    AudienceValidator = ValidationDelegates.AudienceValidatorThrows,
                    IssuerSigningKey = key
                };

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor),
                    TestId = nameof(ValidationDelegates.AudienceValidatorThrows) + "-false",
                    ValidationParameters = validationParameters
                });

                return theoryData;
            }
        }

        public static TheoryData<Saml2TheoryData> RoundTripActorTheoryData
        {
            get => new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    First = true,
                    Handler = new Saml2SecurityTokenHandlerPublic(),
                    TestId = nameof(ClaimSets.DefaultClaimsIdentity),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = ClaimSets.DefaultClaimsIdentity
                    }
                }
            };
        }

        // Test checks to make sure that default times are correctly added to the token
        // upon token creation.
        [Fact]
        public void SetDefaultTimesOnTokenCreation()
        {
            TestUtilities.WriteHeader($"{this}.SetDefaultTimesOnTokenCreation");
            var context = new CompareContext();

            var tokenHandler = new Saml2SecurityTokenHandler();
            var descriptorNoTimeValues = new SecurityTokenDescriptor()
            {
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Subject = new ClaimsIdentity()
            };

            var token = tokenHandler.CreateToken(descriptorNoTimeValues);
            var saml2SecurityToken = token as Saml2SecurityToken;

            Assert.NotEqual(DateTime.MinValue, saml2SecurityToken.ValidFrom);
            Assert.NotEqual(DateTime.MinValue, saml2SecurityToken.ValidTo);
        }

        [Theory, MemberData(nameof(ValidateAudienceTheoryData))]
        public void ValidateAudience(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAudience", theoryData);
            var context = new CompareContext($"{this}.ValidateAudience, {theoryData}");
            try
            {
                (theoryData.Handler as Saml2SecurityTokenHandlerPublic).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateAudienceTheoryData
        {
            get
            {
                var tokenTheoryData = new List<TokenTheoryData>();
                var theoryData = new TheoryData<Saml2TheoryData>();

                ValidateTheoryData.AddValidateAudienceTheoryData(tokenTheoryData);
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new Saml2TheoryData(item)
                    {
                        Handler = new Saml2SecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateIssuerTheoryData))]
        public void ValidateIssuer(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateIssuer", theoryData);
            var context = new CompareContext($"{this}.ValidateAudience, {theoryData}");
            try
            {
                (theoryData.Handler as Saml2SecurityTokenHandlerPublic).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateIssuerTheoryData
        {
            get
            {
                var tokenTheoryData = new List<TokenTheoryData>();
                ValidateTheoryData.AddValidateIssuerTheoryData(tokenTheoryData);

                var theoryData = new TheoryData<Saml2TheoryData>();
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new Saml2TheoryData(item)
                    {
                        Handler = new Saml2SecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateTokenTheoryData))]
        public void ValidateToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);
            var context = new CompareContext($"{this}.ValidateToken, {theoryData}");
            ClaimsPrincipal retVal = null;
            try
            {
                retVal = theoryData.Handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateTokenTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<Saml2TheoryData>
                {
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX10209:"),
                        Handler = new Saml2SecurityTokenHandler { MaximumTokenSizeInBytes = 1 },
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_MissingVersion),
                        Token = ReferenceTokens.Saml2Token_MissingVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13137:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_VersionNotV20),
                        Token = ReferenceTokens.Saml2Token_VersionNotV20,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IdMissing),
                        Token = ReferenceTokens.Saml2Token_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssueInstantMissing),
                        Token = ReferenceTokens.Saml2Token_IssueInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13102:", typeof(FormatException)),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssueInstantFormatError),
                        Token = ReferenceTokens.Saml2Token_IssueInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13102:", typeof(XmlReadException)),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssuerMissing),
                        Token = ReferenceTokens.Saml2Token_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13108:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_NoSubjectNoStatements),
                        Token = ReferenceTokens.Saml2Token_NoSubjectNoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13138:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_NoAttributes),
                        Token = ReferenceTokens.Saml2Token_NoAttributes,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey set",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Valid_Spaces_Added),
                        Token = ReferenceTokens.Saml2Token_Valid_Spaces_Added,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Formated),
                        Token = ReferenceTokens.Saml2Token_Formated,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey Rsa",
                        Token = ReferenceTokens.Saml2Token_Valid_WithRsaKeyValue,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultRsaSecurityKey2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey JsonWithCertificate",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultJsonWebKeyWithCertificate2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey JsonWithParameters",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultJsonWebKeyWithParameters2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_AttributeTampered),
                        Token = ReferenceTokens.Saml2Token_AttributeTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_DigestTampered),
                        Token = ReferenceTokens.Saml2Token_DigestTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    // Removed until we have a way of matching a SecurityKey with a KeyInfo.
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_AttributeTampered_NoKeyMatch),
                        Token = ReferenceTokens.Saml2Token_AttributeTampered_NoKeyMatch,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_SignatureTampered),
                        Token = ReferenceTokens.Saml2Token_SignatureTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_SignatureMissing),
                        Token = ReferenceTokens.Saml2Token_SignatureMissing,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            RequireSignedTokens = false,
                        }
                    }
                };
            }
        }

        #region EncryptedAssertion

        [Theory, MemberData(nameof(AccessEncryptedAssertionTheoryData))]
        public void AccessEncryptedAssertion(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.AccessEncryptedAssertion", theoryData);

            try
            {
                var token = theoryData.Handler.ReadSaml2Token(theoryData.Token);

                IdentityComparer.AreEqual(token.Assertion.Encrypted, true, context); // saml2 assertion is encrypted hence Assertion.Encrypted should be True

                if (string.IsNullOrEmpty(token.Assertion.EncryptedAssertion))
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                var result = token.Assertion.GetType().GetProperty(theoryData.PropertyBag["AssertionPropertyName"].ToString()).GetValue(token.Assertion, null);

                IdentityComparer.AreEqual(result, theoryData.PropertyBag["AssertionPropertyExpectedValue"], context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex.InnerException, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> AccessEncryptedAssertionTheoryData
        {
            get
            {
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Advice" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Advice'"),
                    TestId = "EncryptedAssertion_Access_Advice",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Conditions" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Conditions'"),
                    TestId = "EncryptedAssertion_Access_Conditions",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Id" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Id'"),
                    TestId = "EncryptedAssertion_Access_Id",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "IssueInstant" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'IssueInstant'"),
                    TestId = "EncryptedAssertion_Access_IssueInstantConditions",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Issuer" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Issuer'"),
                    TestId = "EncryptedAssertion_Access_Issuer",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "InclusiveNamespacesPrefixList" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'InclusiveNamespacesPrefixList'"),
                    TestId = "EncryptedAssertion_Access_InclusiveNamespacesPrefixList",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "SigningCredentials" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'SigningCredentials'"),
                    TestId = "EncryptedAssertion_Access_SigningCredentials",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Subject" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Subject'"),
                    TestId = "EncryptedAssertion_Access_Subject",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Statements" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Statements'"),
                    TestId = "EncryptedAssertion_Access_Statements",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Signature" } },
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionException), "IDX13608: Saml2Assertion is encrypted. Unable to get 'Signature'"),
                    TestId = "EncryptedAssertion_Access_Signature",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "Version" }, { "AssertionPropertyExpectedValue", "2.0" } },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_Access_Version",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    PropertyBag = new Dictionary<string, object> { { "AssertionPropertyName", "EncryptingCredentials" }, { "AssertionPropertyExpectedValue", null} },
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_Access_EncryptingCredentials",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ReadEncryptedTokenTheoryData))]
        public void ReadEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadEncryptedToken", theoryData);

            try
            {
                var saml2EncryptedToken = theoryData.Handler.ReadSaml2Token(theoryData.Token);
                IdentityComparer.AreEqual(saml2EncryptedToken.Assertion.Encrypted, true, context); // token should be encrypted

                if (string.IsNullOrEmpty(saml2EncryptedToken.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.Handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken); // validate/decrypt token

                IdentityComparer.AreEqual(((Saml2SecurityToken)validatedToken).Assertion.Encrypted, false, context); // token should be decrypted

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ReadEncryptedTokenTheoryData
        {
            get
            {
                // list keys
                var signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var wrongSessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_192;
                var wrongKeyWrapKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA512;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials_Valid = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);
                var encryptingCredentials_PreSharedSessionKey_Valid = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_Valid = new X509EncryptingCredentials(cert);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials_PreSharedSessionKey_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_Valid.CryptoProviderFactory = new AesGcmProviderFactory();

                var tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_Valid);
                var tokenDescriptor_KeyWrap_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_Valid);

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_ExtraSpaces_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_ExtraSpaces_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_DifferentPrefixes_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_DifferentPrefixes_Valid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid),
                });

                // Bad content. For AES-GCM: IV takes 12 bytes, Auth Tag 16 bytes => Cipher-text size is less than 1
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenDecryptionFailedException), "IDX10620: Decryption failed."),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadContent_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadContent_Invalid),
                });

                // namespace missing
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoXencNamespace_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoXencNamespace_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v2_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v2_Invalid),
                });

                // namespace missing or as expected
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v3_Invalid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_BadNamespace_v3_Invalid),
                });

                // Additional KeyInfo clauses (skipped while reading) should result with a valid EncryptedAssertion
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_AdditionalKeyInfoClauseValid,
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_AdditionalKeyInfoClauseValid),
                });

                // EncryptedKey element embedded in EncryptedData element is not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EmbeddedEncryptedKey_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30029"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EmbeddedEncryptedKey_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptionAlgorithm_v2_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_Invalid),
                });

                // Encryption algorithm is not provided - currently not supported
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13611"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoEncryptionAlgorithm_v2_Invalid),
                });

                // DataReference element is not referencing the EncryptedData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadDataReference_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13616"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadDataReference_Invalid),
                });

                // DataReference element is correct, but referencing EncryptedData element has no Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_GoodDataReference_EncryptedData_NoId_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13615"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_GoodDataReference_EncryptedData_NoId_Invalid),
                });

                // EncryptedData element has a RetreivalUri but the is no EncryptedKey with that Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13618"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_Invalid),
                });

                // EncryptedData element has a correct RetreivalUri but the is EncryptedKey has no Id
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_NoKeyId_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13617"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadRetrievalUri_NoKeyId_Invalid),
                });

                // Type of EncryptedData is not correct
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedDataType_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13613"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedDataType_Invalid),
                });

                // Type of EncryptedKey is not correct
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedKeyType_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13614"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_BadEncryptedKeyType_Invalid),
                });

                // There is no CipherValue element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherValue_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherValue_Invalid),
                });

                // There is no CipherData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherData_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoCipherData_Invalid),
                });

                // There is no EncryptedData element
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptedData_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NoEncryptedData_Invalid),
                });

                // There is no CipherValue element (content)
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_Invalid),
                });

                // There is no CipherValue element (KeyWrap)
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_v2_Invalid,
                    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_NoCipherValue_v2_Invalid),
                });

                // incorrect keywrap key
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, wrongKeyWrapKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenKeyWrapException), "IDX10659"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_Valid) + "_wrong_keyunwrap_key",
                });

                // some prefixes are missing/wrong
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_PrefixMissing_Invalid,
                    ExpectedException = new ExpectedException(typeof(System.Xml.XmlException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_PrefixMissing_Invalid),
                });

                // namespace is missing/wrong
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NamespaceMissing_Invalid,
                    ExpectedException = new ExpectedException(typeof(System.Xml.XmlException)),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_NamespaceMissing_Invalid),
                });

                // Uncomment tests below - when AES-GCM is released and supported
                /*
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, wrongSessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenEncryptionFailedException), "IDX10618"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid) + "_wrong_decrypting_session_key",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_192_Invalid,
                    ExpectedException = new ExpectedException(typeof(ArgumentOutOfRangeException), "IDX10653"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_192_Invalid) + "_wrong_decrypting_session_key",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EncryptionAlgorithmNotSupported_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_KeyWrap_EncryptionAlgorithmNotSupported_Invalid),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey),
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionAlgorithmNotSupported_Invalid,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    TestId = nameof(ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_EncryptionAlgorithmNotSupported_Invalid),
                });
                */

                // Throws as unsupported AES-GCM is used - remove when AES-GCM is released and supported
                var encryptingCredentials_PreSharedSessionKey_AESGCM = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var validationParams = CreateTokenValidationParameters(signingKey, sessionKey);
                validationParams.CryptoProviderFactory = null;
                tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AESGCM);
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionDecryptionException), "IDX13623"),
                    ValidationParameters = validationParams,
                    Token = ReferenceTokens.Saml2Token_EncryptedAssertion_SessionKey_Valid,
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AESGCM",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteEncryptedTokenTheoryData))]
        public void WriteEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteEncryptedToken", theoryData);

            try
            {
                var token = theoryData.Handler.WriteToken(theoryData.SecurityToken);
                var saml2Token = theoryData.Handler.ReadSaml2Token(token);
                IdentityComparer.AreEqual(saml2Token.Assertion.Encrypted, true, context); // token should be encrypted

                if (string.IsNullOrEmpty(saml2Token.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> WriteEncryptedTokenTheoryData
        {
            get
            {
                // list keys used
                var key = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials_Valid = new SigningCredentials(key, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

                // encrypting credentials (Pre_Shared for one scenario and KeyWrap for another one)
                var encryptingCredentials_PreSharedSessionKey_Valid = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_Valid = new X509EncryptingCredentials(cert);
                var encryptingCredentials_X509_AlgNotSupported = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_X509_EncNotSupported = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128CbcHmacSha256);
                var encryptingCredentials_PreSharedSessionKey_AlgNotNone = new EncryptingCredentials(sessionKey, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128Gcm);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials_PreSharedSessionKey_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_Valid.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_AlgNotSupported.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_X509_EncNotSupported.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_PreSharedSessionKey_AlgNotNone.CryptoProviderFactory = new AesGcmProviderFactory();

                // token descriptors (Pre_Shared for one scenario and KeyWrap for another one)
                var tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_Valid);
                var tokenDescriptor_KeyWrap_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_Valid);
                var tokenDescriptor_KeyWrap_AlgotithmNotSupported = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_AlgNotSupported);
                var tokenDescriptor_KeyWrap_EncNotSupported = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_X509_EncNotSupported);
                var tokenDescriptor_PreSharedSessionKey_AlgotithmNotNone = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AlgNotNone);

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_PreSharedSessionKey_Valid",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_Valid) as Saml2SecurityToken,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = "EncryptedAssertion_KeyWrap_Valid",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_AlgotithmNotSupported) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13627"),
                    TestId = "EncryptedAssertion_KeyWrap_AlgNotSupported",
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_EncNotSupported) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13625"),
                    TestId = "EncryptedAssertion_KeyWrap_EncNotSupported",
                });

                // when pre-shared session key is being used, Algorithm should be set to None
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_AlgotithmNotNone) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13626"),
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AlgNotNone",
                });

                // Throws as unsupported AES-GCM is used - remove when AES-GCM is released and supported
                var encryptingCredentials_PreSharedSessionKey_AESGCM = new EncryptingCredentials(sessionKey, SecurityAlgorithms.Aes128Gcm);
                tokenDescriptor_PreSharedSessionKey_Valid = CreateTokenDescriptor(signingCredentials_Valid, encryptingCredentials_PreSharedSessionKey_AESGCM);
                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_PreSharedSessionKey_Valid) as Saml2SecurityToken,
                    ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenEncryptedAssertionEncryptionException), "IDX13601"),
                    TestId = "EncryptedAssertion_PreSharedSessionKey_AESGCM",
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(RoundTripEncryptedTokenTheoryData))]
        public void RoundTripEncryptedToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteEncryptedToken", theoryData);
            context.PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
             {
                 { typeof(Saml2Assertion), new List<string> { "IssueInstant", "Signature", "SigningCredentials", "EncryptingCredentials" } },
                 { typeof(Saml2SecurityToken), new List<string> { "SigningKey" } },
             };

            try
            {
                var token = theoryData.Handler.WriteToken(theoryData.SecurityToken);
                var saml2Token = theoryData.Handler.ReadSaml2Token(token);

                IdentityComparer.AreEqual(saml2Token.Assertion.Encrypted, true); // token should be encrypted
                if (string.IsNullOrEmpty(saml2Token.Assertion.EncryptedAssertion)) // if token is encrypted, EncryptedAssertion string should not be empty
                    context.Diffs.Add("!Assertion.EncryptedAssertion string should not be empty if Saml2Assertion.Encrypted == True");

                theoryData.Handler.ValidateToken(token, theoryData.ValidationParameters, out SecurityToken validatedToken); // validate/decrypt token
                IdentityComparer.AreEqual(validatedToken, theoryData.SecurityToken, context); // validated/decrypted token should be equal to the same token which was not encrypted
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> RoundTripEncryptedTokenTheoryData
        {
            get
            {
                // list keys
                var signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
                var sessionKey128 = KeyingMaterial.DefaultSymmetricSecurityKey_128;
                var sessionKey192 = KeyingMaterial.DefaultSymmetricSecurityKey_192;
                var sessionKey256 = KeyingMaterial.DefaultSymmetricSecurityKey_256;
                var cert = KeyingMaterial.DefaultCert_2048;

                var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest);

                // encrypting credentials (Pre_Shared for one scenario and KeyWrap for another one)
                var encryptingCredentials128_PreShared = new EncryptingCredentials(sessionKey128, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials192_PreShared = new EncryptingCredentials(sessionKey192, SecurityAlgorithms.Aes192Gcm);
                var encryptingCredentials256_PreShared = new EncryptingCredentials(sessionKey256, SecurityAlgorithms.Aes256Gcm);
                var encryptingCredentials_KeyWrap_128_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes128Gcm);
                var encryptingCredentials_KeyWrap_192_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes192Gcm);
                var encryptingCredentials_KeyWrap_256_RSAOAEP = new X509EncryptingCredentials(cert, SecurityAlgorithms.RsaOaepMgf1pKeyWrap, SecurityAlgorithms.Aes256Gcm);

                //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
                encryptingCredentials128_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials192_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials256_PreShared.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_128_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_192_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();
                encryptingCredentials_KeyWrap_256_RSAOAEP.CryptoProviderFactory = new AesGcmProviderFactory();

                // token descriptors (Pre_Shared for one scenario and KeyWrap for another one)
                var tokenDescriptor_128_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials128_PreShared);
                var tokenDescriptor_192_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials192_PreShared);
                var tokenDescriptor_256_PreShared = CreateTokenDescriptor(signingCredentials, encryptingCredentials256_PreShared);
                var tokenDescriptor_KeyWrap_128_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_128_RSAOAEP);
                var tokenDescriptor_KeyWrap_192_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_192_RSAOAEP);
                var tokenDescriptor_KeyWrap_256_RSAOAEP = CreateTokenDescriptor(signingCredentials, encryptingCredentials_KeyWrap_256_RSAOAEP);

                var tokenDescriptor_KeyWrap_Signed = new SecurityTokenDescriptor
                {
                    Audience = Default.Audience,
                    NotBefore = Default.NotBefore,
                    Expires = Default.Expires,
                    Issuer = Default.Issuer,
                    EncryptingCredentials = new X509EncryptingCredentials(KeyingMaterial.DefaultCert_2048), // encrypt with 'one-time-use' session key and wrap a session key using public cert
                    SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest),
                    Subject = new ClaimsIdentity(Default.SamlClaims)
                };

                var tokenHandler = new Saml2SecurityTokenHandler();
                var theoryData = new TheoryData<Saml2TheoryData>();

                // test both scenarios and test all supported combinations (sessionKey-keywrapKey) in KeyWrap scenario
                theoryData.Add(new Saml2TheoryData
                {
                    First = true,
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_128_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey128),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_128_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_192_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey192),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_192_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_256_PreShared) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, sessionKey256),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_256_PreShared),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_128_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_128_RSAOAEP),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_192_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_192_RSAOAEP),
                });

                theoryData.Add(new Saml2TheoryData
                {
                    SecurityToken = tokenHandler.CreateToken(tokenDescriptor_KeyWrap_256_RSAOAEP) as Saml2SecurityToken,
                    ValidationParameters = CreateTokenValidationParameters(signingKey, KeyingMaterial.DefaultX509Key_2048_With_KeyId),
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    TestId = nameof(tokenDescriptor_KeyWrap_256_RSAOAEP),
                });

                return theoryData;
            }
        }

        // helper method to create a common SecurityTokenDescriptor
        private static SecurityTokenDescriptor CreateTokenDescriptor(SigningCredentials signingCredentials, EncryptingCredentials encryptingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Default.Audience,
                NotBefore = Default.NotBefore,
                Expires = Default.Expires,
                Issuer = Default.Issuer,
                SigningCredentials = signingCredentials,
                EncryptingCredentials = encryptingCredentials,
                Subject = new ClaimsIdentity(Default.SamlClaims),
            };
        }

        // helper method to create a common TokenValidationParameters
        private static TokenValidationParameters CreateTokenValidationParameters(SecurityKey signingKey, SecurityKey decryptionKey)
        {
            return new TokenValidationParameters
            {
                IssuerSigningKey = signingKey,
                TokenDecryptionKey = decryptionKey,
                ValidAudience = Default.Audience,
                ValidIssuer = Default.Issuer,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                ValidateActor = false,
                CryptoProviderFactory = new AesGcmProviderFactory(), // //SET HELPER CRYPTO PROVIDER FACTORY - remove when AES-GCM is released and supported
            };
        }

        #endregion
    }

    public class Saml2SecurityTokenHandlerPublic : Saml2SecurityTokenHandler
    {
        public ICollection<Saml2Attribute> ConsolidateAttributesPublic(ICollection<Saml2Attribute> attributes)
        {
            return ConsolidateAttributes(attributes);
        }

        public string CreateActorStringPublic(ClaimsIdentity identity)
        {
            return CreateActorString(identity);
        }

        public void ProcessAttributeStatementPublic(Saml2AttributeStatement statement, ClaimsIdentity identity, string issuer)
        {
            ProcessAttributeStatement(statement, identity, issuer);
        }

        public string ValidateIssuerPublic(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return base.ValidateIssuer(issuer, token, validationParameters);
        }

        public void ValidateAudiencePublic(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            base.ValidateAudience(audiences, token, validationParameters);
        }
    }

    public class Saml2SecurityTokenPublic : Saml2SecurityToken
    {
        public Saml2SecurityTokenPublic(Saml2Assertion assertion)
            : base(assertion)
        {
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
