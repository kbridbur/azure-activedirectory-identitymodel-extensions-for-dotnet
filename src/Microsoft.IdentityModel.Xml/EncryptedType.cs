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

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the abstract base class from which the classes EncryptedData and EncryptedKey derive.
    /// </summary>
    /// <remarks>
    /// http://www.w3.org/TR/2013/REC-xmlenc-core1-20130411/#sec-EncryptedType
    /// </remarks>
    public abstract class EncryptedType
    {
        private CipherData _cipherData;
        private KeyInfo _keyInfo;

        /// <summary>
        /// Gets or sets the <see cref="CipherData"/> value for an instance of an <see cref="EncryptedType"/> class.
        /// </summary>
        public virtual CipherData CipherData
        {
            get
            {
                if (_cipherData == null)
                    _cipherData = new CipherData();

                return _cipherData;
            }
            set
            {
                _cipherData = value ?? throw new ArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual string Id { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public virtual string Type { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public virtual string MimeType { get; set; }
        /// <summary>
        /// 
        /// </summary>
        public virtual string Encoding { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public KeyInfo KeyInfo
        {
            get
            {
                if (_keyInfo == null)
                    _keyInfo = new KeyInfo();
                return _keyInfo;
            }
            set { _keyInfo = value; }
        }

        /// <summary>
        /// 
        /// </summary>
        public virtual EncryptionMethod EncryptionMethod { get; set; }
    }
}
