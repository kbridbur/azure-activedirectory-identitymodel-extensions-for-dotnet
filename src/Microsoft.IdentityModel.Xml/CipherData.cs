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
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class CipherData
    {
        private byte[] _cipherValue = null;

        /// <summary>
        /// 
        /// </summary>
        public CipherData() { }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherValue"></param>
        public CipherData(byte[] cipherValue)
        {
            CipherValue = cipherValue;
        }

        /// <summary>
        /// 
        /// </summary>
        public byte[] CipherValue
        {
            get { return _cipherValue; }
            set
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));
                // if (CipherReference != null)
                //throw new CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);

                _cipherValue = (byte[])value.Clone();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        public void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.CipherData, XmlEncryptionConstants.Namespace);
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.CipherValue, XmlEncryptionConstants.Namespace);

            writer.WriteBase64(_cipherValue, 0, _cipherValue.Length);

            writer.WriteEndElement(); // CipherValue
            writer.WriteEndElement(); // CipherData
        }
    }
}
