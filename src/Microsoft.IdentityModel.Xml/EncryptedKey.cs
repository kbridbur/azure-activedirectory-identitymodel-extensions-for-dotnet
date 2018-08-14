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

using System.Collections.Generic;
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// 
    /// </summary>
    public sealed class EncryptedKey : EncryptedType
    {
        private string _recipient;
        private IList<EncryptedReference> _referenceList;

        /// <summary>
        /// 
        /// </summary>
        public EncryptedKey() { }

        /// <summary>
        /// 
        /// </summary>
        public string Recipient
        {
            get
            {
                // an unspecified value for an XmlAttribute is string.Empty
                if (_recipient == null)
                    _recipient = string.Empty;
                return _recipient;
            }
            set
            {
                _recipient = value;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public string CarriedKeyName { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public IList<EncryptedReference> ReferenceList
        {
            get
            {
                if (_referenceList == null)
                    _referenceList = new List<EncryptedReference>();
                return _referenceList;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dataReference"></param>
        public void AddReference(DataReference dataReference)
        {
            ReferenceList.Add(dataReference);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="keyReference"></param>
        public void AddReference(KeyReference keyReference)
        {
            ReferenceList.Add(keyReference);
        }

        internal void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement(XmlEncryptionConstants.Prefix, XmlEncryptionConstants.Elements.EncryptedData, XmlEncryptionConstants.Namespace);
            //
            writer.WriteEndElement();
        }
    }
}
