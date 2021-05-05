/*
 * BSD 3-Clause License
 *
 * Copyright (c) 2021, Kevin Robertson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

using Quiddity.SPNEGO;
using Quiddity.Support;
using System;
using System.IO;

namespace Quiddity.NTLM
{
    class NTLMNegotiate
    {
        public byte[] Signature { get; set; }
        public uint MessageType { get; set; }
        public byte[] NegotiateFlags { get; set; }
        public ushort DomainNameLen { get; set; }
        public ushort DomainNameMaxLen { get; set; }
        public uint DomainNameBufferOffset { get; set; }
        public ushort WorkstationLen { get; set; }
        public ushort WorkstationMaxLen { get; set; }
        public uint WorkstationBufferOffset { get; set; }
        public byte[] Version { get; set; }
        public byte[] Payload { get; set; }

        internal NTLMNegotiate()
        {
            this.Signature = new byte[8] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 }; // NTLMSSP
            this.MessageType = 1;
            this.NegotiateFlags = new byte[4] { 0x97, 0x82, 0x08, 0xe2 };
            this.DomainNameLen = 0;
            this.DomainNameMaxLen = 0;
            this.DomainNameBufferOffset = 0;
            this.WorkstationLen = 0;
            this.WorkstationMaxLen = 0;
            this.WorkstationBufferOffset = 0;
            this.Version = new byte[8] { 0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f };
            this.Payload = new byte[8];
        }

        internal NTLMNegotiate ReadBytes(byte[] Data, int Position)
        {

            using (MemoryStream memoryStream = new MemoryStream(Data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = Position;
                this.Signature = packetReader.ReadBytes(8);
                this.MessageType = packetReader.ReadUInt16();
                this.DomainNameLen = packetReader.ReadUInt16();
                this.DomainNameMaxLen = packetReader.ReadUInt16();
                this.DomainNameBufferOffset = packetReader.ReadUInt16();
                this.DomainNameLen = packetReader.ReadUInt16();
                this.DomainNameMaxLen = packetReader.ReadUInt16();
                this.DomainNameBufferOffset = packetReader.ReadUInt16();
                this.NegotiateFlags = packetReader.ReadBytes(4);
                this.Version = packetReader.ReadBytes(8);
                this.Payload = packetReader.ReadBytes(16);
                return this;
            }

        }

        internal SPNEGONegTokenInit Decode(byte[] Data)
        {
            SPNEGONegTokenInit packet = new SPNEGONegTokenInit();
            packet.MechTypes = ASN1.GetTagBytes(6, Data);
            packet.MechToken = ASN1.GetTagBytes(4, Data);
            return packet;
        }

        internal NTLMNegotiate Unpack(byte[] Data)
        {
            SPNEGONegTokenInit token = new SPNEGONegTokenInit();
            token = this.Decode(Data);
            this.ReadBytes(token.MechToken, 0);
            return this;
        }

    }

}
