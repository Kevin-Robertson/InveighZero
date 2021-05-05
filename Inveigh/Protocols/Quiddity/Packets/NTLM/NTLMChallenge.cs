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
using System;
using System.Text;
using System.IO;
using Quiddity.Support;
using Quiddity.SPNEGO;

namespace Quiddity.NTLM
{
    class NTLMChallenge
    {
        //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
        public byte[] Signature { get; set; }
        public uint MessageType { get; set; }
        public ushort TargetNameLen { get; set; }
        public ushort TargetNameMaxLen { get; set; }
        public uint TargetNameBufferOffset { get; set; }
        public byte[] NegotiateFlags { get; set; }
        public byte[] ServerChallenge { get; set; }
        public UInt64 Reserved { get; set; }
        public ushort TargetInfoLen { get; set; }
        public ushort TargetInfoMaxLen { get; set; }
        public uint TargetInfoBufferOffset { get; set; }
        public byte[] Version { get; set; }
        public byte[] Payload { get; set; }

        internal NTLMChallenge()
        {
            this.Signature = new byte[8] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 }; // NTLMSSP
            this.MessageType = 2;
            this.TargetNameLen = 0;
            this.TargetNameMaxLen = 0;
            this.TargetNameBufferOffset = 56;
            this.NegotiateFlags = new byte[4] { 0x15, 0x82, 0x8a, 0xe2 };
            this.ServerChallenge = new byte[16];
            this.Reserved = 0;
            this.TargetInfoLen = 0;
            this.TargetInfoMaxLen = 0;
            this.TargetInfoBufferOffset = 0;
            this.Version = new byte[8] { 0x0a, 0x00, 0x61, 0x4a, 0x00, 0x00, 0x00, 0x0f };
            this.Payload = new byte[0];
        }

        internal NTLMChallenge ReadBytes(byte[] Data, int Position)
        {

            using (MemoryStream memoryStream = new MemoryStream(Data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = Position;
                this.Signature = packetReader.ReadBytes(8);
                this.MessageType = packetReader.ReadUInt16();
                this.TargetNameLen = packetReader.ReadUInt16();
                this.TargetNameMaxLen = packetReader.ReadUInt16();
                this.TargetNameBufferOffset = packetReader.ReadUInt16();
                this.NegotiateFlags = packetReader.ReadBytes(4);
                this.ServerChallenge = packetReader.ReadBytes(16);
                this.Reserved = packetReader.ReadUInt64();
                this.TargetInfoLen = packetReader.ReadUInt16();
                this.TargetInfoMaxLen = packetReader.ReadUInt16();
                this.TargetInfoBufferOffset = packetReader.ReadUInt32();
                this.Version = packetReader.ReadBytes(8);
                this.Payload = packetReader.ReadBytes(16);
                return this;
            }

        }

        internal byte[] GetBytes(string TargetName)
        {
            byte[] TargetNameData = Encoding.Unicode.GetBytes(TargetName);
            this.TargetNameLen = (ushort)TargetNameData.Length;
            this.TargetNameMaxLen = this.TargetNameLen;
            this.TargetInfoLen = (ushort)this.Payload.Length;
            this.TargetInfoMaxLen = this.TargetInfoLen;
            this.TargetInfoBufferOffset = (ushort)(TargetNameData.Length + 56);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(this.Signature);
                packetWriter.Write(this.MessageType);
                packetWriter.Write(this.TargetNameLen);
                packetWriter.Write(this.TargetNameMaxLen);
                packetWriter.Write(this.TargetNameBufferOffset);
                packetWriter.Write(this.NegotiateFlags);
                packetWriter.Write(this.ServerChallenge);
                packetWriter.Write(this.Reserved);
                packetWriter.Write(this.TargetInfoLen);
                packetWriter.Write(this.TargetInfoMaxLen);
                packetWriter.Write(this.TargetInfoBufferOffset);
                packetWriter.Write(this.Version);
                packetWriter.Write(TargetNameData);
                packetWriter.Write(this.Payload);
                return memoryStream.ToArray();
            }

        }

        internal byte[] Encode(byte[] Data)
        {
            SPNEGONegTokenResp packet = new SPNEGONegTokenResp();
            packet.NegState = 1;
            packet.SupportedMech = new byte[10] { 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };
            byte[] segment1 = ASN1.Encode(0x04, Data);
            segment1 = ASN1.Encode(0xa2, segment1);
            byte[] segment2 = ASN1.Encode(0x06, packet.SupportedMech);
            segment2 = ASN1.Encode(0xa1, segment2);         
            byte[] segment3 = ASN1.Encode(0x0a, new byte[1] { packet.NegState });
            segment3 = ASN1.Encode(0xa0, segment3);
            byte[] asn1Data = Utilities.BlockCopy(segment3, segment2, segment1);
            asn1Data = ASN1.Encode(0x30, asn1Data);
            asn1Data = ASN1.Encode(0xa1, asn1Data);
            return asn1Data;
        }

        internal SPNEGONegTokenResp Decode(byte[] Data)
        {
            SPNEGONegTokenResp packet = new SPNEGONegTokenResp();
            packet.NegState = ASN1.GetTagBytes(1, Data)[0];
            packet.SupportedMech = ASN1.GetTagBytes(6, Data);
            packet.ResponseToken = ASN1.GetTagBytes(4, Data);
            return packet;
        }

        internal byte[] Challenge(string Challenge)
        {
            byte[] challengeData = new byte[8];
            string challenge = "";

            if (String.IsNullOrEmpty(Challenge))
            {
                string challengeCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                char[] challengeCharactersArray = new char[8];
                Random random = new Random();

                for (int i = 0; i < challengeCharactersArray.Length; i++)
                {
                    challengeCharactersArray[i] = challengeCharacters[random.Next(challengeCharacters.Length)];
                }

                string finalString = new String(challengeCharactersArray);
                challengeData = Encoding.UTF8.GetBytes(finalString);
                challenge = (BitConverter.ToString(challengeData)).Replace("-", "");
            }
            else
            {
                challenge = Challenge;
                string challengeMod = challenge.Insert(2, "-").Insert(5, "-").Insert(8, "-").Insert(11, "-").Insert(14, "-").Insert(17, "-").Insert(20, "-");
                int i = 0;

                foreach (string character in challengeMod.Split('-'))
                {
                    challengeData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                    i++;
                }

            }

            return challengeData;
        }

    }

}
