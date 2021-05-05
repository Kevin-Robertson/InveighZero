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
using System.IO;

namespace Quiddity.DNS
{
    class DNSHeader
    {

        // https://tools.ietf.org/html/rfc1035
        public byte[] ID { get; set; }
        public byte[] QR { get; set; }
        public ushort QDCOUNT { get; set; }
        public ushort ANCOUNT { get; set; }
        public ushort NSCOUNT { get; set; }
        public ushort ARCOUNT { get; set; }

        internal DNSHeader()
        {
            this.ID = new byte[2];
            this.QR = new byte[2];
            this.QDCOUNT = 0;
            this.ANCOUNT = 0;
            this.NSCOUNT = 0;
            this.ARCOUNT = 0;
        }

        internal void ReadBytes(byte[] Data, int Position)
        {

            using (MemoryStream memoryStream = new MemoryStream(Data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = Position;
                this.ID = packetReader.ReadBytes(2);
                this.QR = packetReader.ReadBytes(2);
                this.QDCOUNT = packetReader.BigEndianReadUInt16();
                this.ANCOUNT = packetReader.BigEndianReadUInt16();
                this.NSCOUNT = packetReader.BigEndianReadUInt16();
                this.ARCOUNT = packetReader.BigEndianReadUInt16();
            }

        }

        internal byte[] GetBytes(DNSHeader Packet)
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(Packet.ID);
                packetWriter.Write(Packet.QR);
                packetWriter.Write(Packet.QDCOUNT);
                packetWriter.Write(Packet.ANCOUNT);
                packetWriter.Write(Packet.NSCOUNT);
                packetWriter.Write(Packet.ARCOUNT);
                return memoryStream.ToArray();
            }

        }

    }
}
