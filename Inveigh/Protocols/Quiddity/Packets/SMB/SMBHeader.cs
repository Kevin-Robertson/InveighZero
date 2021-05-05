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

namespace Quiddity.SMB
{
    //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/69a29f73-de0c-45a6-a1aa-8ceeea42217f

    class SMBHeader
    {
        public byte[] Protocol { get; set; }
        public byte[] Command { get; set; }
        public byte[] Status { get; set; }
        public byte Flags { get; set; }
        public ushort Flags2 { get; set; }
        public ushort PIDHigh { get; set; }
        public byte[] SecurityFeatures { get; set; }
        public ushort Reserved { get; set; }
        public ushort TID { get; set; }
        public ushort PIDLow { get; set; }
        public ushort UID { get; set; }
        public ushort MID { get; set; }

        internal SMBHeader()
        {
            this.Protocol = new byte[4] { 0xff, 0x53, 0x4d, 0x42 };
            this.Command = new byte[1];
            this.Status = new byte[4] { 0x00, 0x00, 0x00, 0x00 };
            this.Flags = 0;
            this.Flags2 = 0;
            this.PIDHigh = 0;
            this.SecurityFeatures = new byte[8]; // breakout
            this.Reserved = 0;
            this.TID = 0;
            this.PIDLow = 0;
            this.UID = 0;
            this.MID = 0;
        }

        internal SMBHeader (byte[] Data, int Position)
        {
            ReadBytes(Data, Position);
        }

        internal SMBHeader ReadBytes(byte[] data, int position)
        {

            using (MemoryStream memoryStream = new MemoryStream(data))
            {
                PacketReader packetReader = new PacketReader(memoryStream);
                memoryStream.Position = position;
                this.Protocol = packetReader.ReadBytes(4);
                this.Command = packetReader.ReadBytes(1);
                this.Status = packetReader.ReadBytes(4);
                this.Flags = packetReader.ReadByte();
                this.Flags2 = packetReader.BigEndianReadUInt16();
                this.PIDHigh = packetReader.BigEndianReadUInt16();
                this.SecurityFeatures = packetReader.ReadBytes(8);
                this.Reserved = packetReader.BigEndianReadUInt16();
                this.TID = packetReader.BigEndianReadUInt16();
                this.PIDLow = packetReader.BigEndianReadUInt16();
                this.UID = packetReader.BigEndianReadUInt16();
                this.MID = packetReader.BigEndianReadUInt16();
                return this;
            }

        }

    }

}
