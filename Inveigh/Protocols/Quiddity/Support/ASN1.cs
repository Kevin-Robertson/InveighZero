using System;
using System.IO;

namespace Quiddity.Support
{
    // https://github.com/mono/mono/blob/main/mcs/class/Mono.Security/Mono.Security/ASN1.cs

    class ASN1
    {
        public byte[] Tag { get; set; }
        public byte[] Length { get; set; }
        public byte[] Value { get; set; }

        internal ASN1()
        {
            this.Tag = new byte[1];
            this.Length = new byte[1];
            this.Value = new byte[0];
        }

        internal byte[] GetBytes(ASN1 Packet)
        {

            using (MemoryStream memoryStream = new MemoryStream())
            {
                PacketWriter packetWriter = new PacketWriter(memoryStream);
                packetWriter.Write(Packet.Tag);
                packetWriter.Write(Packet.Length);
                packetWriter.Write(Packet.Value);
                return memoryStream.ToArray();
            }

        }

        internal byte[] GetTagBytes(byte[] Data, ref int Index, int Length, byte Tag, out byte TagDecoded)
        {
            TagDecoded = 0x00;
            byte[] value = new byte[0];
            int valueLength;

            while (Index < Length - 1 && Tag != TagDecoded)
            {

                DecodeTag(Data, ref Index, out TagDecoded, out valueLength, out value);

                if (TagDecoded == 0 || Tag == TagDecoded)
                {
                    continue;
                }

                if ((TagDecoded & 0x20) == 0x20)
                {
                    int decodePosistion = Index;
                    value = GetTagBytes(Data, ref decodePosistion, (decodePosistion + valueLength), Tag, out TagDecoded);
                }

                Index += valueLength;
            }

            return value;
        }

        public static byte[] GetTagBytes(int Tag, byte[] Data)
        {
            byte tagDecoded = 0x00;
            int index = 0;
            ASN1 asn1 = new ASN1();
            return asn1.GetTagBytes(Data, ref index, Data.Length, (byte)Tag, out tagDecoded);
        }

        internal byte[] Decode(byte[] Data, ref int Posistion, int Length)
        {
            byte Tag;
            byte[] Value = new byte[0];
            byte[] temp2 = new byte[0];
            int valueLength;
            int i = 0;

            while (Posistion < Length - 1)
            {
                DecodeTag(Data, ref Posistion, out Tag, out valueLength, out Value);

                if (Tag == 0)
                {
                    continue;
                }

                if((Tag & 0x20) == 0x20)
                {
                    int decodePosistion = Posistion;
                    Value = Decode(Data, ref decodePosistion, (decodePosistion + valueLength));
                }

                Posistion += valueLength;
                i++;
                
            }

            return Value;
        }

        internal void DecodeTag(byte[] Data, ref int Index, out byte Tag, out int Length, out byte[] Value)
        {
            Tag = Data[Index++];
            Length = Data[Index++];

            if ((Length & 0x80) == 0x80)
            {
                int length = Length & 0x7f;
                
                Length = 0;

                for (int i = 0; i < length; i++)
                {
                    Length = Length * 256 + Data[Index++];
                }
               
            }
            
            Value = new byte[Length];
            Buffer.BlockCopy(Data, Index, Value, 0, Length);
        }

        internal byte[] Encode(byte Tag, byte[] Data)
        {
            int dataLength = Data.Length;
            this.Tag[0] = Tag;

            if (dataLength <= 127)
            {
                this.Length[0] = (byte)dataLength;
            }
            else if (dataLength <= 255)
            {
                this.Length = new byte[2];
                this.Length[0] = 0x81;
                this.Length[1] = (byte)dataLength;
            }
            else if (dataLength > 255)
            {
                this.Length = new byte[3];
                this.Length[0] = 0x82;
                this.Length[1] = (byte)(dataLength >> 8);
                this.Length[2] = (byte)(dataLength);
            }

            return Utilities.BlockCopy(this.Tag, this.Length, Data);
        }

        public static byte[] Encode(int Tag, byte[] Data)
        {
            ASN1 asn1 = new ASN1();
            return asn1.Encode((byte)Tag, Data);
        }

    }
}
