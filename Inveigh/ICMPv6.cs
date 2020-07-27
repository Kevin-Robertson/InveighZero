using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace Inveigh
{
    class ICMPv6
    {
        public static void icmpv6RouterAdvertise(string ipV6, int interval)
        {
            interval *= 1000;

            while (!Program.exitInveigh)
            {

                using (MemoryStream icmpv6MemoryStream = new MemoryStream())
                {
                    icmpv6MemoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                    byte[] pseudoHeader = Util.GetIPv6PseudoHeader(IPAddress.Parse("ff02::1"), IPAddress.Parse(ipV6), 58, (int)icmpv6MemoryStream.Length);
                    UInt16 checkSum = Util.GetPacketChecksum(pseudoHeader, icmpv6MemoryStream.ToArray());
                    icmpv6MemoryStream.Position = 2;
                    byte[] packetChecksum = Util.IntToByteArray2(checkSum);
                    Array.Reverse(packetChecksum);
                    icmpv6MemoryStream.Write(packetChecksum, 0, 2);
                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = 16;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(icmpv6MemoryStream.ToArray(), 16, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                }

                Thread.Sleep(interval);
            }

        }

    }

}
