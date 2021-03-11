using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Net.NetworkInformation;

namespace Inveigh
{
    class ICMPv6
    {
        public static void icmpv6RouterAdvertise(string ipV6, int interval) // todo why doesn't this seem to fully work?
        {
            interval *= 1000;

            while (!Program.exitInveigh)
            {

                using (MemoryStream icmpv6MemoryStream = new MemoryStream())
                {
                    icmpv6MemoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                    byte[] pseudoHeader = Util.GetIPv6PseudoHeader(IPAddress.Parse("ff02::1"), 58, (int)icmpv6MemoryStream.Length);
                    UInt16 checksum = Util.GetPacketChecksum(pseudoHeader, icmpv6MemoryStream.ToArray()); // todo is this needed?
                    icmpv6MemoryStream.Position = 2;
                    byte[] packetChecksum = Util.IntToByteArray2(checksum);
                    Array.Reverse(packetChecksum);
                    icmpv6MemoryStream.Write(packetChecksum, 0, 2);
                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = 16;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(icmpv6MemoryStream.ToArray(), 16, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] ICMPv6 router advertisment sent to ff02::1", DateTime.Now.ToString("s")));
                }

                Thread.Sleep(interval);
            }

        }

    }

}
