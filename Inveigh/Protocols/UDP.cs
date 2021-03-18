using System;
using System.Net;
using System.Net.Sockets;

namespace Inveigh
{
    class UDP
    {   

        public static UdpClient UDPListener(string type, string ipVersion, string listenerIP, int listenerPortNumber)
        {
            const int SIO_UDP_CONNRESET = -1744830452;
            AddressFamily addressFamily = AddressFamily.InterNetwork;

            if (String.Equals(ipVersion, "IPv6"))
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Parse(listenerIP), listenerPortNumber);
            UdpClient udpClient = new UdpClient(addressFamily);

            try
            {
                udpClient.ExclusiveAddressUse = false;
                udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
                udpClient.Client.Bind(ipEndPoint);

                switch (type)
                {
                
                    case "LLMNR":
                        udpClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.252"), Program.ipAddress);
                        break;

                    case "LLMNRv6":
                        udpClient.JoinMulticastGroup(IPAddress.Parse("ff02::1:3"));
                        break;

                    case "MDNS":
                        udpClient.JoinMulticastGroup(IPAddress.Parse("224.0.0.251"), Program.ipAddress);
                        break;

                    case "MDNSv6":
                        udpClient.JoinMulticastGroup(IPAddress.Parse("ff02::fb"));
                        break;

                    case "DHCPv6":
                        udpClient.JoinMulticastGroup(IPAddress.Parse("ff02::1:2"));
                        break;

                }

            }
            catch (Exception ex)
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[!] Error starting unprivileged mDNS spoofer, UDP port sharing does not work on all versions of Windows.{1}", DateTime.Now.ToString("s"), ex)); // todo fix
                }

                throw;
            }

            return udpClient;
        }

        public static void UDPListenerClient(IPAddress ipAddress, int portNumber, UdpClient udpClient, byte[] response)
        {
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddress, portNumber);
            udpClient.Client.SendTo(response, ipEndPoint);
        }

        public static void UDPSnifferClient(string ipVersion, int sourcePortNumber, IPAddress destinationIPAddress, int destinationPortNumber, byte[] response)
        {
            AddressFamily addressFamily = AddressFamily.InterNetwork;
            IPEndPoint ipEndPoint;
            IPAddress sourceIPAddress = Program.ipAddress;
            if (String.Equals(ipVersion, "IPv6"))
            {
                sourceIPAddress = Program.ipv6Address;
                addressFamily = AddressFamily.InterNetworkV6;
            }

            Socket socket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Udp);
            socket.SendBufferSize = 1024;
            ipEndPoint = new IPEndPoint(sourceIPAddress, sourcePortNumber);
            socket.Bind(ipEndPoint);
            IPEndPoint destinationEndpoint = new IPEndPoint(destinationIPAddress, destinationPortNumber);
            socket.SendTo(response, destinationEndpoint);
            socket.Close();
        }

    }

}
